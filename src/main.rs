use std::{env, process::Command, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time,
};
use tokio_tun::Tun;

use etherparse::{
    ip_number, IcmpEchoHeader, Icmpv4Header, Icmpv4Type, Ipv4Header, Ipv4HeaderSlice,
};

#[derive(Debug)]
enum PacketError {
    PayloadLengthToBig,
    CouldNotWriteHeader,
}

fn write_ip_header(
    src: [u8; 4],
    dest: [u8; 4],
    size: usize,
    buffer: &mut &mut [u8],
) -> Result<(), PacketError> {
    let mut ip_header = Ipv4Header::new(0, 64, ip_number::ICMP, src, dest);
    ip_header
        .set_payload_len(size)
        .map_err(|_| PacketError::PayloadLengthToBig)?;
    ip_header
        .write(buffer)
        .map_err(|_| PacketError::CouldNotWriteHeader)?;
    Ok(())
}

fn write_icmp_header(icmp_type: Icmpv4Type, buffer: &mut &mut [u8]) -> Result<(), PacketError> {
    let icmp_header = Icmpv4Header::new(icmp_type);
    icmp_header
        .write(buffer)
        .map_err(|_| PacketError::CouldNotWriteHeader)?;
    Ok(())
}

async fn ping(sink: &mut tokio::io::WriteHalf<tokio_tun::Tun>) -> Result<(), PacketError> {
    let mut buffer = [0; 1500];
    let mut buf_slice = &mut buffer[..];
    write_ip_header([192, 168, 0, 3], [3, 3, 3, 3], 8, &mut buf_slice)?;
    write_icmp_header(
        Icmpv4Type::EchoRequest(IcmpEchoHeader { id: 0, seq: 0 }),
        &mut buf_slice,
    )?;

    let unwritten = buf_slice.len();
    let complete = &buffer[..buffer.len() - unwritten];
    sink.write_all(complete).await.unwrap();
    println!("Send ICMP Echo to 3.3.3.3");
    Ok(())
}

async fn time_exceeded(
    sink: &mut tokio::io::WriteHalf<tokio_tun::Tun>,
    src: [u8; 4],
    host: [u8; 4],
) -> Result<(), PacketError> {
    let mut buffer: [u8; 1500] = [0; 1500];
    let mut buf_slice = &mut buffer[..];
    write_ip_header(src, host, 8 + 20 + 8, &mut buf_slice)?;
    write_icmp_header(
        Icmpv4Type::TimeExceeded(etherparse::icmpv4::TimeExceededCode::TtlExceededInTransit),
        &mut buf_slice,
    )?;

    write_ip_header(src, host, 8, &mut buf_slice)?;
    write_icmp_header(
        Icmpv4Type::EchoRequest(IcmpEchoHeader { id: 0, seq: 0 }),
        &mut buf_slice,
    )?;

    let unwritten = buf_slice.len();
    let complete = &buffer[..buffer.len() - unwritten];
    sink.write_all(complete).await.unwrap();
    println!("Send ICMP TimeExceeded to {host:?}");
    Ok(())
}

fn setup_viface(name: &str) {
    Command::new("ip")
        .args(["addr", "add", "dev", name, "192.168.0.1/24"])
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let tun = Tun::builder()
        .name("tun0")
        .packet_info(false)
        .up()
        .try_build()
        .unwrap();

    setup_viface("tun0");
    let (mut stream, mut sink) = tokio::io::split(tun);

    let pinging = if args.len() > 1 && args[1] == "-c" {
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_millis(250));
            loop {
                interval.tick().await;
                time_exceeded(&mut sink, [195, 90, 213, 214], [192, 168, 0, 3])
                    .await
                    .unwrap();
            }
        })
    } else {
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_millis(250));
            loop {
                interval.tick().await;
                ping(&mut sink).await.unwrap();
            }
        })
    };

    let listening = tokio::spawn(async move {
        loop {
            let mut buf = [0u8; 1500];
            let n = stream.read(&mut buf).await.unwrap();
            match Ipv4HeaderSlice::from_slice(&buf[..n]) {
                Ok(iph) => {
                    let src = iph.source_addr();
                    let proto = iph.protocol();

                    if proto == 1 {
                        println!("Received ICMP Packet from {src}");
                    }
                }
                Err(etherparse::ReadError::Ipv4UnexpectedVersion(6)) => {}
                Err(e) => {
                    eprintln!("ignoring weird packet {:?}", e);
                }
            }
        }
    });

    futures::future::join_all(vec![pinging, listening]).await;
}
