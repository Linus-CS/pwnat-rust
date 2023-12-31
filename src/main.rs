use std::{env, io::Write, net::Ipv4Addr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time,
};
use tokio_tun::Tun;

use etherparse::{
    ip_number, IcmpEchoHeader, Icmpv4Header, Icmpv4Type, Ipv4Header, Ipv4HeaderSlice, UdpHeader,
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

async fn ping(
    sink: &mut tokio::io::WriteHalf<tokio_tun::Tun>,
    host: [u8; 4],
) -> Result<(), PacketError> {
    let mut buffer = [0; 1500];
    let mut buf_slice = &mut buffer[..];
    write_ip_header([192, 168, 0, 3], host, 8, &mut buf_slice)?;
    write_icmp_header(
        Icmpv4Type::EchoRequest(IcmpEchoHeader { id: 0, seq: 0 }),
        &mut buf_slice,
    )?;

    let unwritten = buf_slice.len();
    let complete = &buffer[..buffer.len() - unwritten];
    sink.write_all(complete).await.unwrap();
    println!("Send ICMP Echo to {host:?}");
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

async fn udp(sink: &mut tokio::io::WriteHalf<tokio_tun::Tun>) -> Result<(), PacketError> {
    let mut ip_header =
        Ipv4Header::new(0, 64, ip_number::UDP, [192, 168, 0, 3], [192, 168, 178, 21]);

    ip_header
        .set_payload_len(8 + 5)
        .map_err(|_| PacketError::PayloadLengthToBig)?;

    let payload = [1, 2, 3, 4, 5];
    let udp_header = UdpHeader::with_ipv4_checksum(3478, 799, &ip_header, &payload).unwrap();
    let mut buffer = [0; 20 + 8 + 5];
    let mut slice = &mut buffer[..];

    ip_header.write(&mut slice);
    udp_header.write(&mut slice);
    slice.write_all(&payload);

    sink.write_all(&buffer).await;
    Ok(())
}

#[tokio::main]
async fn main() {
    // https://unix.stackexchange.com/questions/588938/how-to-relay-traffic-from-tun-to-internet to relay tun traffic to internet
    let args: Vec<String> = env::args().collect();
    let tun = Tun::builder()
        .name("tun0")
        .address(Ipv4Addr::new(10, 168, 0, 1))
        .netmask(Ipv4Addr::new(255, 255, 255, 0))
        // .destination(Ipv4Addr::new(192, 168, 178, 21))
        .packet_info(false)
        .up()
        .try_build()
        .unwrap();

    // setup_viface("tun0");
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
                // ping(&mut sink, [195, 90, 213, 214]).await.unwrap();
                udp(&mut sink).await.unwrap();
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
                    println!("Received {proto} Packet from {src}");

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
