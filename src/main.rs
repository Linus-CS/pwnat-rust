use etherparse::PacketBuilder;
use local_ip_address::{list_afinet_netifas, local_ip};
use std::{
    env::{self},
    error::Error,
    net::Ipv4Addr,
    process::Command,
    u8,
};
use tokio_tun::Tun;

fn setup_iface() -> Result<Tun, Box<dyn Error>> {
    let tun_name = "p2p";
    let tun = Tun::builder()
        .name(tun_name)
        .address(Ipv4Addr::new(10, 0, 0, 1))
        .netmask(Ipv4Addr::new(255, 255, 255, 0))
        .packet_info(false)
        .up()
        .try_build()?;

    Ok(tun)
}

fn setup_iptable_entries(interface: &str) -> Result<(), Box<dyn Error>> {
    Command::new("iptables")
        .arg("-A")
        .arg("FORWARD")
        .arg("-s")
        .arg("10.0.0.0/24")
        .arg("-o")
        .arg(interface)
        .arg("-j")
        .arg("ACCEPT")
        .status()?;

    Command::new("iptables")
        .arg("-A")
        .arg("FORWARD")
        .arg("-i")
        .arg(interface)
        .arg("-d")
        .arg("10.0.0.0/24")
        .arg("-m")
        .arg("state")
        .arg("--state")
        .arg("ESTABLISHED,RELATED")
        .arg("-j")
        .arg("ACCEPT")
        .status()?;

    Command::new("iptables")
        .arg("-t")
        .arg("nat")
        .arg("-A")
        .arg("POSTROUTING")
        .arg("-s")
        .arg("10.0.0.0/24")
        .arg("-o")
        .arg(interface)
        .arg("-j")
        .arg("MASQUERADE")
        .status()?;

    Ok(())
}

fn remove_iptable_entries(interface: &str) -> Result<(), Box<dyn Error>> {
    Command::new("iptables")
        .arg("-D")
        .arg("FORWARD")
        .arg("-s")
        .arg("10.0.0.0/24")
        .arg("-o")
        .arg(interface)
        .arg("-j")
        .arg("ACCEPT")
        .status()?;

    Command::new("iptables")
        .arg("-D")
        .arg("FORWARD")
        .arg("-i")
        .arg(interface)
        .arg("-d")
        .arg("10.0.0.0/24")
        .arg("-m")
        .arg("state")
        .arg("--state")
        .arg("ESTABLISHED,RELATED")
        .arg("-j")
        .arg("ACCEPT")
        .status()?;

    Command::new("iptables")
        .arg("-t")
        .arg("nat")
        .arg("-D")
        .arg("POSTROUTING")
        .arg("-s")
        .arg("10.0.0.0/24")
        .arg("-o")
        .arg(interface)
        .arg("-j")
        .arg("MASQUERADE")
        .status()?;

    Ok(())
}

fn get_interface() -> Result<String, Box<dyn Error>> {
    let interfaces = list_afinet_netifas()?;
    let local = local_ip()?;

    Ok(interfaces
        .iter()
        .find(|x| x.1 == local)
        .map(|x| x.0.split(':').next().unwrap().to_owned())
        .unwrap())
}

struct CmdArguments {
    is_client: bool,
    remote: Option<[u8; 4]>,
}
enum ParsingError {
    UnsupportedArgument(String),
    IPv4Parsing,
    MissingRemote,
}

impl TryFrom<Vec<String>> for CmdArguments {
    type Error = ParsingError;

    fn try_from(mut args: Vec<String>) -> Result<Self, Self::Error> {
        let mut ans = CmdArguments {
            is_client: false,
            remote: None,
        };
        args = args[1..].to_vec();
        let mut check_remote = false;
        for arg in args {
            if check_remote {
                let address: Vec<&str> = arg.split('.').collect();
                if address.len() != 4 {
                    return Err(ParsingError::IPv4Parsing);
                }
                let mut values = [0; 4];
                for (i, value) in address.iter().enumerate() {
                    values[i] = value.parse().map_err(|_| ParsingError::IPv4Parsing)?;
                }
                ans.remote = Some(values);
                check_remote = false;
                continue;
            }
            match arg.as_str() {
                "-c" => ans.is_client = true,
                "--remote" | "-R" => check_remote = true,
                a => return Err(ParsingError::UnsupportedArgument(a.to_owned())),
            }
        }
        if ans.is_client && ans.remote.is_none() {
            return Err(ParsingError::MissingRemote);
        }
        Ok(ans)
    }
}

impl CmdArguments {
    fn parse(args: Vec<String>) -> Option<Self> {
        match CmdArguments::try_from(args) {
            Ok(value) => Some(value),
            Err(e) => {
                match e {
                    ParsingError::IPv4Parsing => println!(
                        "Could not parse the provided ip use a.b.c.d with a-d between 0 and 255"
                    ),
                    ParsingError::UnsupportedArgument(arg) => {
                        println!("Unsupported argument: {arg}")
                    }

                    ParsingError::MissingRemote => println!(
                        "Client needs to provide remote ip. Use --remote to set remote ip address."
                    ),
                };

                None
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let args = CmdArguments::parse(args);
    if args.is_none() {
        return Ok(());
    }

    let correct_interface = get_interface()?;

    let args = args.expect("Errors where already handled!");

    let tun = setup_iface()?;
    setup_iptable_entries(&correct_interface)?;

    if args.is_client {
        let remote = args.remote.expect("Checked during parsing!");
        let builder1 =
            PacketBuilder::ipv4([10, 0, 0, 2], remote, u8::MAX).icmpv4_raw(11, 0, [0; 4]);
        let builder2 = PacketBuilder::ipv4(remote, [3, 3, 3, 3], 1).icmpv4_echo_request(0, 0);
        let mut packet = Vec::<u8>::with_capacity(builder1.size(builder2.size(0)));
        let mut inner = Vec::<u8>::with_capacity(builder2.size(0));
        builder2.write(&mut inner, &[]).unwrap();
        builder1.write(&mut packet, &inner).unwrap();

        println!("packet \n{packet:?}");
        let n = tun.send(&packet).await?;
        println!("send {n} bytes!");
        let mut buffer = [0; 1500];
        let _ = tun.recv(&mut buffer).await.unwrap();
        let n = tun.recv(&mut buffer).await.unwrap();
        println!("{:?}", &buffer[..n]);
    } else {
        let builder =
            PacketBuilder::ipv4([10, 0, 0, 2], [3, 3, 3, 3], u8::MAX).icmpv4_echo_request(0, 0);
        let mut packet = Vec::<u8>::with_capacity(builder.size(0));
        builder.write(&mut packet, &[]).unwrap();

        println!("packet \n{packet:?}");
        let n = tun.send(&packet).await?;
        println!("send {n} bytes!");

        let mut buffer = [0; 1500];
        let _ = tun.recv(&mut buffer).await.unwrap();
        let n = tun.recv(&mut buffer).await.unwrap();
        println!("{:?}", &buffer[..n]);
    };

    remove_iptable_entries(&correct_interface)?;

    Ok(())
}

// sysctl -w net.ipv4.ip_forward=1 or
// echo 1 > /proc/sys/net/ipv4/ip_forward

// CREATE
// iptables -A FORWARD -s 10.0.0.0/24 -o wlo1 -j ACCEPT
// iptables -A FORWARD -i wlo1 -d 10.0.0.0/24 -m state --state ESTABLISHED,RELATED -j ACCEPT
// iptables -t nat -A POSTROUTING -s 10.0.0.1/24 -o wlo1 -j MASQUERADE

// DELETE
// iptables -D FORWARD -s 10.0.0.0/24 -o wlo1 -j ACCEPT
// iptables -D FORWARD -i wlo1 -d 10.0.0.0/24 -m state --state ESTABLISHED,RELATED -j ACCEPT
// iptables -t nat -D POSTROUTING -s 10.0.0.1/24 -o wlo1 -j MASQUERADE

// [69, 0, 0, 56,| 0, 0, 0, 0,| 255, 1, 253, 205,| 192, 168, 178, 21,| 79, 216, 187, 96,|| 11, 0, 244, 255, 0, 0, 0, 0,|| 69, 0, 0, 28,| 0, 0, 64, 0,| 1, 1, 104, 163,| 79, 216, 187, 96,| 3, 3, 3, 3,|| 8, 0, 247, 255, 0, 0, 0, 0]
// [69, 0, 0, 56,| 0, 0, 0, 0,| 253, 1, 125, 123,| 62, 155, 247, 172,| 10, 0, 0, 2,|| 11, 0, 244, 255, 0, 0, 0, 0,|| 69, 0, 0, 28,| 0, 0, 64, 0,| 1, 1, 214, 174|, 10, 0, 0, 2,| 195, 90, 213, 214,|| 8, 0, 247, 255, 0, 0, 0, 0]
//  ---------------------------IPv4-Header-----------------------------------------||------------ICMP-------------||-----------------------------original-IPv4-Header------------------------------||----------original-ICMP----
//                                                                                                                  [69, 0, 0, 28,| 0, 0, 64, 0,| 3, 1, 212, 174|, 10, 0, 0, 2,| 195, 90, 213, 214,|| 8, 0, 247, 255, 0, 0, 0, 0]
//                                                                                                                                                ^      ^----^
//                                                                                                                                               TTL  Header Checksum
//[69, 0, 0, 28, 0, 0, 64, 0, 1, 1, 251, 234, 192, 168, 178, 21, 79, 216, 187, 96, 11, 0, 244, 255, 0, 0, 0, 0]

// iptable entries need to be changed not use wlo1 but correct interface
