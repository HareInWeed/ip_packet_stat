use anyhow::{anyhow, bail, Result};

use clap::Parser;

use crate::{socket::ipv4_sniffer, utils::AppProtocol};
use byteorder::{self, NetworkEndian, WriteBytesExt};
use ipconfig;
use packet::{
    ip::{v4, Protocol},
    tcp, udp, Packet,
};

use std::{
    fmt::Display,
    io::{self, Read, Write},
    net::SocketAddr,
};

/// capture ipv4 packet with winsock2
#[derive(Parser, Debug)]
#[clap(name = "ip_packets", version = "0.1.0", author = "HareInWeed")]
pub struct CliArgs {
    /// run as cli mode without gui
    #[clap(short, long)]
    pub cli: bool,

    /// print whole ip packet
    #[clap(short, long)]
    pub packet: bool,

    /// using polling mode with non-blocking socket
    #[clap(short = 'P', long)]
    pub poll: bool,

    /// flush after printing info for each packet
    #[clap(short, long)]
    pub flush: bool,

    /// print payload
    #[clap(short, long)]
    pub load: bool,
}

use crate::utils::{print_interfaces, Bytes, TransProto};

pub fn main(cli_args: &CliArgs) -> Result<()> {
    /* Choose network interface */
    let interfaces = {
        let mut interfaces = ipconfig::get_adapters()?
            .into_iter()
            .filter(|adapter| adapter.ip_addresses().iter().any(|addr| addr.is_ipv4()))
            .collect::<Vec<_>>();
        interfaces.sort_by(|a1, a2| a1.description().cmp(a2.description()));
        interfaces
    };
    print_interfaces(interfaces.iter(), true);
    println!("choose an interface with the number at the beginning of the row");
    let interface = {
        let mut choice = String::new();
        loop {
            io::stdout().flush()?;
            choice.clear();
            io::stdin().read_line(&mut choice)?;
            let id: usize = match choice.trim().parse() {
                Ok(num) => num,
                Err(_) => {
                    println!(
                        "choice must be a number between 0 to {}",
                        interfaces.len() - 1
                    );
                    continue;
                }
            };
            break match interfaces.iter().nth(id) {
                Some(ni) => {
                    if ni.oper_status() != ipconfig::OperStatus::IfOperStatusUp {
                        println!("Network Interface is not up, please choose another one");
                        continue;
                    }
                    ni
                }
                None => {
                    println!(
                        "choice must be a number between 0 to {}",
                        interfaces.len() - 1
                    );
                    continue;
                }
            };
        }
    };

    /* create ip packet sniffer */
    let interface_addr = interface
        .ip_addresses()
        .iter()
        .find(|&addr| addr.is_ipv4())
        .ok_or(anyhow!("no address available"))?;
    // It seems like you can bind any port to this?
    let address = SocketAddr::from((interface_addr.clone(), 8000));
    let mut socket = ipv4_sniffer(address, cli_args.poll)?;

    /* start sniffing */
    let mut buffer = vec![0; socket.recv_buffer_size()?];
    loop {
        match socket.read(buffer.as_mut_slice()) {
            Ok(bytes) => {
                /* parse and print packet info */
                println!("read {} bytes: ", bytes);
                if let Ok(mut ip_packet) = v4::Packet::new(&buffer[..bytes]) {
                    if ip_packet.length() < 20 {
                        println!(
                            "corrupted ipv4 packet, Total Length = {} < 20",
                            ip_packet.length()
                        );
                        if bytes > 4 {
                            println!(
                                "try to recover packet with whole byte array length {}...",
                                bytes
                            );
                            (&mut buffer[2..]).write_u16::<NetworkEndian>(bytes as u16)?;
                            ip_packet = v4::Packet::unchecked(&buffer[..bytes]);
                        }
                    }
                    let have_payload = ip_packet.payload().len() != 0;

                    println!(
                        "transport layer protocol: {}",
                        TransProto(ip_packet.protocol())
                    );
                    let src_ip = ip_packet.source();
                    let dest_ip = ip_packet.destination();
                    let (src_ipp, dest_ipp);
                    let (src, dest): (&dyn Display, &dyn Display) = match ip_packet.protocol() {
                        Protocol::Tcp if have_payload => {
                            if let Ok(tcp_packet) = tcp::Packet::new(ip_packet.payload()) {
                                let src_p = tcp_packet.source();
                                let dest_p = tcp_packet.destination();
                                src_ipp = SocketAddr::from((src_ip, src_p));
                                dest_ipp = SocketAddr::from((dest_ip, dest_p));
                                println!(
                                    "application layer protocol: {}",
                                    AppProtocol::from((src_p, dest_p))
                                );
                                (&src_ipp, &dest_ipp)
                            } else {
                                println!("corrupted TCP packet");
                                (&src_ip, &dest_ip)
                            }
                        }
                        Protocol::Udp if have_payload => {
                            if let Ok(udp_packet) = udp::Packet::new(ip_packet.payload()) {
                                let src_p = udp_packet.source();
                                let dest_p = udp_packet.destination();
                                src_ipp = SocketAddr::from((src_ip, src_p));
                                dest_ipp = SocketAddr::from((dest_ip, dest_p));
                                println!(
                                    "application layer protocol: {}",
                                    AppProtocol::from((src_p, dest_p))
                                );
                                (&src_ipp, &dest_ipp)
                            } else {
                                println!("corrupted UDP packet");
                                (&src_ip, &dest_ip)
                            }
                        }
                        _ => (&src_ip, &dest_ip),
                    };
                    println!("source: {}", src);
                    println!("destination: {}", dest);
                    if cli_args.packet {
                        println!("whole packet:");
                        print!("{}", Bytes(ip_packet.as_ref()));
                    }
                    if cli_args.load {
                        println!("ip packet payload, {} bytes:", ip_packet.payload().len());
                        print!("{}", Bytes(ip_packet.payload()));
                    } else {
                        println!("ip packet payload: {} bytes", ip_packet.payload().len());
                    }
                    println!();
                } else {
                    println!("corrupted ipv4 packet");
                    print!("{}", Bytes(&buffer[..bytes]));
                }
            }
            Err(err) => match err.raw_os_error() {
                Some(10035) => continue,
                _ => bail!(err),
            },
        }
        if cli_args.flush {
            io::stdout().flush()?;
        }
    }
}
