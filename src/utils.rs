use std::{fmt::Display, io};

use ipconfig::{self, Adapter};
use itertools::Itertools;

use packet::ip::Protocol;

use winapi::um::{consoleapi::AllocConsole, wincon};

pub fn print_interfaces<'a>(nfs: impl Iterator<Item = &'a Adapter>, list_number: bool) {
    if list_number {
        print!(" # ");
    }
    print!("{:width$}", "name", width = 40);
    print!("{:width$}", "description", width = 45);
    print!("{:width$}", "up", width = 6);
    print!("ip list");
    println!();

    for (i, nf) in nfs.enumerate() {
        if list_number {
            print!("{:2} ", i);
        }
        print!("{:width$}", nf.adapter_name(), width = 40);
        print!("{:width$}", nf.description(), width = 45);
        print!(
            "{:width$}",
            nf.oper_status() == ipconfig::OperStatus::IfOperStatusUp,
            width = 6
        );
        print!("[{}]", nf.ip_addresses().iter().format(", "));
        println!();
    }
}

#[derive(Debug)]
pub struct Bytes<'a>(pub &'a [u8]);

impl<'a> Display for Bytes<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.0.len();
        for (i, b) in self.0.iter().enumerate() {
            write!(f, "{:02x} ", b)?;
            match i % 16 {
                7 => write!(f, " ")?,
                15 => writeln!(f)?,
                _ => {}
            }
        }
        if len % 16 != 0 {
            writeln!(f)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct TransProtocol(pub Protocol);

impl Display for TransProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Protocol::Unknown(p) => write!(f, "Unknown ({})", p),
            _ => write!(f, "{}", trans_protocol_name(self.0)),
        }
    }
}

fn trans_protocol_name(p: Protocol) -> &'static str {
    match p {
        Protocol::Hopopt => "Hopopt",
        Protocol::Icmp => "ICMP",
        Protocol::Igmp => "Igmp",
        Protocol::Ggp => "Ggp",
        Protocol::Ipv4 => "IPv4",
        Protocol::St => "St",
        Protocol::Tcp => "TCP",
        Protocol::Cbt => "Cbt",
        Protocol::Egp => "Egp",
        Protocol::Igp => "Igp",
        Protocol::BbnRccMon => "BbnRccMon",
        Protocol::NvpII => "NvpII",
        Protocol::Pup => "Pup",
        Protocol::Argus => "Argus",
        Protocol::Emcon => "Emcon",
        Protocol::Xnet => "Xnet",
        Protocol::Chaos => "Chaos",
        Protocol::Udp => "UDP",
        Protocol::Mux => "Mux",
        Protocol::DcnMeas => "DcnMeas",
        Protocol::Hmp => "Hmp",
        Protocol::Prm => "Prm",
        Protocol::XnsIdp => "XnsIdp",
        Protocol::Trunk1 => "Trunk1",
        Protocol::Trunk2 => "Trunk2",
        Protocol::Leaf1 => "Leaf1",
        Protocol::Leaf2 => "Leaf2",
        Protocol::Rdp => "Rdp",
        Protocol::Irtp => "Irtp",
        Protocol::IsoTp4 => "IsoTp4",
        Protocol::Netblt => "Netblt",
        Protocol::MfeNsp => "MfeNsp",
        Protocol::MeritInp => "MeritInp",
        Protocol::Dccp => "Dccp",
        Protocol::ThreePc => "ThreePc",
        Protocol::Idpr => "Idpr",
        Protocol::Xtp => "Xtp",
        Protocol::Ddp => "Ddp",
        Protocol::IdprCmtp => "IdprCmtp",
        Protocol::TpPlusPlus => "TpPlusPlus",
        Protocol::Il => "Il",
        Protocol::Ipv6 => "IPv6",
        Protocol::Sdrp => "Sdrp",
        Protocol::Ipv6Route => "IPv6Route",
        Protocol::Ipv6Frag => "IPv6Frag",
        Protocol::Idrp => "Idrp",
        Protocol::Rsvp => "Rsvp",
        Protocol::Gre => "Gre",
        Protocol::Dsr => "Dsr",
        Protocol::Bna => "Bna",
        Protocol::Esp => "Esp",
        Protocol::Ah => "Ah",
        Protocol::INlsp => "INlsp",
        Protocol::Swipe => "Swipe",
        Protocol::Narp => "Narp",
        Protocol::Mobile => "Mobile",
        Protocol::Tlsp => "Tlsp",
        Protocol::Skip => "Skip",
        Protocol::Ipv6Icmp => "IPv6ICMP",
        Protocol::Ipv6NoNxt => "IPv6NoNxt",
        Protocol::Ipv6Opts => "IPv6Opts",
        Protocol::HostInternal => "HostInternal",
        Protocol::Cftp => "Cftp",
        Protocol::LocalNetwork => "LocalNetwork",
        Protocol::SatExpak => "SatExpak",
        Protocol::Kryptolan => "Kryptolan",
        Protocol::Rvd => "Rvd",
        Protocol::Ippc => "Ippc",
        Protocol::DistributedFs => "DistributedFs",
        Protocol::SatMon => "SatMon",
        Protocol::Visa => "Visa",
        Protocol::Ipcv => "Ipcv",
        Protocol::Cpnx => "Cpnx",
        Protocol::Cphb => "Cphb",
        Protocol::Wsn => "Wsn",
        Protocol::Pvp => "Pvp",
        Protocol::BrSatMon => "BrSatMon",
        Protocol::SunNd => "SunNd",
        Protocol::WbMon => "WbMon",
        Protocol::WbExpak => "WbExpak",
        Protocol::IsoIp => "IsoIp",
        Protocol::Vmtp => "Vmtp",
        Protocol::SecureVmtp => "SecureVmtp",
        Protocol::Vines => "Vines",
        Protocol::TtpOrIptm => "TtpOrIptm",
        Protocol::NsfnetIgp => "NsfnetIgp",
        Protocol::Dgp => "Dgp",
        Protocol::Tcf => "Tcf",
        Protocol::Eigrp => "Eigrp",
        Protocol::OspfigP => "OspfigP",
        Protocol::SpriteRpc => "SpriteRpc",
        Protocol::Larp => "Larp",
        Protocol::Mtp => "Mtp",
        Protocol::Ax25 => "Ax25",
        Protocol::IpIp => "IpIp",
        Protocol::Micp => "Micp",
        Protocol::SccSp => "SccSp",
        Protocol::Etherip => "Etherip",
        Protocol::Encap => "Encap",
        Protocol::PrivEncryption => "PrivEncryption",
        Protocol::Gmtp => "Gmtp",
        Protocol::Ifmp => "Ifmp",
        Protocol::Pnni => "Pnni",
        Protocol::Pim => "Pim",
        Protocol::Aris => "Aris",
        Protocol::Scps => "Scps",
        Protocol::Qnx => "Qnx",
        Protocol::AN => "AN",
        Protocol::IpComp => "IpComp",
        Protocol::Snp => "Snp",
        Protocol::CompaqPeer => "CompaqPeer",
        Protocol::IpxInIp => "IpxInIp",
        Protocol::Vrrp => "Vrrp",
        Protocol::Pgm => "Pgm",
        Protocol::ZeroHop => "ZeroHop",
        Protocol::L2tp => "L2tp",
        Protocol::Ddx => "Ddx",
        Protocol::Iatp => "Iatp",
        Protocol::Stp => "Stp",
        Protocol::Srp => "Srp",
        Protocol::Uti => "Uti",
        Protocol::Smp => "Smp",
        Protocol::Sm => "Sm",
        Protocol::Ptp => "Ptp",
        Protocol::IsisOverIpv4 => "IsisOverIpv4",
        Protocol::Fire => "Fire",
        Protocol::Crtp => "Crtp",
        Protocol::Crudp => "Crudp",
        Protocol::Sscopmce => "Sscopmce",
        Protocol::Iplt => "Iplt",
        Protocol::Sps => "Sps",
        Protocol::Pipe => "Pipe",
        Protocol::Sctp => "Sctp",
        Protocol::Fc => "Fc",
        Protocol::RsvpE2eIgnore => "RsvpE2eIgnore",
        Protocol::MobilityHeader => "MobilityHeader",
        Protocol::UdpLite => "UdpLite",
        Protocol::MplsInIp => "MplsInIp",
        Protocol::Manet => "Manet",
        Protocol::Hip => "Hip",
        Protocol::Shim6 => "Shim6",
        Protocol::Wesp => "Wesp",
        Protocol::Rohc => "Rohc",
        Protocol::Test1 => "Test1",
        Protocol::Test2 => "Test2",
        Protocol::Unknown(_) => "Unknown",
    }
}

#[derive(Debug)]
pub enum AppProtocolPort {
    FtpData,    // 20
    FtpControl, // 21
    Ssh,        // 22
    Telnet,     // 23
    Smtp,       // 25
    Dns,        // 53
    DhcpServer, // 67
    DhcpClient, // 68
    Http,       // 80
    Pop3,       // 110
    Nntp,       // 119
    Ntp,        // 123
    Imap,       // 143
    Snmp,       // 161
    Irc,        // 194
    Https,      // 443
    Unknown(u16),
}

impl From<u16> for AppProtocolPort {
    fn from(port: u16) -> Self {
        match port {
            20 => Self::FtpData,
            21 => Self::FtpControl,
            22 => Self::Ssh,
            23 => Self::Telnet,
            25 => Self::Smtp,
            53 => Self::Dns,
            67 => Self::DhcpServer,
            68 => Self::DhcpClient,
            80 => Self::Http,
            110 => Self::Pop3,
            119 => Self::Nntp,
            123 => Self::Ntp,
            143 => Self::Imap,
            161 => Self::Snmp,
            194 => Self::Irc,
            443 => Self::Https,
            p => Self::Unknown(p),
        }
    }
}

pub enum AppProtocol {
    Ftp,
    Ssh,
    Telnet,
    Smtp,
    Dns,
    Dhcp,
    Http,
    Pop3,
    Nntp,
    Ntp,
    Imap,
    Snmp,
    Irc,
    Https,
    Unknown,
}

impl From<(AppProtocolPort, AppProtocolPort)> for AppProtocol {
    fn from((src, dest): (AppProtocolPort, AppProtocolPort)) -> Self {
        use AppProtocolPort::*;
        match src {
            FtpData | FtpControl => Self::Ftp,
            Ssh => Self::Ssh,
            Telnet => Self::Telnet,
            Smtp => Self::Smtp,
            Dns => Self::Dns,
            DhcpServer | DhcpClient => Self::Dhcp,
            Http => Self::Http,
            Pop3 => Self::Pop3,
            Nntp => Self::Nntp,
            Ntp => Self::Ntp,
            Imap => Self::Imap,
            Snmp => Self::Snmp,
            Irc => Self::Irc,
            Https => Self::Https,
            Unknown(_) => match dest {
                FtpData | FtpControl => Self::Ftp,
                Ssh => Self::Ssh,
                Telnet => Self::Telnet,
                Smtp => Self::Smtp,
                Dns => Self::Dns,
                DhcpServer | DhcpClient => Self::Dhcp,
                Http => Self::Http,
                Pop3 => Self::Pop3,
                Nntp => Self::Nntp,
                Ntp => Self::Ntp,
                Imap => Self::Imap,
                Snmp => Self::Snmp,
                Irc => Self::Irc,
                Https => Self::Https,
                Unknown(_) => Self::Unknown,
            },
        }
    }
}

impl From<(u16, u16)> for AppProtocol {
    fn from((src, dest): (u16, u16)) -> Self {
        let src: AppProtocolPort = src.into();
        let dest: AppProtocolPort = dest.into();
        Self::from((src, dest))
    }
}

impl Display for AppProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use AppProtocol::*;
        match self {
            Ftp => write!(f, "FTP"),
            Ssh => write!(f, "SSH"),
            Telnet => write!(f, "Telnet"),
            Smtp => write!(f, "SMTP"),
            Dns => write!(f, "DNS"),
            Dhcp => write!(f, "DHCP"),
            Http => write!(f, "HTTP"),
            Pop3 => write!(f, "POP3"),
            Nntp => write!(f, "NNTP"),
            Ntp => write!(f, "NTP"),
            Imap => write!(f, "IMAP"),
            Snmp => write!(f, "SNMP"),
            Irc => write!(f, "IRC"),
            Https => write!(f, "HTTPS"),
            Unknown => write!(f, "Unknown"),
        }
    }
}

pub fn alloc_console() -> io::Result<()> {
    if unsafe { AllocConsole() } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn attach_console() -> io::Result<()> {
    if unsafe { wincon::AttachConsole(wincon::ATTACH_PARENT_PROCESS) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
