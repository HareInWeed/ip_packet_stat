use crate::utils::{AppProtocol, TransProtocol};
use chrono::prelude::*;
use packet::ip::Protocol;
use std::net::Ipv4Addr;

pub struct Record {
    pub time: DateTime<Local>,
    pub src_ip: Option<Ipv4Addr>,
    pub src_port: Option<u16>,
    pub dest_ip: Option<Ipv4Addr>,
    pub dest_port: Option<u16>,
    pub len: u16,
    pub ip_payload_len: Option<u16>,
    pub trans_proto: Protocol,
    pub trans_payload_len: Option<u16>,
    pub app_proto: AppProtocol,
}

impl Record {
    pub fn to_string_array(&self) -> [String; 10] {
        [
            self.time.format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
            self.src_ip.map_or("".to_string(), |ip| ip.to_string()),
            self.src_port
                .map_or("".to_string(), |port| port.to_string()),
            self.dest_ip.map_or("".to_string(), |ip| ip.to_string()),
            self.dest_port
                .map_or("".to_string(), |port| port.to_string()),
            self.len.to_string(),
            self.ip_payload_len
                .map_or("".to_string(), |l| l.to_string()),
            format!("{}", TransProtocol(self.trans_proto)),
            self.trans_payload_len
                .map_or("".to_string(), |l| l.to_string()),
            if matches!(self.trans_proto, Protocol::Udp | Protocol::Tcp) {
                format!("{}", self.app_proto)
            } else {
                "".to_string()
            },
        ]
    }
}
