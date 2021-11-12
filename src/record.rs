use crate::utils::{trans_protocol_name, AppProtocol, TransProtocol};
use anyhow::{anyhow, Error, Result};
use chrono::prelude::*;
use packet::ip::Protocol;
use std::{
    collections::{hash_map::Entry as HashMapEntry, HashMap},
    convert::TryFrom,
    iter,
    net::Ipv4Addr,
};

#[derive(Debug, Clone)]
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
            TransProtocol(self.trans_proto).to_string(),
            self.trans_payload_len
                .map_or("".to_string(), |l| l.to_string()),
            if matches!(self.trans_proto, Protocol::Udp | Protocol::Tcp) {
                self.app_proto.to_string()
            } else {
                "".to_string()
            },
        ]
    }
}

#[derive(Debug, Default)]
pub struct NetRecord {
    pub packet_num: u64,
    pub byte_num: u64,
}

impl NetRecord {
    pub fn add_up(&mut self, other: &Self) {
        self.packet_num += other.packet_num;
        self.byte_num += other.byte_num;
    }
    pub fn to_string_iter(&self) -> impl Iterator<Item = String> {
        iter::once(self.packet_num.to_string()).chain(iter::once(self.byte_num.to_string()))
    }
}

impl From<&Record> for NetRecord {
    fn from(record: &Record) -> Self {
        Self {
            packet_num: 1,
            byte_num: record.len as _,
        }
    }
}

#[derive(Debug)]
pub struct TransRecord {
    pub packet_num: u64,
    pub byte_num: u64,
    pub byte_num_in_net: u64,
}

impl TransRecord {
    pub fn add_up(&mut self, other: &Self) {
        self.packet_num += other.packet_num;
        self.byte_num += other.byte_num;
        self.byte_num_in_net += other.byte_num_in_net;
    }
    pub fn to_string_array(&self) -> [String; 3] {
        [
            self.packet_num.to_string(),
            self.byte_num.to_string(),
            self.byte_num_in_net.to_string(),
        ]
    }
}

impl TryFrom<&Record> for TransRecord {
    type Error = Error;

    fn try_from(record: &Record) -> Result<Self, Self::Error> {
        Ok(Self {
            packet_num: 1,
            byte_num: record.ip_payload_len.ok_or(anyhow!(
                "record does not represent a transport layer packet"
            ))? as _,
            byte_num_in_net: record.len as _,
        })
    }
}

#[derive(Debug)]
pub struct AppRecord {
    pub packet_num: u64,
    pub byte_num: u64,
    pub byte_num_in_net: u64,
    pub byte_num_in_trans: u64,
}

impl AppRecord {
    pub fn add_up(&mut self, other: &Self) {
        self.packet_num += other.packet_num;
        self.byte_num += other.byte_num;
        self.byte_num_in_net += other.byte_num_in_net;
        self.byte_num_in_trans += other.byte_num_in_trans;
    }
    pub fn to_string_array(&self) -> [String; 4] {
        [
            self.packet_num.to_string(),
            self.byte_num.to_string(),
            self.byte_num_in_net.to_string(),
            self.byte_num_in_trans.to_string(),
        ]
    }
}

impl TryFrom<&Record> for AppRecord {
    type Error = Error;

    fn try_from(record: &Record) -> Result<Self, Self::Error> {
        Ok(Self {
            packet_num: 1,
            byte_num: record.trans_payload_len.ok_or(anyhow!(
                "record does not represent a application layer packet"
            ))? as _,
            byte_num_in_net: record.len as _,
            byte_num_in_trans: record.ip_payload_len.ok_or(anyhow!(
                "record does not represent a application layer packet"
            ))? as _,
        })
    }
}

#[derive(Debug, Default)]
pub struct StatRecord {
    pub stat_net_table: NetRecord,
    pub stat_trans_table: HashMap<String, TransRecord>,
    pub stat_app_table: HashMap<String, AppRecord>,
}

impl StatRecord {
    pub fn clear(&mut self) {
        self.stat_net_table = Default::default();
        self.stat_trans_table.clear();
        self.stat_app_table.clear();
    }

    pub fn update(&mut self, record: &Record) {
        let net_record: NetRecord = record.into();
        self.stat_net_table.add_up(&net_record);

        if let Ok(trans_record) = TransRecord::try_from(record) {
            match self
                .stat_trans_table
                .entry(trans_protocol_name(record.trans_proto).to_owned())
            {
                HashMapEntry::Occupied(mut trans) => {
                    trans.get_mut().add_up(&trans_record);
                }
                HashMapEntry::Vacant(trans) => {
                    trans.insert(trans_record);
                }
            }
        }

        if let Ok(app_record) = AppRecord::try_from(record) {
            match self.stat_app_table.entry(record.app_proto.to_string()) {
                HashMapEntry::Occupied(mut trans) => {
                    trans.get_mut().add_up(&app_record);
                }
                HashMapEntry::Vacant(trans) => {
                    trans.insert(app_record);
                }
            }
        }
    }

    pub fn update_multiple<'a>(&mut self, records: impl Iterator<Item = &'a Record>) {
        for record in records {
            self.update(record);
        }
    }
}
