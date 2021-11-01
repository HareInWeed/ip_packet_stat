extern crate native_windows_derive as nwd;
extern crate native_windows_gui as nwg;

mod socket;

use anyhow::{anyhow, bail, Result};
use socket::SocketExt;
use socket2::{Domain, Socket, Type};
use std::{io::Read, net::SocketAddr};
use winapi::shared::ws2def::IPPROTO_IP;
// use nwd::NwgUi;
// use nwg::NativeUi;

fn main() -> Result<()> {
    let mut socket = Socket::new_raw(Domain::IPV4, Type::RAW, Some(IPPROTO_IP.into()))?;
    socket.set_recv_ip_header(true)?;
    socket.set_recv_all_packets(true)?;
    socket.set_nonblocking(true)?;
    let address: SocketAddr = "0.0.0.0:8000".parse()?;
    socket.bind(&address.into())?;

    let mut buffer = vec![0; socket.recv_buffer_size()?];
    loop {
        match socket.read(buffer.as_mut_slice()) {
            Ok(bytes) => {
                println!("read {} bytes: ", bytes);
                for (i, b) in buffer[..bytes].iter().enumerate() {
                    print!("{:02x} ", b);
                    match i % 16 {
                        7 => print!(" "),
                        15 => println!(),
                        _ => {}
                    }
                }
                if bytes % 16 != 0 {
                    println!();
                }
                println!();
            }
            Err(err) => match err.raw_os_error() {
                Some(10035) => continue,
                _ => bail!(err),
            },
        }
    }

    // Ok(())
}
