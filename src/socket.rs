use anyhow::{anyhow, Result};

use socket2::{Domain, Socket, Type};
use std::os::windows::prelude::{AsRawSocket, RawSocket};
use std::{
    io::{self, Read},
    mem,
    net::SocketAddr,
    ptr,
};
use winapi::ctypes::c_int;
use winapi::shared::{mstcpip, ws2def, ws2ipdef};
use winapi::um::winsock2 as sock;

macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ), $err_test: path, $err_value: expr) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { sock::$fn($($arg, )*) };
        if $err_test(&res, &$err_value) {
            Err(io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

unsafe fn setsockopt<T>(
    socket: RawSocket,
    level: c_int,
    optname: c_int,
    optval: T,
) -> io::Result<()> {
    syscall!(
        setsockopt(
            socket as usize,
            level,
            optname,
            (&optval as *const T).cast(),
            mem::size_of::<T>() as c_int,
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| ())
}

pub trait SocketExt {
    fn set_recv_ip_header(&self, recv_ip_header: bool) -> io::Result<()>;
    fn set_recv_ip_header_v6(&self, recv_ip_header: bool) -> io::Result<()>;
    fn set_recv_all_packets(&self, recv_all_packets: bool) -> io::Result<()>;
}

impl SocketExt for Socket {
    fn set_recv_ip_header(&self, recv_ip_header: bool) -> io::Result<()> {
        let recv_ip_header = recv_ip_header as c_int;
        unsafe {
            setsockopt(
                self.as_raw_socket(),
                ws2def::IPPROTO_IP,
                ws2ipdef::IP_HDRINCL,
                recv_ip_header,
            )
        }
    }

    fn set_recv_ip_header_v6(&self, recv_ip_header: bool) -> io::Result<()> {
        unsafe {
            setsockopt(
                self.as_raw_socket(),
                ws2def::IPPROTO_IP,
                ws2ipdef::IPV6_HDRINCL,
                recv_ip_header,
            )
        }
    }

    fn set_recv_all_packets(&self, recv_all_packets: bool) -> io::Result<()> {
        let mut in_buf: mstcpip::RCVALL_VALUE = if recv_all_packets {
            mstcpip::RCVALL_ON
        } else {
            mstcpip::RCVALL_OFF
        };
        let mut out = 0;
        syscall!(
            WSAIoctl(
                self.as_raw_socket() as usize,
                mstcpip::SIO_RCVALL,
                &mut in_buf as *mut _ as *mut _,
                mem::size_of_val(&in_buf) as _,
                ptr::null_mut(),
                0,
                &mut out,
                ptr::null_mut(),
                None,
            ),
            PartialEq::eq,
            sock::SOCKET_ERROR
        )
        .map(|_| ())
    }
}

pub fn ipv4_capturer(address: SocketAddr, nonblocking: bool) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(ws2def::IPPROTO_IP.into()))?;
    socket.set_recv_ip_header(true)?;
    socket.set_nonblocking(nonblocking)?;
    socket.bind(&address.into())?;
    socket.set_recv_all_packets(true)?;
    Ok(socket)
}

#[derive(Default)]
pub struct Capturer {
    socket: Option<Socket>,
    buffer: Vec<u8>,
}

impl Capturer {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn capture(&mut self, address: SocketAddr, nonblocking: bool) -> io::Result<()> {
        drop(self.socket.take());
        let socket = ipv4_capturer(address, nonblocking)?;
        let buffer_size = socket.recv_buffer_size()?;
        if self.buffer.len() < buffer_size {
            self.buffer.resize(buffer_size, 0u8);
        }
        self.socket = Some(socket);
        Ok(())
    }
    pub fn connected(&self) -> bool {
        self.socket.is_some()
    }
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        if let Some(socket) = self.socket.as_ref() {
            socket.set_nonblocking(nonblocking)?;
            Ok(())
        } else {
            Err(anyhow!("no socket connection, capture an ip address first"))
        }
    }
    pub fn read_mut(&mut self) -> Result<&mut [u8]> {
        if let Some(socket) = self.socket.as_mut() {
            let bytes = match socket.read(self.buffer.as_mut_slice()) {
                Ok(bytes) => bytes,
                Err(err) => match err.raw_os_error() {
                    Some(10035) => 0,
                    _ => return Err(anyhow!(err)),
                },
            };
            Ok(&mut self.buffer[..bytes])
        } else {
            Err(anyhow!("no socket connection, capture an ip address first"))
        }
    }
    pub fn read(&mut self) -> Result<&[u8]> {
        self.read_mut().map(|s| &s[..])
    }
}
