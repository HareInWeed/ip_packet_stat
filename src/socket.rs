use socket2::{Domain, Socket};
use std::os::windows::prelude::{AsRawSocket, RawSocket};
use std::{io, mem, ptr};
use winapi::ctypes::{self, c_int};
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

unsafe fn getsockopt<T: Default>(socket: RawSocket, level: c_int, optname: c_int) -> io::Result<T> {
    let mut optval = T::default();
    let mut optlen = mem::size_of::<T>() as c_int;
    syscall!(
        getsockopt(
            socket as usize,
            level,
            optname,
            (&mut optval as *mut T).cast(),
            &mut optlen as *mut c_int,
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| optval)
}

pub trait SocketExt {
    fn domain(&self) -> io::Result<Domain>;
    fn set_recv_ip_header(&self, recv_ip_header: bool) -> io::Result<()>;
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
            )?;
        }
        if self.domain()? == Domain::IPV6 {
            unsafe {
                setsockopt(
                    self.as_raw_socket(),
                    ws2def::IPPROTO_IP,
                    ws2ipdef::IPV6_HDRINCL,
                    recv_ip_header,
                )?;
            }
        }
        Ok(())
    }

    fn domain(&self) -> io::Result<Domain> {
        // TODO: fully implement this
        Ok(Domain::IPV4)
    }

    fn set_recv_all_packets(&self, recv_all_packets: bool) -> io::Result<()> {
        let mut in_buf: mstcpip::RCVALL_VALUE = if recv_all_packets {
            mstcpip::RCVALL_ON
        } else {
            mstcpip::RCVALL_OFF
        };
        let mut out_buf = [0u32; 10];
        let mut out = 0;
        syscall!(
            WSAIoctl(
                self.as_raw_socket() as usize,
                mstcpip::SIO_RCVALL,
                &mut in_buf as *mut _ as *mut _,
                mem::size_of_val(&in_buf) as _,
                &mut out_buf as *mut _ as *mut _,
                mem::size_of_val(&out_buf) as _,
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
