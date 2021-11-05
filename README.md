# IP Stats

## Detail

- GUI: [Native Windows GUI](https://github.com/gabdube/native-windows-gui)
- raw socket: 
  - [socket2](https://github.com/rust-lang/socket2) and [winapi-rs](https://github.com/retep998/winapi-rs)
    - Administrator permission is required due to raw socket api constraints
    - Does not support reading ipv6 packet header
  - [libpnet](https://github.com/libpnet/libpnet)
    - require Rust toolchain built on MSVC
    - require WinPcap or npcap in WinPcap API-compatible Mode installed
    - require static lib `Packet.lib`, which could be found in [WinPcap Developers pack](https://www.winpcap.org/devel.htm)
