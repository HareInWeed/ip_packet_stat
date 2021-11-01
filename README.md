# IP Stats

## Detail

- GUI: [Native Windows GUI](https://github.com/gabdube/native-windows-gui)
  - As for `native-windows-gui-1.0.12` under `rustc-1.56.0`, there is some compiling errors in `native-windows-gui-1.0.12/src/layouts/grid_layout.rs` line 457 and 458. In order to make this pass compilation, You have to manually modify

  ```rust
  ... ].iter().sum() + ... // line 457
  ... ].iter().sum() + ... // line 458
  ```

  into

  ```rust
  ... ].iter().sum::<u32>() + ... // line 457
  ... ].iter().sum::<u32>() + ... // line 458
  ```

- raw socket: 
  - [socket2](https://github.com/rust-lang/socket2) and [winapi-rs](https://github.com/retep998/winapi-rs)
    - Administrator permission is required due to raw socket api constraints
    - Does not support reading ipv6 packet header
  - [libpnet](https://github.com/libpnet/libpnet)
    - require Rust toolchain built on MSVC
    - require WinPcap or npcap in WinPcap API-compatible Mode installed
    - require static lib `Packet.lib`, which could be found in [WinPcap Developers pack](https://www.winpcap.org/devel.htm)
