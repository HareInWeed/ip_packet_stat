#![cfg_attr(not(test), windows_subsystem = "windows")]

mod cli;
mod filter;
mod gui;
mod meta;
mod record;
mod socket;
mod utils;

use anyhow::Result;

use std::env;

fn main() -> Result<()> {
    if env::args().len() > 1 {
        cli::main()
    } else {
        gui::main()
    }
}
