mod cli;
mod gui;
mod socket;
mod utils;

use anyhow::Result;

use clap::Parser;
use cli::CliArgs;

// use nwd::NwgUi;
// use nwg::NativeUi;

fn main() -> Result<()> {
    let cli_args = CliArgs::parse();
    if cli_args.cli {
        cli::main(&cli_args)
    } else {
        gui::main()
    }
}
