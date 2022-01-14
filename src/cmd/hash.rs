//! Module implementing the `hash` subcommand for `keccak256` hashing data.

use crate::cmd;
use anyhow::Result;
use clap::Parser;
use hdwallet::hash;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct Options {
    /// Path to the data to hash. Use `-` for standard in.
    #[clap(name = "DATA", default_value = "-")]
    data: PathBuf,
}

pub fn run(options: Options) -> Result<()> {
    let data = cmd::read_input(&options.data)?;
    println!("0x{}", hex::encode(hash::keccak256(data)));
    Ok(())
}
