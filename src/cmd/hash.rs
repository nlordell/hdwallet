//! Module implementing the `hash` subcommand for `keccak256` hashing data.

use crate::{cmd, hash};
use anyhow::Result;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Options {
    /// Path to the data to hash. Use `-` for standard in.
    #[structopt(name = "DATA", default_value = "-")]
    data: PathBuf,
}

pub fn run(options: Options) -> Result<()> {
    let data = cmd::read_input(&options.data)?;
    println!("0x{}", hex::encode(hash::keccak256(data)));
    Ok(())
}
