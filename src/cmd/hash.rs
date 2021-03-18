//! Module implementing the `hash` subcommand for `keccak256` hashing data.

use crate::{cmd, hash};
use anyhow::Result;
use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
    str,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct Options {
    /// The data is hexidecimal encoded.
    #[structopt(short, long)]
    hex: bool,

    /// Path to the data to hash. Use `-` for standard in.
    #[structopt(name = "DATA", default_value = "-")]
    data: PathBuf,
}

pub fn run(options: Options) -> Result<()> {
    let data = match options.data.to_str() {
        Some("-") => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            buf
        }
        _ => fs::read(&options.data)?,
    };
    let bytes = if options.hex {
        cmd::permissive_hex(str::from_utf8(&data)?)?
    } else {
        data.into_boxed_slice()
    };

    println!("0x{}", hex::encode(hash::keccak256(bytes)));
    Ok(())
}
