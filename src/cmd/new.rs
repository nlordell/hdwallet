//! Module implementing the `new` command for generating a mnemonic for a new
//! hierarchical deterministic wallet.

use crate::mnemonic::{Language, Seed};
use anyhow::Result;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(about = "generate a new HD wallet mnemonic")]
pub struct Options {
    /// The number of words for the mnemonic phrase.
    #[structopt(short = "n", long, default_value = "12")]
    length: usize,

    /// The language to generate the mnemonic for.
    #[structopt(short, long, default_value)]
    language: Language,
}

pub fn run(options: Options) -> Result<()> {
    let seed = Seed::random(options.length)?;
    println!("{}", seed.to_mnemonic(options.language));

    Ok(())
}
