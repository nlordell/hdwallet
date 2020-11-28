//! Module implementing the `new` command for generating a mnemonic for a new
//! hierarchical deterministic wallet.

use crate::mnemonic::Language;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(about = "generate a new HD wallet mnemonic")]
pub struct Options {
    language: Language,
}
