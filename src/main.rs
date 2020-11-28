mod cmd;
mod mnemonic;

use crate::cmd::*;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "hdwallet",
    about = "Hierarchical deterministic wallet for Ethereum",
)]
enum Options {
    New(new::Options),
}

fn main() {
    match Options::from_args() {
        Options::New(options) => new::run(options),
    }
}
