mod cmd;
mod hash;
mod mnemonic;
mod rand;

use crate::cmd::*;
use std::process;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "hdwallet",
    about = "Hierarchical deterministic wallet for Ethereum"
)]
enum Options {
    New(new::Options),
}

fn main() {
    if let Err(err) = match Options::from_args() {
        Options::New(options) => new::run(options),
    } {
        if cfg!(debug_assertions) {
            eprintln!("ERROR: {:?}", err);
        } else {
            eprintln!("ERROR: {}", err);
        }
        process::exit(-1);
    }
}
