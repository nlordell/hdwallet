mod account;
mod cmd;
mod hash;
mod hdk;
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
    Address(address::Options),
    New(new::Options),
}

fn main() {
    if let Err(err) = match Options::from_args() {
        Options::Address(options) => address::run(options),
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
