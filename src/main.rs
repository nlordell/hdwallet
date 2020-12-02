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
    #[structopt(about = "Print account public address")]
    Address(address::Options),
    #[structopt(about = "Export a private key")]
    Export(export::Options),
    #[structopt(about = "Generate a new HD wallet mnemonic")]
    New(new::Options),
    #[structopt(about = "Sign a message")]
    Sign(sign::Options),
}

fn main() {
    if let Err(err) = match Options::from_args() {
        Options::Address(options) => address::run(options),
        Options::Export(options) => export::run(options),
        Options::New(options) => new::run(options),
        Options::Sign(options) => sign::run(options),
    } {
        if cfg!(debug_assertions) {
            eprintln!("ERROR: {:?}", err);
        } else {
            eprintln!("ERROR: {}", err);
        }
        process::exit(-1);
    }
}
