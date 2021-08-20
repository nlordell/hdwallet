mod account;
mod cmd;
mod hash;
mod hdk;
mod mnemonic;
mod rand;
mod serialization;
mod transaction;

#[cfg(test)]
mod ganache;

use std::process;
use structopt::StructOpt;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, StructOpt)]
#[structopt(
    name = "hdwallet",
    about = "Hierarchical deterministic wallet for Ethereum"
)]
enum Options {
    #[structopt(about = "Print account public address")]
    Address(cmd::address::Options),
    #[structopt(about = "Export a private key")]
    Export(cmd::export::Options),
    #[structopt(about = "Keccak256 hash data")]
    Hash(cmd::hash::Options),
    #[structopt(about = "Hex encoding and decoding")]
    Hex(cmd::hex::Options),
    #[structopt(about = "Generate a new HD wallet mnemonic")]
    New(cmd::new::Options),
    #[structopt(about = "Export the public key for an account")]
    PublicKey(cmd::public_key::Options),
    #[structopt(about = "Sign a message")]
    Sign(cmd::sign::Options),
}

fn main() {
    if let Err(err) = match Options::from_args() {
        Options::Address(options) => cmd::address::run(options),
        Options::Export(options) => cmd::export::run(options),
        Options::Hash(options) => cmd::hash::run(options),
        Options::Hex(options) => cmd::hex::run(options),
        Options::New(options) => cmd::new::run(options),
        Options::Sign(options) => cmd::sign::run(options),
        Options::PublicKey(options) => cmd::public_key::run(options),
    } {
        if cfg!(debug_assertions) {
            eprintln!("ERROR: {:?}", err);
        } else {
            eprintln!("ERROR: {}", err);
        }
        process::exit(-1);
    }
}
