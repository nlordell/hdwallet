mod cmd;

use clap::Parser;
use std::process;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Parser)]
#[clap(version, about)]
enum Options {
    #[clap(about = "Print account public address")]
    Address(cmd::address::Options),
    #[clap(about = "Export a private key")]
    Export(cmd::export::Options),
    #[clap(about = "Keccak256 hash data")]
    Hash(cmd::hash::Options),
    #[clap(about = "Hex encoding and decoding")]
    Hex(cmd::hex::Options),
    #[clap(about = "Generate a new HD wallet mnemonic")]
    New(cmd::new::Options),
    #[clap(about = "Export the public key for an account")]
    PublicKey(cmd::public_key::Options),
    #[clap(about = "Sign a message")]
    Sign(cmd::sign::Options),
}

fn main() {
    if let Err(err) = match Options::parse() {
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
