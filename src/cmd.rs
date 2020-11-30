//! Module containing subcommands.

pub mod address;
pub mod new;

use crate::{account::PrivateKey, hdk, mnemonic::Mnemonic};
use anyhow::Result;
use structopt::StructOpt;

/// Shared account options.
#[derive(Debug, StructOpt)]
struct AccountOptions {
    /// The BIP-0039 mnemonic phrase for seeding the HD wallet.
    #[structopt(short, long, env)]
    mnemonic: Mnemonic,

    /// The BIP-44 account index for deriving a private from the mnemonic seed
    /// phrase.
    #[structopt(long, env, default_value = "0")]
    account_index: usize,
}

impl AccountOptions {
    /// Returns the private key for the specified account options.
    pub fn private_key(&self) -> Result<PrivateKey> {
        let path = format!("m/44'/60'/0'/0/{}", self.account_index).parse()?;
        hdk::derive(&self.mnemonic, &path)
    }
}
