//! Module containing subcommands.

pub mod address;
pub mod export;
pub mod new;
pub mod sign;

use crate::{account::PrivateKey, hdk, mnemonic::Mnemonic};
use anyhow::Result;
use structopt::StructOpt;

/// Shared account options.
#[derive(Debug, StructOpt)]
struct AccountOptions {
    /// The BIP-0039 mnemonic phrase for seeding the HD wallet.
    #[structopt(short, long, env)]
    mnemonic: Mnemonic,

    /// The password to use with the mnemonic phrase for salting the seed used
    /// for the HD wallet.
    #[structopt(long, env, default_value)]
    password: String,

    /// The BIP-44 account index for deriving a private from the mnemonic seed
    /// phrase. The derived key will use the path "m/44'/60'/0'/0/{index}".
    #[structopt(long, env, default_value = "0")]
    account_index: usize,

    /// Manually specified HD path for deriving the account key. This option can
    /// not be used in conjunction with the "--account-index" option.
    #[structopt(long, env, conflicts_with = "account-index")]
    hd_path: Option<String>,
}

impl AccountOptions {
    /// Returns the private key for the specified account options.
    pub fn private_key(&self) -> Result<PrivateKey> {
        let seed = self.mnemonic.seed(&self.password);
        let path = match &self.hd_path {
            None => format!("m/44'/60'/0'/0/{}", self.account_index).parse(),
            Some(hd_path) => hd_path.parse(),
        }?;
        hdk::derive(seed, &path)
    }
}
