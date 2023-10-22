//! Module implementing the `new` subcommand for generating a mnemonic for a new
//! hierarchical deterministic wallet.

use crate::cmd::AccountOptions;
use anyhow::{Context, Result};
use clap::Parser;
use ethaddr::Address;
use hdwallet::mnemonic::{Language, Mnemonic};
use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

#[derive(Debug, Parser)]
pub struct Options {
    /// The number of words for the mnemonic phrase.
    #[clap(short = 'n', long, default_value_t = 12)]
    length: usize,

    /// The language to generate the mnemonic for.
    #[clap(short, long, default_value_t)]
    language: Language,

    /// Choose a vanity prefix for a public for the new mnemonic.
    #[clap(long)]
    vanity_prefix: Option<Prefix>,

    /// The password to use of the account whose private key should match the
    /// vanity prefix specifed in "--vanity-prefix".
    #[clap(long, default_value_t)]
    vanity_password: String,

    /// The BIP-44 account index that should of the account whose private key
    /// should match the vanity prefix specifed in "--vanity-prefix".
    #[clap(long, default_value_t = 0)]
    vanity_account_index: usize,

    /// Manually specified HD path for deriving the account key that should
    /// match the vanity prefix. This option can not be used in conjunction
    /// with the "--vanity-3account-index" option.
    #[clap(long, conflicts_with = "vanity_account_index")]
    vanity_hd_path: Option<String>,
}

#[derive(Clone, Debug)]
struct Prefix {
    bytes: Vec<u8>,
    nibble: Option<u8>,
}

impl Prefix {
    fn matches(&self, addr: Address) -> bool {
        let start = || addr.starts_with(&self.bytes);
        let end = || {
            if let Some(nibble) = self.nibble {
                addr.get(self.bytes.len())
                    .map(|last| last >> 4 == nibble)
                    .unwrap_or(false)
            } else {
                true
            }
        };

        start() && end()
    }
}

impl Display for Prefix {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str("0x")?;
        for byte in &self.bytes {
            write!(f, "{byte:02x}")?;
        }
        if let Some(nibble) = self.nibble {
            write!(f, "{nibble:x}")?;
        }
        Ok(())
    }
}

impl FromStr for Prefix {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").context("missing '0x' prefix")?;

        let parse_nibble = |n: u8| match n {
            b'0'..=b'9' => Ok(n - b'0'),
            b'a'..=b'f' => Ok(n - b'a' + 0xa),
            b'A'..=b'F' => Ok(n - b'a' + 0xa),
            _ => anyhow::bail!("invalid hex digit {n:#x}"),
        };

        let mut bytes = vec![0; s.len() / 2];
        let mut nibble = None;
        for (i, c) in s.as_bytes().chunks(2).enumerate() {
            match c {
                [hi, lo] => bytes[i] = (parse_nibble(*hi)? << 4) + parse_nibble(*lo)?,
                [ni] => nibble = Some(parse_nibble(*ni)?),
                _ => unreachable!(),
            }
        }

        Ok(Self { bytes, nibble })
    }
}

pub fn run(options: Options) -> Result<()> {
    let random_mnemonic = || Mnemonic::random(options.language, options.length);
    let mnemonic = if let Some(prefix) = options.vanity_prefix {
        let mut account = AccountOptions {
            mnemonic: random_mnemonic()?,
            password: options.vanity_password,
            account_index: options.vanity_account_index,
            hd_path: options.vanity_hd_path,
        };
        while !prefix.matches(account.private_key()?.address()) {
            account.mnemonic = random_mnemonic()?;
        }

        account.mnemonic
    } else {
        random_mnemonic()?
    };

    println!("{mnemonic}");
    Ok(())
}
