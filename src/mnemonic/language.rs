//! Mnemonic language for selecting word lists.

use anyhow::{bail, Result};
use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

/// The mnemonic langage used to select the word list.
#[derive(Clone, Copy, Debug)]
pub enum Language {
    English,
    // TODO(nlordell): Support more languages. Note that this is not necessarily
    // trivial as some have specific considerations (like 'ñ' being equivalent
    // to 'n' in Spanish, and Japanese using '\u{3000}` for spaces).
}

impl Language {
    /// Splits a mnemonic phrase into its words, returning the detected language
    /// and a vector of **normalized** words.
    pub fn split(phrase: impl AsRef<str>) -> Result<(Self, Vec<String>)> {
        // TODO(nlordell): A lot to do here...
        Ok((
            Language::English,
            phrase
                .as_ref()
                .trim()
                .split_whitespace()
                .filter(|word| !word.is_empty())
                .map(|word| word.to_lowercase())
                .collect(),
        ))
    }
}

impl Default for Language {
    fn default() -> Self {
        // TODO(nlordell): Read the default language from the system locale.
        Language::English
    }
}

impl Display for Language {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(match self {
            Language::English => "english",
        })
    }
}

impl FromStr for Language {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s.to_lowercase().as_str() {
            "english" => Language::English,
            _ => bail!("unsupported language '{}'", s),
        })
    }
}
