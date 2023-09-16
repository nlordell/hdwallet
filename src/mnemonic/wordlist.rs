//! Module containing the embedded BIP-0039 word lists.

use crate::mnemonic::Language;
use std::sync::OnceLock;

/// A parsed word list.
pub struct Wordlist<'a>(Vec<&'a str>);

/// The number of words in a list, as defined in BIP-0039.
pub const WORD_COUNT: usize = 2048;

impl<'a> Wordlist<'a> {
    /// Parses a list of newline-separated words.
    fn parse(words: &'a str) -> Wordlist<'a> {
        let words = words.trim().split('\n').map(str::trim).collect::<Vec<_>>();

        debug_assert_eq!(words.len(), WORD_COUNT);
        debug_assert!(words
            .iter()
            .all(|word| word.chars().all(char::is_lowercase)));
        debug_assert!(words.windows(2).all(|pair| pair[0] < pair[1]));

        Wordlist(words)
    }

    /// Searches the word list for the specified word returning its numerical
    /// value representing its index in the list. This method returns `None`
    /// if the word does not belong to the list.
    pub fn search(&self, word: impl AsRef<str>) -> Option<usize> {
        // TODO(nlordell): It is possible to be generous here and fix common
        // spelling mistakes as well as only consider the first letters of the
        // word as long as it is unique. Additionally, certain languages have
        // equivalent characters like Spanish with 'ñ' and 'n'.
        self.0.binary_search(&word.as_ref()).ok()
    }

    /// Returns the word for the specified index.
    ///
    /// # Panics
    ///
    /// This method panics if the index is out of range for the BIP-0039 word
    /// list: it must be less than `WORD_COUNT` or `1024`.
    pub fn word(&'a self, index: usize) -> &'a str {
        assert!(index < WORD_COUNT, "invalid word index");
        self.0[index]
    }
}

macro_rules! match_language {
    ($lang:expr; $(
        $l:ident => $f:expr,
    )*) => {$(
        match $lang {
            Language::$l => {
                static WORDLIST: OnceLock<Wordlist> = OnceLock::new();
                WORDLIST.get_or_init(|| {
                    Wordlist::parse(include_str!(concat!("wordlist/", $f)))
                })
            }
        }
    )*};
}

/// Retrieves the wordlist for the specified language.
pub fn for_language(language: Language) -> &'static Wordlist<'static> {
    match_language! { language;
        English => "english.txt",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wordlists() {
        for_language(Language::English);
    }
}
