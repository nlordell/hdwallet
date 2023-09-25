//! Module containing the embedded SLIP-0039 word list.

use std::sync::OnceLock;

/// A parsed word list.
pub struct Wordlist<'a>(Vec<&'a str>);

/// The number of words in the list, as defined in SLIP-0039.
pub const WORD_COUNT: usize = 1024;
/// Masking value for a mnemonic word.
pub const WORD_MASK: usize = WORD_COUNT - 1;
/// The number of bits represented by each mnemonic word.
pub const WORD_BITS: usize = WORD_MASK.count_ones() as _;

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
        self.0.binary_search(&word.as_ref()).ok()
    }

    /// Returns the word for the specified index.
    ///
    /// # Panics
    ///
    /// This method panics if the index is out of range for the SLIP-0039 word
    /// list: it must be less than `WORD_COUNT` or `1024`.
    pub fn word(&'a self, index: usize) -> &'a str {
        assert!(index < WORD_COUNT, "invalid word index");
        self.0[index]
    }
}

/// Retrieves the SLIP-0039 word list.
pub fn wordlist() -> &'static Wordlist<'static> {
    static WORDLIST: OnceLock<Wordlist> = OnceLock::new();
    WORDLIST.get_or_init(|| Wordlist::parse(include_str!("wordlist.txt")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wordlist() {
        wordlist();
    }
}
