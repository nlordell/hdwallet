//! Module containing the embedded BIP-0039 word lists.

use std::borrow::Cow;

/// A parsed word list.
pub struct Wordlist<'a>(Vec<Cow<'a, str>>);

/// The number of words in a list, as defined in BIP-0039.
pub const WORD_COUNT: usize = 1024;

impl<'a> Wordlist<'a> {
    /// Parses a list of newline-separated words.
    fn parse(words: &'a str) -> Wordlist<'a> {
        let words = words
            .trim()
            .split('\n')
            .map(|word| {
                // TODO(nlordell): The words here need to be normalized for its
                // language, like converting 'ñ' to 'n' in Spanish.
                Cow::Borrowed(word.trim())
            })
            .collect::<Vec<_>>();

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
        // word as long as it is unique.
        self.0
            .binary_search_by_key(&word.as_ref(), |word| &word)
            .ok()
    }

    /// Returns the word for the specified index.
    ///
    /// # Panics
    ///
    /// This method panics if the index is out of range for the BIP-0039 word
    /// list: it must be less than `WORD_COUNT` or `1024`.
    pub fn word(&'a self, index: usize) -> &'a str {
        assert!(index < WORD_COUNT, "invalid word index");
        &self.0[index]
    }
}

macro_rules! define {
    ($(
        $(#[$attr:meta])*
        $vis:vis $lang:ident = $f:expr;
    )*) => {$(
        $(#[$attr])*
        $vis fn $lang() -> &'static Wordlist;
    )*};
}

define!();
