//! BIP-0039 mnemonic phrase implementation.

mod language;
mod wordlist;

pub use self::{language::Language, wordlist::WORD_COUNT};
use crate::{hash, rand};
use anyhow::{anyhow, ensure, Result};
use hmac::Hmac;
use sha2::Sha512;
use std::{
    convert::TryInto,
    fmt::{self, Display, Formatter},
    mem,
    ops::Deref,
    str::FromStr,
};
use unicode_normalization::UnicodeNormalization as _;

/// A seed generated from a BIP-0039 mnemonic used for an HD wallet.
#[derive(Clone, Debug)]
pub struct Mnemonic {
    /// The language for the mnemonic phrase.
    language: Language,
    /// A buffer containing the mnemonic's binary representation and hash used
    /// for checksums.
    buf: [u8; 64],
    /// The length of the seed bytes without the 32 byte hash.
    len: usize,
}

/// Masking value for a mnemonic word.
const WORD_MASK: usize = WORD_COUNT - 1;
/// The number of bits represented by each mnemonic word.
const WORD_BITS: usize = WORD_MASK.count_ones() as _;

impl Mnemonic {
    /// Generates a new cryptographically random seed for the specified mnemonic
    /// word length.
    ///
    /// This method returns an error if it fails if the specified mnemonic word
    /// length is invalid (it must be in the range `12..=24`) or if there is an
    /// error reading cryptographically strong entropy from the operating
    /// system.
    pub fn random(language: Language, mnemonic_length: usize) -> Result<Self> {
        let len = mnemonic_to_byte_length(mnemonic_length)?;
        let buf = {
            let mut buf = [0; 64];
            let (seed, hash) = buf.split_at_mut(len);

            rand::get_entropy(&mut *seed)?;
            hash[..32].copy_from_slice(&hash::sha256(seed));

            buf
        };

        Ok(Self { language, buf, len })
    }

    /// Parses a mnemonic from a phrase.
    pub fn from_phrase(mnemonic: impl AsRef<str>) -> Result<Self> {
        Self::from_phrase_str(mnemonic.as_ref())
    }

    fn from_phrase_str(mnemonic: &str) -> Result<Self> {
        let (language, words) = Language::split(mnemonic.as_ref())?;

        let len = mnemonic_to_byte_length(words.len())?;
        let buf = {
            let wordlist = language.wordlist();

            let mut buf = [0; 64];
            let (seed, hash) = buf.split_at_mut(len);

            let mut acc = 0;
            let mut bit_offset = 0;
            let mut byte_offset = 0;
            for word in &words {
                let index = wordlist
                    .search(word)
                    .ok_or_else(|| anyhow!("invalid BIP-0039 {} word '{}'", language, word))?;
                acc = (acc << WORD_BITS) | index;

                bit_offset += WORD_BITS;
                while bit_offset > 8 {
                    bit_offset -= 8;
                    seed[byte_offset] = ((acc >> bit_offset) & 0xff) as _;
                    byte_offset += 1;
                }
            }

            // NOTE: The remaining bits are checksum bits that we need to
            // verify now.
            debug_assert_eq!(len * 8 + bit_offset, words.len() * WORD_BITS);
            debug_assert_eq!(byte_offset, len);

            hash[..32].copy_from_slice(&hash::sha256(seed));

            let checksum_mask = (1 << bit_offset) - 1;
            ensure!(
                hash[0] >> (8 - bit_offset) == (acc & checksum_mask) as u8,
                "mnemonic checksum verification failure",
            );

            buf
        };

        Ok(Self { language, buf, len })
    }

    /// Gets the mnemonic's binary representation as a slice of bytes.
    #[cfg(test)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Gets the BIP-0039 mnemonic word length.
    pub fn mnemonic_length(&self) -> usize {
        ((self.len * 8) / WORD_BITS) + 1
    }

    /// Returns the BIP-0039 mnemonic phrase.
    pub fn to_phrase(&self) -> String {
        let wordlist = self.language.wordlist();
        let separator = self.language.separator();

        let mut buf = String::new();
        for i in 0..self.mnemonic_length() {
            let bit_offset = i * WORD_BITS;

            let offset = bit_offset / 8;
            let shift = mem::size_of::<usize>() * 8 - WORD_BITS - bit_offset % 8;
            let index = (usize::from_be_bytes(
                self.buf[offset..][..mem::size_of::<usize>()]
                    .try_into()
                    .unwrap(),
            ) >> shift)
                & WORD_MASK;

            buf.push_str(wordlist.word(index as _));
            buf.push(separator);
        }

        buf.pop();
        buf
    }

    /// Gets the PBKDF2 stretched binary seed for this mnemonic.
    pub fn seed(&self, password: impl AsRef<str>) -> Seed {
        const ROUNDS: u32 = 2048;

        let mut buf = [0; 64];
        let salt = format!("mnemonic{}", password.as_ref());
        pbkdf2::pbkdf2::<Hmac<Sha512>>(
            self.to_phrase().as_bytes(),
            salt.nfkd().to_string().as_bytes(),
            ROUNDS,
            &mut buf,
        );

        Seed(buf)
    }
}

impl Display for Mnemonic {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(&self.to_phrase())
    }
}

impl FromStr for Mnemonic {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_phrase(s)
    }
}

/// A 64 byte seed derived from a BIP-0039 mnemonic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Seed([u8; 64]);

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Seed {
    type Target = [u8; 64];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn mnemonic_to_byte_length(len: usize) -> Result<usize> {
    ensure!(matches!(len, 12..=24), "invalid mnemonic length {}", len);

    // NOTE: Derived from the BIP-0039 spec where `CS` is the checksum bit
    // length, `ENT` is the entropy bit length (so `8 * byte_length`) and `MS`
    // is the mnemonic word length.
    // ```
    // CS = ENT / 32
    // MS = (ENT + CS) / 11
    // ```
    // <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic>
    Ok((len * WORD_BITS * 32 / 33) / 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn random_mnemonic() {
        for &(bit_length, mnemonic_length) in
            &[(128, 12), (160, 15), (192, 18), (224, 21), (256, 24)]
        {
            let mnemonic = Mnemonic::random(Language::English, mnemonic_length).unwrap();
            assert_eq!(mnemonic.as_bytes().len() * 8, bit_length);
            let all_zeros = mnemonic.as_bytes().iter().all(|&byte| byte == 0);
            assert!(!all_zeros);
        }
    }

    #[test]
    fn mnemonic_phrases() {
        for &(bytes, phrase, password, seed) in &[
            (
                &hex!("00000000000000000000000000000000")[..],
                "abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon about",
                "TREZOR",
                hex!(
                    "c552 57c3 60c0 7c72 029a ebc1 b53c 05ed
                     0362 ada3 8ead 3e3e 9efa 3708 e534 9553
                     1f09 a698 7599 d182 64c1 e1c9 2f2c f141
                     630c 7a3c 4ab7 c81b 2f00 1698 e746 3b04"
                ),
            ),
            (
                &hex!("92903465e029df56cab416a53b015396")[..],
                "myth like bonus scare over problem \
                 client lizard pioneer submit female collect",
                "",
                hex!(
                    "15e7 bbc6 ac54 a721 ad44 0f8e f7d1 fa7c
                     4f77 ae5e c71e 2418 7649 e9d2 2802 2655
                     b9e6 fb36 59f8 e4b2 274a c3b1 955b f9e5
                     8f15 0492 c44e 7aa1 6109 5ba0 ad92 6e9e"
                ),
            ),
            (
                &hex!("0000000000000000000000000000000000000000000000000000000000000000")[..],
                "abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon art",
                "TREZOR",
                hex!(
                    "bda8 5446 c684 1370 7090 a520 22ed d26a
                     1c94 6229 5029 f2e6 0cd7 c4f2 bbd3 0971
                     70af 7a4d 7324 5caf a9c3 cca8 d561 a7c3
                     de6f 5d4a 10be 8ed2 a5e6 08d6 8f92 fcc8"
                ),
            ),
            (
                &hex!("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f")[..],
                "void come effort suffer camp survey \
                 warrior heavy shoot primary clutch crush \
                 open amazing screen patrol group space \
                 point ten exist slush involve unfold",
                "TREZOR",
                hex!(
                    "01f5 bced 59de c48e 362f 2c45 b5de 68b9
                     fd6c 92c6 634f 44d6 d40a ab69 0565 06f0
                     e355 24a5 1803 4ddc 1192 e1da cd32 c1ed
                     3eaa 3c3b 131c 88ed 8e7e 54c4 9a5d 0998"
                ),
            ),
        ] {
            let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
            assert_eq!(mnemonic.as_bytes(), bytes);
            assert_eq!(*mnemonic.seed(password), seed);
            assert_eq!(mnemonic.to_phrase(), phrase);
        }
    }
}
