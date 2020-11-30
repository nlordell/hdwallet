//! BIP-0039 mnemonic phrase implementation.

mod language;
mod wordlist;

pub use self::{language::Language, wordlist::WORD_COUNT};
use crate::{hash, rand};
use anyhow::{anyhow, ensure, Result};
use std::{convert::TryInto, mem};

/// A seed generated from a BIP-0039 mnemonic used for an HD wallet.
#[derive(Clone, Debug)]
pub struct Seed {
    /// A buffer containing the seed bytes and hash used for checksums.
    buf: [u8; 64],
    /// The length of the seed bytes without the 32-byte hash.
    len: usize,
}

/// Masking value for a mnemonic word.
const WORD_MASK: usize = WORD_COUNT - 1;
/// The number of bits represented by each mnemonic word.
const WORD_BITS: usize = WORD_MASK.count_ones() as _;

impl Seed {
    /// Generates a new cryptographically random seed for the specified mnemonic
    /// word length.
    ///
    /// This method returns an error if it fails if the specified mnemonic word
    /// length is invalid (it must be in the range `12..=24`) or if there is an
    /// error reading cryptographically strong entropy from the operating
    /// system.
    pub fn random(mnemonic_length: usize) -> Result<Self> {
        let len = mnemonic_to_byte_length(mnemonic_length)?;
        let buf = {
            let mut buf = [0u8; 64];
            let (seed, hash) = buf.split_at_mut(len);

            rand::get_entropy(&mut *seed)?;
            hash[..32].copy_from_slice(&hash::sha256(seed));

            buf
        };

        Ok(Seed { buf, len })
    }

    /// Parses a seed from a mnemonic.
    pub fn from_mnemonic(mnemonic: impl AsRef<str>) -> Result<Self> {
        let (language, words) = Language::split(mnemonic.as_ref())?;

        let len = mnemonic_to_byte_length(words.len())?;
        let buf = {
            let wordlist = language.wordlist();

            let mut buf = [0u8; 64];
            let (seed, hash) = buf.split_at_mut(len);

            let mut acc = 0usize;
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
                hash[0] >> (8 - bit_offset) == (acc & checksum_mask) as _,
                "mnemonic checksum verification failure",
            );

            buf
        };

        Ok(Seed { buf, len })
    }

    /// Gets the seed as a slice of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Gets the BIP-0039 mnemonic word length for the seed.
    pub fn mnemonic_length(&self) -> usize {
        ((self.len * 8) / WORD_BITS) + 1
    }

    /// Generates a BIP-0039 mnemonic from the seed.
    pub fn to_mnemonic(&self, language: Language) -> String {
        let wordlist = language.wordlist();
        let separator = language.separator();

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
            buf.push(separator)
        }

        buf.pop();
        buf
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
    fn random_seed() {
        for &(bit_length, mnemonic_length) in
            &[(128, 12), (160, 15), (192, 18), (224, 21), (256, 24)]
        {
            let seed = Seed::random(mnemonic_length).unwrap();
            assert_eq!(seed.as_bytes().len() * 8, bit_length);
            let all_zeros = seed.as_bytes().iter().all(|&byte| byte == 0);
            assert!(!all_zeros);
        }
    }

    #[test]
    fn roundtrip_seed_to_mnemonic() {
        for &(bytes, mnemonic) in &[
            (
                &hex!("00000000000000000000000000000000")[..],
                "abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon about",
            ),
            (
                &hex!("92903465e029df56cab416a53b015396")[..],
                "myth like bonus scare over problem \
                 client lizard pioneer submit female collect",
            ),
            (
                &hex!("0000000000000000000000000000000000000000000000000000000000000000")[..],
                "abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon art",
            ),
            (
                &hex!("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f")[..],
                "void come effort suffer camp survey \
                 warrior heavy shoot primary clutch crush \
                 open amazing screen patrol group space \
                 point ten exist slush involve unfold",
            ),
        ] {
            let seed = Seed::from_mnemonic(mnemonic).unwrap();
            assert_eq!(seed.as_bytes(), bytes);
            assert_eq!(seed.to_mnemonic(Language::English), *mnemonic);
        }
    }
}
