//! Shamir Secret Sharing implementation.
//!
//! This implementation follows the SLIP-0039 standard for generating and
//! encoding shares with mnemonics.

use self::wordlist::WORD_BITS;
use crate::{rand, shamir::wordlist::WORD_MASK};
use std::mem;

mod cypher;
mod ff;
mod secret;
mod wordlist;

/// A single share for a secret.
pub struct Share {
    id: i16,
    e: u8,
    gi: u8,
    gt: u8,
    g: u8,
    mi: u8,
    mt: u8,
    share: Vec<u8>,
}

/// Generates shares for the given input.
fn generate_shares(gt: usize, g: &[(usize, usize)], s: &[u8], p: &[u8], e: u32) -> Vec<Share> {
    debug_assert!(
        !g.iter().any(|&(t, n)| t == 1 && n == 1) && e < 0x1f,
        "invalid shamir paramters",
    );

    let id = {
        let mut buf = [0; 2];
        rand::fill(&mut buf);
        i16::from_be_bytes(buf) & 0x7fff
    };

    let es = cypher::encrypt(s, p, e, id);

    secret::split(gt, g.len(), &es)
        .iter()
        .enumerate()
        .zip(g)
        .flat_map(|((gi, s), &(mt, mn))| {
            secret::split(mt, mn, s)
                .into_iter()
                .enumerate()
                .map(move |(mi, share)| Share {
                    id,
                    e: e as _,
                    gi: gi as _,
                    gt: gt as _,
                    g: g.len() as _,
                    mi: mi as _,
                    mt: mt as _,
                    share,
                })
        })
        .collect()
}

fn words(bytes: &[u8]) -> impl Iterator<Item = usize> + '_ {
    let bits = bytes.len() * 8;
    let n = (bits + WORD_BITS - 1) / WORD_BITS;

    (0..n).rev().map(move |i| {
        let mut buf = [0; 4];
        let shift = i * WORD_BITS;

        let end = (bits - shift + 7) / 8;
        let rem = shift % 8;

        let start = end.saturating_sub(3);
        let len = end - start;

        buf[4 - len..].copy_from_slice(&bytes[start..end]);
        (u32::from_be_bytes(buf) >> rem) as usize & WORD_MASK
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn words_iterator() {
        let buf = (1..=15).map(|i| (i << 4) + i).collect::<Vec<_>>();
        let words = |i: usize| words(&buf[..i]).collect::<Vec<_>>();

        assert!(words(0).is_empty());

        assert_eq!(words(1), [0x011]);
        assert_eq!(words(2), [0x004, 0x122]);
        assert_eq!(words(3), [0x001, 0x048, 0x233]);
        assert_eq!(words(4), [0x000, 0x112, 0x08c, 0x344]);
        assert_eq!(words(5), [0x044, 0x223, 0x0d1, 0x055]);
        assert_eq!(words(6), [0x011, 0x088, 0x334, 0x115, 0x166]);
        assert_eq!(words(7), [0x004, 0x122, 0x0cd, 0x045, 0x159, 0x277]);
        assert_eq!(words(8), [0x001, 0x048, 0x233, 0x111, 0x156, 0x19d, 0x388]);
        assert_eq!(
            words(9),
            [0x000, 0x112, 0x08c, 0x344, 0x155, 0x267, 0x1e2, 0x099],
        );
        assert_eq!(
            words(10),
            [0x044, 0x223, 0x0d1, 0x055, 0x199, 0x378, 0x226, 0x1aa],
        );
        assert_eq!(
            words(11),
            [0x011, 0x088, 0x334, 0x115, 0x166, 0x1de, 0x089, 0x26a, 0x2bb],
        );
        assert_eq!(
            words(12),
            [0x004, 0x122, 0x0cd, 0x045, 0x159, 0x277, 0x222, 0x19a, 0x2ae, 0x3cc],
        );
        assert_eq!(
            words(13),
            [0x001, 0x048, 0x233, 0x111, 0x156, 0x19d, 0x388, 0x266, 0x2ab, 0x2f3, 0x0dd],
        );
        assert_eq!(
            words(14),
            [0x000, 0x112, 0x08c, 0x344, 0x155, 0x267, 0x1e2, 0x099, 0x2aa, 0x3bc, 0x337, 0x1ee],
        );
        assert_eq!(
            words(15),
            [0x044, 0x223, 0x0d1, 0x055, 0x199, 0x378, 0x226, 0x1aa, 0x2ef, 0x0cd, 0x37b, 0x2ff],
        );
    }
}
