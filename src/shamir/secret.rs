//! Implementation of SLIP-0039 secret encryption.

use hmac::Hmac;
use sha2::Sha256;
use std::iter;

/// Encrypts a secret using a 4-round Feistel cypher.
pub fn encrypt(s: &[u8], p: &[u8], e: u32, id: i16) -> Vec<u8> {
    feistel(s, p, e, id, [0, 1, 2, 3])
}

/// Decrypts a secret using a 4-round Feistel cypher.
pub fn decrypt(es: &[u8], p: &[u8], e: u32, id: i16) -> Vec<u8> {
    feistel(es, p, e, id, [3, 2, 1, 0])
}

fn feistel(m: &[u8], p: &[u8], e: u32, id: i16, instances: [u8; 4]) -> Vec<u8> {
    let n = m.len() / 2;
    debug_assert!(n * 2 == m.len(), "secret must be even number of bytes");

    let (l, r) = m.split_at(n);
    let mut output = [r, l].concat();
    let (mut r, mut l) = output.split_at_mut(n);

    let mut key = [&[0], p].concat();
    let mut salt = iter::empty()
        .chain(*b"shamir")
        .chain(id.to_be_bytes())
        .chain(iter::repeat(0).take(n))
        .collect::<Vec<_>>();
    let rounds = 2500 << e;
    let mut buf = vec![0; n];

    for i in instances {
        key[0] = i;
        salt[8..].copy_from_slice(r);
        pbkdf2::pbkdf2::<Hmac<Sha256>>(&key, &salt, rounds, &mut buf)
            .expect("HMAC can be initialized with any key length");
        for (l, b) in l.iter_mut().zip(&buf) {
            *l ^= *b;
        }

        (l, r) = (r, l);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feistel_ecryption() {
        let secret = b"hello shamir";
        let enc = encrypt(secret, b"password", 0, 0x1337);
        let dec = decrypt(&enc, b"password", 0, 0x1337);
        assert_eq!(secret[..], dec);
    }
}
