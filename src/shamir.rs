//! Shamir Secret Sharing implementation.
//!
//! This implementation follows the SLIP-0039 standard for generating and
//! encoding shares with mnemonics.

use crate::rand;
use anyhow::{ensure, Result};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;

mod ff;

/// A single share for a secret.
pub struct Share {}

/// Lagrange interpolation of a polynomial at `x` described by the specified
/// points.
fn interpolate<const N: usize>(x: u8, points: &[(u8, &[u8; N])]) -> [u8; N] {
    let points = || points.iter().copied();

    let mut y = [0; N];
    for (xi, yi) in points() {
        let mut pi = 1;
        for (xj, _) in points().filter(|(xj, _)| *xj != xi) {
            pi = ff::mul(pi, ff::div(ff::sub(x, xj), ff::sub(xi, xj)));
        }
        for k in 0..N {
            y[k] = ff::add(y[k], ff::mul(yi[k], pi));
        }
    }
    y
}

/// Splits a secret into `n` shares, with a threshold recovery `t`. Returns a
/// `Vec` with `n` elements representing each of the shares.
fn split_secret<const N: usize>(t: usize, n: usize, s: &[u8; N]) -> Vec<[u8; N]> {
    debug_assert!(
        0 < t && t <= n && n <= 16 && N >= 16 && N <= 36,
        "invalid shamir parameters",
    );

    if t == 1 {
        return (0..n).map(|_| *s).collect();
    }

    let d = {
        let mut buf = [0; N];

        let r = &mut buf[4..];
        rand::fill(r);

        let mut mac = Hmac::<Sha256>::new_from_slice(r).expect("r is small enough");
        mac.update(s);
        let code = mac.finalize().into_bytes();
        buf[..4].copy_from_slice(&code[..4]);

        buf
    };

    let mut ys = vec![[0; N]; n];
    let (ysr, ysi) = ys.split_at_mut(t - 2);

    for y in ysr.iter_mut() {
        rand::getentropy(y).expect("y is small enough");
    }

    let points = ysr
        .iter()
        .enumerate()
        .map(|(x, y)| (x as u8, y))
        .chain([(254, &d), (255, &s)])
        .collect::<Vec<_>>();
    for (i, y) in ysi.iter_mut().enumerate() {
        let x = i + t - 2;
        *y = interpolate(x as _, &points)
    }

    ys
}

/// Recovers a secret from a list of shares for a threshold `t`.
fn recover_secret<const N: usize>(t: usize, ps: &[(u8, &[u8; N])]) -> Result<[u8; N]> {
    debug_assert!(
        0 < t && t <= 16 && t <= ps.len() && N >= 16 && N <= 36,
        "invalid shamir parameters",
    );

    if t == 1 {
        return Ok(*ps[0].1);
    }

    let s = interpolate(255, ps);
    let d = interpolate(254, ps);

    let code = {
        let r = &d[4..];
        let mut mac = Hmac::<Sha256>::new_from_slice(r).expect("r is small enough");
        mac.update(&s);
        mac.finalize().into_bytes()
    };

    ensure!(d[..4] == code[..4], "secret checksum mismatch");

    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lagrange_interpolation() {
        assert_eq!(
            interpolate(0, &[(1, &[118, 56]), (2, &[146, 14])]),
            [42, 42]
        );
    }

    #[test]
    fn split_and_recover() {
        let secret = {
            let mut buf = [0; 32];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i + 1) as u8;
            }
            buf
        };

        let shares = split_secret(3, 5, &secret);
        for i in 0..5 {
            for j in 0..5 {
                for k in 0..5 {
                    if i == j || i == k || j == k {
                        continue;
                    }

                    let recovered = recover_secret(
                        3,
                        &[
                            (i as _, &shares[i]),
                            (j as _, &shares[j]),
                            (k as _, &shares[k]),
                        ],
                    )
                    .unwrap();
                    assert_eq!(secret, recovered);
                }
            }
        }

        let extra = recover_secret(
            3,
            &[
                (0, &shares[0]),
                (1, &shares[1]),
                (2, &shares[2]),
                (3, &shares[3]),
                (4, &shares[4]),
            ],
        )
        .unwrap();
        assert_eq!(secret, extra);

        let missing = interpolate(255, &[(0, &shares[0]), (1, &shares[1])]);
        assert_ne!(secret, missing);
    }
}
