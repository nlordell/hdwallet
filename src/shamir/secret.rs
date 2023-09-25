//! SLIP-0039 secret splitting and restoring.

use super::ff;
use crate::rand;
use anyhow::{ensure, Result};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;

/// Lagrange interpolation of a polynomial at `x` described by the specified
/// points.
fn interpolate(ps: &[(u8, &[u8])], x: u8, y: &mut [u8]) {
    assert_lengths(y.len(), ps.iter().map(|(_, yi)| *yi));

    let ps = || ps.iter().copied().enumerate();
    for (i, (xi, yi)) in ps() {
        let mut pi = 1;
        for (j, (xj, _)) in ps().filter(|(j, _)| *j != i) {
            debug_assert!(xi != xj, "duplicate point");
            pi = ff::mul(pi, ff::div(ff::sub(x, xj), ff::sub(xi, xj)));
        }
        for (yk, yik) in y.iter_mut().zip(yi) {
            *yk = ff::add(*yk, ff::mul(*yik, pi));
        }
    }
}

/// Splits a secret into `n` shares, with a threshold recovery `t`. Returns a
/// `Vec` with `n` elements representing each of the shares.
pub fn split(t: usize, n: usize, s: &[u8]) -> Vec<Vec<u8>> {
    let m = s.len();
    debug_assert!(
        0 < t && t <= n && n <= 16 && m >= 16 && m % 2 == 0,
        "invalid shamir parameters",
    );

    if t == 1 {
        return (0..n).map(|_| s.to_vec()).collect();
    }

    let d = {
        let mut buf = vec![0; m];

        let r = &mut buf[4..];
        rand::fill(r);

        let code = hmac_sha256(r, s);
        buf[..4].copy_from_slice(&code[..4]);

        buf
    };

    let mut ys = vec![vec![0; m]; n];
    let (ysr, ysi) = ys.split_at_mut(t - 2);

    for y in ysr.iter_mut() {
        rand::fill(y.as_mut());
    }

    let ps = ysr
        .iter()
        .enumerate()
        .map(|(x, y)| (x as u8, &y[..]))
        .chain([(254, &d[..]), (255, s)])
        .collect::<Vec<_>>();
    for (i, y) in ysi.iter_mut().enumerate() {
        let x = i + t - 2;
        interpolate(&ps, x as _, y);
    }

    ys
}

/// Recovers a secret from a list of shares for a threshold `t`.
pub fn recover(ps: &[(u8, &[u8])]) -> Result<Vec<u8>> {
    let t = ps.len();
    let m = ps.first().map(|(_, y)| y.len()).unwrap_or_default();
    assert_lengths(m, ps.iter().map(|(_, y)| *y));
    debug_assert!(
        0 < t && t <= 16 && m >= 16 && m % 2 == 0,
        "invalid shamir parameters"
    );

    if t == 1 {
        return Ok(ps[0].1.to_vec());
    }

    let (mut s, mut d) = (vec![0; m], vec![0; m]);

    interpolate(ps, 255, &mut s);
    interpolate(ps, 254, &mut d);

    let r = &d[4..];
    let code = hmac_sha256(r, &s[..]);

    ensure!(d[..4] == code[..4], "secret checksum mismatch");
    Ok(s)
}

fn hmac_sha256(r: &[u8], s: &[u8]) -> [u8; 32] {
    Hmac::<Sha256>::new_from_slice(r)
        .expect("HMAC should accept arbitrary key sizes")
        .chain_update(&s)
        .finalize()
        .into_bytes()
        .into()
}

fn assert_lengths<'a>(m: usize, mut ys: impl Iterator<Item = &'a [u8]>) {
    debug_assert!(
        ys.all(|y| y.len() == m),
        "secret and shares have different lengths",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lagrange_interpolation() {
        let mut y = [0, 0];
        interpolate(&[(1, &[118, 56]), (2, &[146, 14])], 0, &mut y);

        assert_eq!(y, [42, 42]);
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

        let shares = split(3, 5, &secret);

        // Insufficient shares
        assert!(recover(&[(0, &shares[0]), (1, &shares[1])]).is_err());

        // Exact amount of shares
        for i in 0..5 {
            for j in 0..5 {
                for k in 0..5 {
                    if i == j || i == k || j == k {
                        continue;
                    }

                    let exact = recover(&[
                        (i as _, &shares[i]),
                        (j as _, &shares[j]),
                        (k as _, &shares[k]),
                    ])
                    .unwrap();
                    assert_eq!(secret[..], exact);
                }
            }
        }

        // Extra shares
        let extra = recover(&[
            (0, &shares[0]),
            (1, &shares[1]),
            (2, &shares[2]),
            (3, &shares[3]),
            (4, &shares[4]),
        ])
        .unwrap();
        assert_eq!(secret[..], extra);
    }

    #[test]
    fn very_large_secret() {
        let secret = [42; 8192];
        let shares = split(2, 2, &secret);
        let recovered = recover(&[(0, &shares[0]), (1, &shares[1])]).unwrap();

        assert_eq!(&secret[..], recovered);
    }
}
