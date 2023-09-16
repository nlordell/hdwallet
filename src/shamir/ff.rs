//! Implementation of GF(256) using the Rijndael irreducible polynomial.

/// The Rijndael irreducible polynomial: `x⁸ + x⁴ + x³ + x + 1`.
const P: u16 = 0b01_0001_1011;

/// Adds two elements of GF(256). Constant time.
pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Subtracts two elements of GF(256). Constant time.
pub use add as sub;

/// Multiplies two elements of GF(256). Constant time.
pub fn mul(mut a: u8, mut b: u8) -> u8 {
    #[inline(always)]
    fn neg(x: u8) -> u8 {
        -(x as i8) as _
    }

    let mut p = 0;

    macro_rules! it {
        () => {
            p = add(p, neg(b & 1) & a);
            a = sub(a << 1, neg(a >> 7) & (P as u8));
            b >>= 1;
        };
    }
    it!();
    it!();
    it!();
    it!();
    it!();
    it!();
    it!();

    add(p, neg(b & 1) & a)
}

/// Divides two elements of GF(256). Constant time.
pub fn div(a: u8, b: u8) -> u8 {
    debug_assert_ne!(b, 0);

    #[inline(always)]
    fn inv(x: u8) -> u8 {
        // This is fun... but the inverse of b, is just b to the power of 254.
        let mut i = x;
        i = mul(i, i); // x^2
        i = mul(i, x); // x^3
        i = mul(i, i); // x^6
        i = mul(i, x); // x^7
        i = mul(i, i); // x^14
        i = mul(i, x); // x^15
        i = mul(i, i); // x^30
        i = mul(i, x); // x^31
        i = mul(i, i); // x^62
        i = mul(i, x); // x^63
        i = mul(i, i); // x^126
        i = mul(i, x); // x^127
        i = mul(i, i); // x^254
        i
    }

    mul(a, inv(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplication() {
        assert_eq!(mul(0x00, 0x00), 0x00);
        assert_eq!(mul(0x53, 0xca), 0x01);
    }

    #[test]
    fn division() {
        assert_eq!(div(0x01, 0x53), 0xca);
    }

    #[test]
    #[should_panic]
    fn divide_by_zero() {
        assert_eq!(div(0x01, 0x00), 0x00);
    }
}
