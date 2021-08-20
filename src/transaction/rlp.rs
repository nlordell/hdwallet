//! Tiny (and inefficient) RLP encoding implementation.

use ethnum::U256;

/// RLP encode a list.
pub fn list(items: &[&[u8]]) -> Vec<u8> {
    let total_len = items.iter().map(|item| item.len()).sum();
    let mut buf = len(total_len, 0xc0);
    for item in items {
        buf.extend_from_slice(item);
    }
    buf
}

/// RLP encodes an iterator as a list.
pub fn iter<U, I>(items: I) -> Vec<u8>
where
    U: AsRef<[u8]>,
    I: IntoIterator<Item = U>,
{
    let collected = items.into_iter().collect::<Vec<_>>();
    let items = collected.iter().map(U::as_ref).collect::<Vec<_>>();
    list(&items)
}

/// RLP encode some bytes.
pub fn bytes(bytes: &[u8]) -> Vec<u8> {
    match bytes {
        [x] if *x < 0x80 => vec![*x],
        _ => {
            let mut buf = len(bytes.len(), 0x80);
            buf.extend_from_slice(bytes);
            buf
        }
    }
}

/// RLP encode a length.
pub fn len(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        vec![len as u8 + offset]
    } else {
        let bl_buf = len.to_be_bytes();
        let bl = {
            let start = len.leading_zeros() / 8;
            &bl_buf[start as usize..]
        };
        let mut buf = vec![bl.len() as u8 + offset + 55];
        buf.extend_from_slice(bl);
        buf
    }
}

/// RLP encode a unsigned integer. This ensures that it is shortned to its
/// shortest little endian byte representation.
pub fn uint(value: U256) -> Vec<u8> {
    let start = value.leading_zeros() / 8;
    bytes(&value.to_be_bytes()[start as usize..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_encoding() {
        assert_eq!(len(1024, 0x80), [0xb9, 0x04, 0x00]);
    }

    #[test]
    fn examples() {
        // RLP encoding examples taken from the Ethereum wiki
        // <https://eth.wiki/en/fundamentals/rlp>
        assert_eq!(bytes(b"dog"), b"\x83dog");
        assert_eq!(
            list(&[&bytes(b"cat"), &bytes(b"dog")]),
            b"\xc8\x83cat\x83dog"
        );
        assert_eq!(bytes(b""), [0x80]);
        assert_eq!(list(&[]), [0xc0]);
        assert_eq!(uint(U256::ZERO), [0x80]);
        assert_eq!(bytes(b"\0"), [0x00]);
        assert_eq!(uint(U256::new(15)), [0x0f]);
        assert_eq!(uint(U256::new(1024)), [0x82, 0x04, 0x00]);
        assert_eq!(
            list(&[
                &list(&[]),
                &list(&[&list(&[])]),
                &list(&[&list(&[]), &list(&[&list(&[])]),]),
            ]),
            [0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0],
        );
        assert_eq!(
            bytes(b"Lorem ipsum dolor sit amet, consectetur adipisicing elit"),
            b"\xb8\x38Lorem ipsum dolor sit amet, consectetur adipisicing elit"
        );
    }
}
