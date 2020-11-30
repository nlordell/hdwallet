//! Cryptographically secure randomness.

use std::{io, os::raw::c_int};

/// Populates the provided slice with cryptographically strong entropy.
pub fn get_entropy(mut buf: impl AsMut<[u8]>) -> io::Result<()> {
    let buf = buf.as_mut();
    let result = unsafe { getentropy(buf.as_mut_ptr(), buf.len()) };
    if result >= 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

extern "C" {
    fn getentropy(buffer: *mut u8, len: usize) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_os_entropy() {
        let mut buf = [0u8; 32];
        assert!(get_entropy(&mut buf[..16]).is_ok());
        assert!(get_entropy(&mut buf).is_ok());
    }

    #[test]
    fn error_reading_more_than_256_bytes() {
        let mut buf = [0u8; 257];
        assert!(get_entropy(&mut buf).is_err());
    }
}
