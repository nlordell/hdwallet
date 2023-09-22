//! Cryptographically secure randomness.

use std::io;

/// The maximum amount of entropy that can be read at a time.
pub const MAX_SIZE: usize = 256;

/// Fills the specified slice with cryptographically strong entropy.
pub fn fill(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(MAX_SIZE) {
        getentropy(chunk).expect("chunk size less than max");
    }
}

/// Populates the specified slice with cryptographically strong entropy.
///
/// Returns an error if the buffer length is greater than [`MAX_SIZE`].
pub fn getentropy(buf: &mut [u8]) -> io::Result<()> {
    let result = unsafe { ffi::getentropy(buf.as_mut_ptr(), buf.len()) };
    if result >= 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

mod ffi {
    use std::ffi::c_int;

    extern "C" {
        pub fn getentropy(buffer: *mut u8, len: usize) -> c_int;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_os_entropy() {
        let mut buf = [0u8; 32];
        assert!(getentropy(&mut buf[..16]).is_ok());
        assert!(getentropy(&mut buf).is_ok());
    }

    #[test]
    fn error_reading_more_than_256_bytes() {
        let mut buf = [0u8; MAX_SIZE + 1];
        assert!(getentropy(&mut buf[..MAX_SIZE]).is_ok());
        assert!(getentropy(&mut buf).is_err());
    }
}
