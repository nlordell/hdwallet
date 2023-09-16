//! Module implementing the hierachical deterministic key derivation scheme.

mod path;

pub use self::path::{Component, Path};
use crate::account::PrivateKey;
use anyhow::{Context as _, Result};
use hmac::{Hmac, Mac as _};
use k256::{elliptic_curve::sec1::ToEncodedPoint as _, SecretKey};
use sha2::Sha512;

/// A value indicating a path component is hardened.
const HARDENED: u32 = 0x8000_0000;

/// Creates a new extended private key for an account index using the standard
/// Ethereum HD path.
pub fn derive_index(seed: impl AsRef<[u8]>, account_index: usize) -> Result<PrivateKey> {
    derive(seed, &format!("m/44'/60'/0'/0/{account_index}").parse()?)
}

/// Creates a new extended private key from a seed.
pub fn derive(seed: impl AsRef<[u8]>, path: &Path) -> Result<PrivateKey> {
    derive_slice(seed.as_ref(), path)
}

fn derive_slice(seed: &[u8], path: &Path) -> Result<PrivateKey> {
    let mut extended_key = {
        let mut hmac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed")?;
        hmac.update(seed.as_ref());
        hmac.finalize().into_bytes()
    };

    for (i, component) in path.components().enumerate() {
        let (secret, chain_code) = extended_key.split_at(32);
        let secret = SecretKey::from_slice(secret)?;

        let mut hmac: Hmac<Sha512> = Hmac::<Sha512>::new_from_slice(chain_code)?;
        let value = match component {
            Component::Hardened(value) => {
                hmac.update(&[0]);
                hmac.update(&secret.to_bytes());
                value | HARDENED
            }
            Component::Normal(value) => {
                hmac.update(secret.public_key().to_encoded_point(true).as_bytes());
                value
            }
        };
        hmac.update(&value.to_be_bytes());

        let mut child_key = hmac.finalize().into_bytes();

        let child_secret = SecretKey::from_slice(&child_key[..32])
            .with_context(|| format!("path '{path}' component #{i} yields invalid child key"))?;
        let next_secret =
            SecretKey::new(*child_secret.as_scalar_primitive() + *secret.as_scalar_primitive());
        child_key[..32].copy_from_slice(&next_secret.to_bytes());

        extended_key = child_key
    }

    PrivateKey::new(&extended_key[..32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ganache::DETERMINISTIC_MNEMONIC, mnemonic::Mnemonic};
    use ethaddr::address;

    #[test]
    fn ganache_deterministic_mnemonic() {
        let mnemonic = DETERMINISTIC_MNEMONIC.parse::<Mnemonic>().unwrap();
        let path = "m/44'/60'/0'/0/0".parse::<Path>().unwrap();

        let account = derive(mnemonic.seed(""), &path).unwrap();
        assert_eq!(
            account.address(),
            address!("0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1"),
        );
    }
}
