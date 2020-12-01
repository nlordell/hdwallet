//! Module implementing the hierachical deterministic key derivation scheme.

mod path;

pub use self::path::{Component, Path};
use crate::account::PrivateKey;
use anyhow::{Context as _, Result};
use hmac::{Hmac, Mac as _, NewMac as _};
use secp256k1::{
    key::{PublicKey, SecretKey},
    Secp256k1, Signing,
};
use sha2::Sha512;

/// A value indicating a path component is hardened.
const HARDENED: u32 = 0x80000000;

/// Creates a new extended private key from a seed.
pub fn derive(seed: impl AsRef<[u8]>, path: &Path) -> Result<PrivateKey> {
    let mut extended_key = {
        let mut hmac = Hmac::<Sha512>::new_varkey(b"Bitcoin seed")?;
        hmac.update(seed.as_ref());
        hmac.finalize().into_bytes()
    };

    let secp = Secp256k1::signing_only();
    for (i, component) in path.components().enumerate() {
        let (secret, chain_code) = extended_key.split_at(32);

        let mut hmac: Hmac<Sha512> = Hmac::<Sha512>::new_varkey(chain_code)?;
        let value = match component {
            Component::Hardened(value) => {
                hmac.update(&[0]);
                hmac.update(secret);
                value | HARDENED
            }
            Component::Normal(value) => {
                hmac.update(&public_key(&secp, secret)?);
                value
            }
        };
        hmac.update(&value.to_be_bytes());

        let mut child_key = hmac.finalize().into_bytes();
        let child_secret = SecretKey::from_slice(&child_key[..32])
            .and_then(|mut key| {
                key.add_assign(secret)?;
                Ok(key)
            })
            .with_context(|| {
                format!("path '{}' component #{} yields invalid child key", path, i)
            })?;
        child_key[..32].copy_from_slice(child_secret.as_ref());

        extended_key = child_key
    }

    PrivateKey::new(&extended_key[..32])
}

fn public_key<C>(secp: &Secp256k1<C>, secret: &[u8]) -> Result<[u8; 33]>
where
    C: Signing,
{
    let secret_key = SecretKey::from_slice(secret)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    Ok(public_key.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account::Address, mnemonic::Mnemonic};
    use hex_literal::hex;

    #[test]
    fn ganache_deterministic_mnemonic() {
        const GANACHE_DETERMINISTIC_MNEMONIC: &str = "myth like bonus scare over problem \
                                                      client lizard pioneer submit female collect";
        let mnemonic = GANACHE_DETERMINISTIC_MNEMONIC.parse::<Mnemonic>().unwrap();
        let path = "m/44'/60'/0'/0/0".parse::<Path>().unwrap();

        let account = derive(mnemonic.seed(""), &path).unwrap();
        assert_eq!(
            account.address(),
            Address(hex!("90F8bf6A479f320ead074411a4B0e7944Ea8c9C1")),
        );
    }
}
