//! The `k256` crate only supports signing messages by passing message bytes and
//! specifying a hasher, or specifying an already partially updated hasher.
//!
//! This module provides a `Digest` implementation that can be used as an
//! allowing `k256` signing to be done on a prehashed messsage.

use k256::ecdsa::digest::{
    consts::U32, generic_array::GenericArray, BlockInput, FixedOutput, Reset, Update,
};
use sha2::{digest::core_api::BlockSizeUser, Digest as _, Sha256};
use std::mem;

/// A pre-hashed meessage.
#[derive(Clone)]
pub enum Prehashed {
    /// The pre-hashed message to use for signing.
    Message([u8; 32]),
    /// The hasher used for rfc-6979 nonce generation for deterministic ECDSA
    /// signature computation.
    Rfc6979(Sha256),
}

impl Default for Prehashed {
    fn default() -> Self {
        Self::Rfc6979(Sha256::default())
    }
}

impl BlockInput for Prehashed {
    type BlockSize = <Sha256 as BlockSizeUser>::BlockSize;
}

impl FixedOutput for Prehashed {
    type OutputSize = U32;

    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        match self {
            Self::Message(message) => *out = message.into(),
            Self::Rfc6979(hasher) => hasher.finalize_into(out),
        }
    }

    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        mem::take(self).finalize_into(out)
    }
}

impl Reset for Prehashed {
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl Update for Prehashed {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        match self {
            Prehashed::Message(_) => unimplemented!(),
            Prehashed::Rfc6979(hasher) => hasher.update(data),
        }
    }
}
