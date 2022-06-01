//! The `k256` crate only supports signing messages by passing message bytes and
//! specifying a hasher, or specifying an already partially updated hasher.
//!
//! This module provides a `Digest` implementation that can be used as an
//! allowing `k256` signing to be done on a prehashed messsage.

use k256::ecdsa::digest::{
    core_api::{
        Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore, UpdateCore,
    },
    HashMarker, Output, OutputSizeUser,
};
use sha3::Keccak256Core;

/// Returns a prehashed message.
pub fn message(message: [u8; 32]) -> Prehashed {
    CoreWrapper::from_core(Core(message))
}

/// A pre-hashed meessage digest shim.
pub type Prehashed = CoreWrapper<Core>;

#[derive(Clone, Default)]
pub struct Core(pub [u8; 32]);

impl BufferKindUser for Core {
    type BufferKind = <Keccak256Core as BufferKindUser>::BufferKind;
}

impl BlockSizeUser for Core {
    type BlockSize = <Keccak256Core as BlockSizeUser>::BlockSize;
}

impl FixedOutputCore for Core {
    fn finalize_fixed_core(&mut self, _: &mut Buffer<Self>, out: &mut Output<Self>) {
        *out = self.0.into()
    }
}

impl HashMarker for Core {}

impl OutputSizeUser for Core {
    type OutputSize = <Keccak256Core as OutputSizeUser>::OutputSize;
}

impl UpdateCore for Core {
    fn update_blocks(&mut self, _: &[Block<Self>]) {
        unimplemented!()
    }
}
