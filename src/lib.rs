//! Ethereum hierarchically deterministic wallet.
//!
//! This crate implements generating and parsing BIP-0039 mnemonic phrases, as
//! well as BIP-0032 private key derivation, and various utilities for using
//! these derived keys for signing various messages relative to Ethereum.

pub mod account;
pub mod hash;
pub mod hdk;
pub mod mnemonic;
mod rand;
mod serialization;
pub mod transaction;
pub mod typeddata;

#[cfg(test)]
mod ganache;
