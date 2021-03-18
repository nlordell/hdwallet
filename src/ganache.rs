//! Module containing Ganache deterministic secrets for testing.

use hex_literal::hex;

/// The Ganache deterministic mnemonic.
pub const DETERMINISTIC_MNEMONIC: &str =
    "myth like bonus scare over problem client lizard pioneer submit female collect";

/// The private key of the account at index 0 derived from the Ganache
/// deterministic mnemonic.
pub const DETERMINISTIC_PRIVATE_KEY: [u8; 32] =
    hex!("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d");
