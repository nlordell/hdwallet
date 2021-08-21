#[path = "../../src/ganache.rs"]
mod ganache;

use std::{str, process::Command};
pub use ganache::*;

/// Utility function for running the `hdwallet` command for integration tests.
pub fn exec(subcommand: &str, args: &[&str]) -> String {
    try_exec(subcommand, args).unwrap()
}

/// Try and execute a command, returning an error if there was one.
pub fn try_exec(subcommand: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new("cargo")
        .env("MNEMONIC", ganache::DETERMINISTIC_MNEMONIC)
        .args(["run", "--", subcommand])
        .args(args)
        .output()
        .unwrap();
    if output.status.success() {
        Ok(string_from_utf8(output.stdout))
    } else {
        Err(string_from_utf8(output.stderr))
    }
}

fn string_from_utf8(bytes: Vec<u8>) -> String {
    str::from_utf8(&bytes).unwrap().trim().to_string()
}