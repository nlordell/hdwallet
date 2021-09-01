#![allow(dead_code)]

#[path = "../../src/ganache.rs"]
mod ganache;

pub use ganache::*;
use std::{
    io::Write as _,
    process::{Command, Stdio},
    str, thread,
};

/// Utility type for building an `hdwallet` command for integration tests.
pub struct Hdwallet {
    command: Command,
    stdin: Option<Vec<u8>>,
}

impl Hdwallet {
    /// Create a new `hdwallet` command builder.
    pub fn new(subcommand: &str, args: &[&str]) -> Self {
        let mut command = Command::new("cargo");
        command
            .env("MNEMONIC", ganache::DETERMINISTIC_MNEMONIC)
            .args(["run", "--", subcommand])
            .args(args);
        Self {
            command,
            stdin: None,
        }
    }

    /// Sets the standard input to be used for the command.
    pub fn stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    /// Executes the command and returns the standard output on success and
    /// standard error on failure.
    pub fn execute(mut self) -> Result<String, String> {
        self.command.stdout(Stdio::piped()).stderr(Stdio::piped());
        if self.stdin.is_some() {
            self.command.stdin(Stdio::piped());
        }

        let mut process = self.command.spawn().unwrap();

        let input = self.stdin.map(|data| {
            let mut stdin = process.stdin.take().unwrap();
            thread::spawn(move || {
                stdin.write_all(&data).unwrap();
            })
        });

        let output = process.wait_with_output().unwrap();
        if let Some(input) = input {
            input.join().unwrap();
        }

        if output.status.success() {
            Ok(string_from_utf8(output.stdout))
        } else {
            Err(string_from_utf8(output.stderr))
        }
    }

    /// Builds and executes an `hdwallet` command.
    pub fn run(subcommand: &str, args: &[&str]) -> String {
        Hdwallet::new(subcommand, args).execute().unwrap()
    }
}

fn string_from_utf8(bytes: Vec<u8>) -> String {
    str::from_utf8(&bytes).unwrap().trim().to_string()
}
