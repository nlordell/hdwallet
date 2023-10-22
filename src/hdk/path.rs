//! Module implementing parsing for BIP-0032 HD paths used for key derivation.

use anyhow::{Context as _, Result};
use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

/// A parsed hierarchical derivation path.
#[derive(Debug)]
pub struct Path {
    components: Vec<Component>,
}

impl Path {
    /// Creates the default Ethereum HD path for the specified account index.
    pub fn for_index(index: usize) -> Self {
        format!("m/44'/60'/0'/0/{index}").parse().unwrap()
    }

    /// Returns an iterator over the path components.
    pub fn components(&self) -> impl Iterator<Item = Component> + '_ {
        self.components.iter().copied()
    }
}

impl Display for Path {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str("m")?;
        for component in self.components() {
            write!(f, "/{component}")?;
        }

        Ok(())
    }
}

impl FromStr for Path {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let components = s
            .strip_prefix("m/")
            .context("BIP-0032 path missing main node")?
            .split('/')
            .map(Component::from_str)
            .collect::<Result<_>>()?;

        Ok(Self { components })
    }
}

/// A hierarchical path component.
#[derive(Clone, Copy, Debug)]
pub enum Component {
    /// Component to generate a hardened child key.
    Hardened(u32),
    /// Component to generate a normal child key.
    Normal(u32),
}

impl Display for Component {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Hardened(value) => write!(f, "{value}'"),
            Self::Normal(value) => write!(f, "{value}"),
        }
    }
}

impl FromStr for Component {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let (value, hardened) = match s.strip_suffix('\'') {
            Some(value) => (value, true),
            None => (s, false),
        };

        let value = value
            .parse()
            .with_context(|| format!("invalid BIP-0032 path component '{s}'"))?;

        Ok(if hardened {
            Component::Hardened(value)
        } else {
            Component::Normal(value)
        })
    }
}
