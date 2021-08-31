//! Module for hashing EIP-712 typed data.

use crate::{
    account::Address,
    hash,
    serialization::{self, JsonObject},
};
use anyhow::{bail, ensure, Context as _, Result};
use ethnum::U256;
use serde::{
    de::{self, Deserializer},
    Deserialize,
};
use serde_json::Value;
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    fmt::{self, Display, Formatter, Write},
};

/// EIP-712 typed data.
pub struct TypedData {
    digest: [u8; 32],
}

impl TypedData {
    /// Returns the EIP-712 digest of the typed data.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

impl<'de> Deserialize<'de> for TypedData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let blob = TypedDataBlob::deserialize(deserializer)?;
        Ok(Self {
            digest: blob.digest().map_err(de::Error::custom)?,
        })
    }
}

#[derive(Deserialize)]
struct TypedDataBlob {
    types: Types,
    #[serde(rename = "primaryType")]
    primary_type: String,
    domain: JsonObject,
    message: JsonObject,
}

impl TypedDataBlob {
    fn digest(self) -> Result<[u8; 32]> {
        self.verify_domain_type()?;

        let TypedDataBlob {
            types,
            primary_type,
            domain,
            message,
        } = self;
        let domain_separator = types.struct_hash("EIP712Domain", domain)?;
        let message_hash = types.struct_hash(&primary_type, message)?;

        let mut buffer = [0; 66];
        buffer[0..2].copy_from_slice(b"\x19\x01");
        buffer[2..34].copy_from_slice(&domain_separator);
        buffer[34..66].copy_from_slice(&message_hash);
        Ok(hash::keccak256(buffer))
    }

    fn verify_domain_type(&self) -> Result<()> {
        const DOMAIN_MEMBERS: [(&str, MemberKind); 5] = [
            ("name", MemberKind::String),
            ("version", MemberKind::String),
            ("chainId", MemberKind::Uint(256)),
            ("verifyingContract", MemberKind::Address),
            ("salt", MemberKind::Bytes(Some(32))),
        ];

        let domain_type = self.types.type_definition("EIP712Domain")?;
        ensure!(
            !domain_type.members.is_empty(),
            "EIP-712 domain must have at least one member"
        );
        domain_type.members.iter().try_fold(
            DOMAIN_MEMBERS.iter(),
            |mut allowed_members, member| {
                let (_, kind) = allowed_members
                    .find(|(name, _)| member.name == *name)
                    .with_context(|| format!("unexpected EIP-712 domain member {}", member.name))?;
                ensure!(
                    &member.kind == kind,
                    "expected EIP-712 domain member {} to be of type {}",
                    member,
                    kind
                );
                Ok(allowed_members)
            },
        )?;

        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(transparent)]
struct Types(HashMap<String, Vec<Member>>);

impl Types {
    fn struct_hash(&self, kind: &str, mut data: JsonObject) -> Result<[u8; 32]> {
        let type_definition = self.type_definition(kind)?;
        let mut buffer = vec![0_u8; 32 * (1 + type_definition.members.len())];
        buffer[0..32].copy_from_slice(&self.type_hash(kind)?);
        for (i, member) in type_definition.members.iter().enumerate() {
            buffer[(i + 1) * 32..][..32].copy_from_slice(
                &self.encode_value(
                    &member.kind,
                    data.remove(&member.name).with_context(|| {
                        format!("{} value missing property {}", kind, member.name)
                    })?,
                )?,
            );
        }

        ensure!(
            data.is_empty(),
            "additional unspecified {} properties: {}",
            kind,
            data.keys().cloned().collect::<Vec<_>>().join(", "),
        );
        Ok(hash::keccak256(&buffer))
    }

    fn encode_type(&self, kind: &str) -> Result<String> {
        let type_definition = self.type_definition(kind)?;
        let mut sub_types = BTreeMap::new();

        let mut unresolved_sub_types = type_definition.struct_references().collect::<Vec<_>>();
        while let Some(sub_type_name) = unresolved_sub_types
            .pop()
            .filter(|name| !sub_types.contains_key(name))
        {
            let sub_type = self.type_definition(sub_type_name)?;
            unresolved_sub_types.extend(sub_type.struct_references());
            sub_types.insert(sub_type_name, sub_type);
        }

        let mut buffer = type_definition.to_string();
        for sub_type in sub_types.values() {
            write!(buffer, "{}", sub_type)?;
        }

        Ok(buffer)
    }

    fn type_hash(&self, kind: &str) -> Result<[u8; 32]> {
        let encoded_type = self.encode_type(kind)?;
        Ok(hash::keccak256(&encoded_type))
    }

    fn type_definition<'a>(&'a self, kind: &'a str) -> Result<TypeDefinition<'a>> {
        let members = self
            .0
            .get(kind)
            .with_context(|| format!("missing EIP-712 type definition for {}", kind))?;

        Ok(TypeDefinition { kind, members })
    }

    fn encode_value(&self, kind: &MemberKind, value: Value) -> Result<[u8; 32]> {
        Ok(match kind {
            MemberKind::Bytes(n) => {
                let bytes = serialization::bytes::deserialize(value)?;
                match n {
                    Some(n) => {
                        let mut buffer = [0_u8; 32];
                        buffer
                            .get_mut(..(*n as usize))
                            .with_context(|| format!("invalid byte array length {}", n))?
                            .copy_from_slice(&bytes);
                        buffer
                    }
                    None => hash::keccak256(&bytes),
                }
            }
            MemberKind::Uint(n) => {
                // TODO(nlordell): Actual signed integer support.
                let value = serialization::u256::deserialize(value)?;
                ensure!(
                    value.leading_zeros() + n >= 256,
                    "value {:#x} overflows uint{}",
                    value,
                    n,
                );
                value.to_be_bytes()
            }
            MemberKind::Bool => match bool::deserialize(value)? {
                true => U256::ONE,
                false => U256::ZERO,
            }
            .to_be_bytes(),
            MemberKind::Address => {
                let address = Address::deserialize(value)?;
                let mut buffer = [0_u8; 32];
                buffer[12..].copy_from_slice(&*address);
                buffer
            }
            MemberKind::String => hash::keccak256(&*Cow::<str>::deserialize(value)?),
            MemberKind::Struct(inner) => {
                let value = match value {
                    Value::Object(value) => value,
                    value => bail!("expected JSON object but got '{}'", value),
                };
                self.struct_hash(inner, value)?
            }
            _ => {
                todo!()
            }
        })
    }
}

struct TypeDefinition<'a> {
    kind: &'a str,
    members: &'a [Member],
}

impl<'a> TypeDefinition<'a> {
    fn struct_references(&self) -> impl Iterator<Item = &'a str> + 'a {
        self.members
            .iter()
            .filter_map(|member| member.kind.struct_reference())
    }
}

impl Display for TypeDefinition<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.kind)?;
        if let Some(first_member) = self.members.get(0) {
            write!(f, "{}", first_member)?;
        }
        for member in self.members.get(1..).into_iter().flatten() {
            write!(f, ",{}", member)?;
        }
        write!(f, ")")
    }
}

#[derive(Deserialize)]
struct Member {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: MemberKind,
}

impl Display for Member {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.kind, self.name)
    }
}

#[derive(Debug, PartialEq)]
enum MemberKind {
    Bytes(Option<u32>),
    Uint(u32),
    Int(u32),
    Bool,
    Address,
    String,
    Struct(String),
    Array(Box<MemberKind>, Option<usize>),
}

impl MemberKind {
    fn from_str(value: &str) -> Self {
        match value {
            "bool" => return MemberKind::Bool,
            "address" => return MemberKind::Address,
            "bytes" => return MemberKind::Bytes(None),
            "string" => return MemberKind::String,
            _ => {}
        }

        if let Some((prefix, n)) = value.find(char::is_numeric).and_then(|i| {
            let (prefix, n) = value.split_at(i);
            Some((prefix, n.parse::<u32>().ok()?))
        }) {
            match (prefix, n) {
                ("bytes", n) if (1..=32).contains(&n) => return MemberKind::Bytes(Some(n as _)),
                ("uint", n) if n % 8 == 0 && (8..=256).contains(&n) => return MemberKind::Uint(n),
                ("int", n) if n % 8 == 0 && (8..=256).contains(&n) => return MemberKind::Int(n),
                _ => {}
            }
        }

        if let Some(prefix) = value.strip_suffix("[]") {
            return MemberKind::Array(Box::new(MemberKind::from_str(prefix)), None);
        }
        if let Some((prefix, n)) = value.strip_suffix(']').and_then(|value| {
            let (prefix, n) = value.rsplit_once('[')?;
            Some((prefix, n.parse::<usize>().ok()?))
        }) {
            return MemberKind::Array(Box::new(MemberKind::from_str(prefix)), Some(n));
        }

        MemberKind::Struct(value.to_string())
    }

    fn struct_reference(&self) -> Option<&str> {
        match self {
            MemberKind::Struct(name) => Some(name),
            MemberKind::Array(inner, _) => inner.struct_reference(),
            _ => None,
        }
    }
}

impl Display for MemberKind {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            MemberKind::Bytes(None) => f.write_str("bytes"),
            MemberKind::Bytes(Some(n)) => write!(f, "bytes{}", n),
            MemberKind::Uint(n) => write!(f, "uint{}", n),
            MemberKind::Int(n) => write!(f, "int{}", n),
            MemberKind::Bool => f.write_str("bool"),
            MemberKind::Address => f.write_str("address"),
            MemberKind::String => f.write_str("string"),
            MemberKind::Struct(kind) => f.write_str(kind),
            MemberKind::Array(kind, None) => write!(f, "{}[]", kind),
            MemberKind::Array(kind, Some(n)) => write!(f, "{}[{}]", kind, n),
        }
    }
}

impl<'de> Deserialize<'de> for MemberKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Cow::<str>::deserialize(deserializer)?;
        Ok(MemberKind::from_str(&*value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use maplit::hashmap;

    #[test]
    fn typed_data_digest() {
        let typed_data = serde_json::from_str::<TypedData>(
            r#"{
                "types": {
                    "EIP712Domain": [
                        { "name": "name", "type": "string" },
                        { "name": "version", "type": "string" },
                        { "name": "chainId", "type": "uint256" },
                        { "name": "verifyingContract", "type": "address" }
                    ],
                    "Person": [
                        { "name": "name", "type": "string" },
                        { "name": "wallet", "type": "address" }
                    ],
                    "Mail": [
                        { "name": "from", "type": "Person" },
                        { "name": "to", "type": "Person" },
                        { "name": "contents", "type": "string" }
                    ]
                },
                "primaryType": "Mail",
                "domain": {
                    "name": "Ether Mail",
                    "version": "1",
                    "chainId": 1,
                    "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
                },
                "message": {
                    "from": {
                        "name": "Cow",
                        "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
                    },
                    "to": {
                        "name": "Bob",
                        "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                    },
                    "contents": "Hello, Bob!"
                }
            }"#,
        )
        .unwrap();
        assert_eq!(
            typed_data.digest(),
            hex!("be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"),
        );
    }

    #[test]
    fn encode_types() {
        let types = Types(hashmap! {
            "Transaction".to_string() => vec![
                Member {
                    name: "from".to_string(),
                    kind: MemberKind::Struct("Person".to_string()),
                },
                Member {
                    name: "to".to_string(),
                    kind: MemberKind::Struct("Person".to_string()),
                },
                Member {
                    name: "tx".to_string(),
                    kind: MemberKind::Struct("Asset".to_string()),
                },
            ],
            "Person".to_string() => vec![
                Member {
                    name: "wallet".to_string(),
                    kind: MemberKind::Address,
                },
                Member {
                    name: "name".to_string(),
                    kind: MemberKind::String,
                },
            ],
            "Asset".to_string() => vec![
                Member {
                    name: "token".to_string(),
                    kind: MemberKind::Address,
                },
                Member {
                    name: "amount".to_string(),
                    kind: MemberKind::Uint(256),
                },
            ],
        });
        assert_eq!(
            types.encode_type("Transaction").unwrap(),
            "Transaction(Person from,Person to,Asset tx)Asset(address token,uint256 amount)Person(address wallet,string name)",
        );

        let types = Types(hashmap! {
            "Foo".to_string() => vec![
                Member {
                    name: "bar".to_string(),
                    kind: MemberKind::Array(
                        Box::new(MemberKind::Array(
                            Box::new(MemberKind::Struct("Bar".to_string())),
                            None,
                        )),
                        Some(1),
                    ),
                },
            ],
            "Bar".to_string() => vec![
                Member {
                    name: "baz".to_string(),
                    kind: MemberKind::Array(
                        Box::new(MemberKind::Array(
                            Box::new(MemberKind::Struct("Baz".to_string())),
                            Some(1),
                        )),
                        None,
                    ),
                },
            ],
            "Baz".to_string() => vec![],
        });
        assert_eq!(
            types.encode_type("Foo").unwrap(),
            "Foo(Bar[][1] bar)Bar(Baz[1][] baz)Baz()",
        );
    }

    #[test]
    fn member_kind_from_and_to_str() {
        for (name, kind) in [
            ("bool", MemberKind::Bool),
            ("address", MemberKind::Address),
            ("bytes", MemberKind::Bytes(None)),
            ("string", MemberKind::String),
            ("bytes12", MemberKind::Bytes(Some(12))),
            ("uint96", MemberKind::Uint(96)),
            ("int256", MemberKind::Int(256)),
            ("bytes0", MemberKind::Struct("bytes0".to_string())),
            ("uint9", MemberKind::Struct("uint9".to_string())),
            ("uint320", MemberKind::Struct("uint320".to_string())),
            ("int42", MemberKind::Struct("int42".to_string())),
            ("int0", MemberKind::Struct("int0".to_string())),
            (
                "uint256[]",
                MemberKind::Array(Box::new(MemberKind::Uint(256)), None),
            ),
            (
                "bool[][3]",
                MemberKind::Array(
                    Box::new(MemberKind::Array(Box::new(MemberKind::Bool), None)),
                    Some(3),
                ),
            ),
            ("uint256]", MemberKind::Struct("uint256]".to_string())),
            ("uin[t256]", MemberKind::Struct("uin[t256]".to_string())),
        ] {
            let parsed = MemberKind::from_str(name);
            assert_eq!(parsed, kind);
            assert_eq!(parsed.to_string(), name);
        }
    }

    #[test]
    fn type_definition_display() {
        for (type_definition, formatted) in [
            (
                TypeDefinition {
                    kind: "Empty",
                    members: &[],
                },
                "Empty()",
            ),
            (
                TypeDefinition {
                    kind: "Foo",
                    members: &[Member {
                        name: "foo".to_string(),
                        kind: MemberKind::Address,
                    }],
                },
                "Foo(address foo)",
            ),
            (
                TypeDefinition {
                    kind: "FooBar",
                    members: &[
                        Member {
                            name: "foo".to_string(),
                            kind: MemberKind::Address,
                        },
                        Member {
                            name: "bar".to_string(),
                            kind: MemberKind::Array(Box::new(MemberKind::Uint(256)), None),
                        },
                    ],
                },
                "FooBar(address foo,uint256[] bar)",
            ),
        ] {
            assert_eq!(type_definition.to_string(), formatted);
        }
    }
}
