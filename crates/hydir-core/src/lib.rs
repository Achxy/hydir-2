//! Frontend-neutral facts recovered from a binary. Unknown recovery is never
//! represented as a negative fact.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const SPEC_VERSION: u32 = 1;

/// JSON addresses are strings so no consumer can round a 64-bit address via f64.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Address(pub u64);

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{:016x}", self.0))
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let digits = value
            .strip_prefix("0x")
            .ok_or_else(|| serde::de::Error::custom("address must start with 0x"))?;
        u64::from_str_radix(digits, 16)
            .map(Address)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgramSpec {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub target_triple: String,
    pub abi: String,
    pub file_kind: String,
    pub image_base: Option<Address>,
    pub data_layout: Option<String>,
    /// Sections are file-derived. They are not a reconstructed runtime image.
    pub sections: Vec<SectionSpec>,
    pub functions: Vec<FunctionSpec>,
    pub recovery_scope: String,
    pub unresolved_control_flow: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionSpec {
    pub name: String,
    pub address: Address,
    pub address_kind: AddressKind,
    pub file_offset: Option<Address>,
    pub size: u64,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionSpec {
    pub id: String,
    pub name: String,
    pub address: Address,
    pub address_kind: AddressKind,
    pub section_name: String,
    pub size: u64,
    pub provenance: String,
    pub control_flow_status: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressKind {
    Virtual,
    SectionRelative,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_is_hex_string_not_json_number() {
        let original = Address(0xffff_ffff_ffff_fffe);
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"0xfffffffffffffffe\"");
        let recovered: Address = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, original);
    }
}
