extern crate serde;

use super::{Config, STANDARD};
use self::serde::{Deserialize, Deserializer, de, Serializer};

struct ConfigAsField {
    config: Config
}

impl ConfigAsField {
    pub fn serialize<S>(&self, bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
        serializer.serialize_str(&super::encode_config(bytes, self.config))
    }

    pub fn deserialize<'de, D>(&self, deserializer: D) -> Result<Vec<u8>, D::Error>
        where D: Deserializer<'de> {
        let s = <&str>::deserialize(deserializer)?;
        super::decode_config(s, self.config).map_err(de::Error::custom)
    }
}

struct ConfigPerType {}

impl ConfigPerType {
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
        serializer.serialize_str(&super::encode_config(bytes, super::STANDARD))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
        where D: Deserializer<'de> {
        let s = <&str>::deserialize(deserializer)?;
        super::decode_config(s, super::STANDARD).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    extern crate serde_json;

    use super::serde::{Deserialize, Serialize};
    use super::*;
    use super::super::*;

    const B64: ConfigAsField = ConfigAsField { config: STANDARD };

    #[derive(Serialize, Deserialize)]
    struct ByteHolder {
        #[serde(with = "super::ConfigPerType")]
        bytes: Vec<u8>,
    }

    #[derive(Serialize, Deserialize)]
    struct FlexiByteHolder {
        #[serde(with = "B64")]
        bytes: Vec<u8>,
    }

    #[test]
    fn serde_with_type() {
        let b = ByteHolder { bytes: vec![0x00, 0x77, 0xFF] };

        let s = serde_json::to_string(&b).unwrap();
        let expected = format!("{{\"bytes\":\"{}\"}}", encode_config(&b.bytes, STANDARD));
        assert_eq!(expected, s);
    }

    #[test]
    fn serde_with_const() {
        let b = FlexiByteHolder { bytes: vec![0x00, 0x77, 0xFF] };

        let s = serde_json::to_string(&b).unwrap();
        let expected = format!("{{\"bytes\":\"{}\"}}", encode_config(&b.bytes, STANDARD));
        assert_eq!(expected, s);
    }

}
