extern crate base64;
extern crate quickcheck;
extern crate rand;

use rand::Rng;

use base64::*;

mod helpers;
use helpers::*;
use quickcheck::{Arbitrary, Gen, QuickCheck, StdThreadGen};

#[derive(Debug, Clone, Copy)]
struct ArbitraryConfig(Config);

impl From<ArbitraryConfig> for Config {
    fn from(ac: ArbitraryConfig) -> Config {
        ac.0
    }
}

impl Arbitrary for ArbitraryConfig {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        const CHARSETS: &[CharacterSet] = &[
            CharacterSet::UrlSafe,
            CharacterSet::Standard,
            CharacterSet::Crypt,
        ];
        let charset = *g.choose(CHARSETS).unwrap();

        ArbitraryConfig(Config::new(charset, g.gen()))
    }
}

// similar to the quicktest! macro except that it uses a generator that goes
// up to 1024 (default is 100) and runs 1000 tests (default is 100).
macro_rules! qc_test {
    (@as_items $($i:item)*) => ($($i)*);
    {
        $(
            fn $fn_name:ident($($arg_name:tt : $arg_ty:ty),*) {
                $($code:tt)*
            }
        )*
    } => (
        qc_test! {
            @as_items
            $(
                #[test]
                fn $fn_name() {
                    fn prop($($arg_name: $arg_ty),*) {
                        $($code)*
                    }
                    QuickCheck::with_gen(StdThreadGen::new(1024))
                        .tests(1000)
                        .quickcheck(prop as fn($($arg_ty),*));
                }
            )*
        }
    )
}

qc_test! {
    fn qc_roundtrip((input, config): (Vec<u8>, ArbitraryConfig)) {
        let config = config.into();
        let mut encoded = String::new();
        let mut decoded = Vec::new();
        encode_config_buf(&input, config, &mut encoded);
        decode_config_buf(&encoded, config, &mut decoded).unwrap();
        assert_eq!(input, decoded);
    }

    fn qc_display_matches_encoded((input, config): (Vec<u8>, ArbitraryConfig)) {
        let config = config.into();
        let mut encoded = String::new();
        encode_config_buf(&input, config, &mut encoded);
        let display = format!(
            "{}",
            base64::display::Base64Display::with_config(&input, config)
        );
        assert_eq!(display, encoded);
    }

    fn qc_encode_slice((input, config): (Vec<u8>, ArbitraryConfig)) {
        let config = config.into();
        let mut encoded = vec![0xff; input.len()*2+2];  // conservative size for output buffer.
        let bytes_written = encode_config_slice(&input, config, &mut encoded);
        let decoded = decode_config(&encoded[..bytes_written], config).unwrap();

        // Verify that decoded up to bytes_written match input.
        assert_eq!(input, decoded);
        // and that no bytes after bytes_written were modified.
        assert!(encoded[bytes_written..].iter().all(|&x| x == 0xff), "bytes beyond bytes_written were modified");
    }

    fn qc_encode_buf((input, config, prefix): (Vec<u8>, ArbitraryConfig, String)) {
        let config = config.into();
        let mut prefixed_encoded = prefix.clone();
        let mut encoded = String::new();
        encode_config_buf(&input, config, &mut prefixed_encoded);
        encode_config_buf(&input, config, &mut encoded);
        let decoded = decode_config(&encoded, config).unwrap();
        assert_eq!(input, decoded);

        // Ensure that the prefix was not modified.
        assert!(prefixed_encoded.starts_with(&prefix));
        // and that everything after the prefix is the same as normal output.
        assert_eq!(prefixed_encoded[prefix.len()..], encoded);
    }

    fn qc_encode_writer_matches_normal_encode((input, config): (Vec<u8>, ArbitraryConfig)) {
        use std::io::Write;
        let config = config.into();
        let mut normal_output = String::new();
        let mut written_output = Vec::new();
        encode_config_buf(&input, config, &mut normal_output);
        {
            let mut writer = write::EncoderWriter::new(&mut written_output, config);
            writer.write_all(&input).expect("writing to vec shouldn't fail");
        }
        assert_eq!(normal_output.as_bytes(), written_output.as_slice());
    }

    fn qc_decode_buf((input, config, prefix): (Vec<u8>, ArbitraryConfig, Vec<u8>)) {
        let config = config.into();
        let mut encoded = String::new();
        encode_config_buf(&input, config, &mut encoded);
        let mut decoded = prefix.clone();
        decode_config_buf(&encoded, config, &mut decoded).unwrap();

        // Ensure that the prefix was not modified.
        assert_eq!(&decoded[..prefix.len()], prefix.as_slice());
        // and that everything after the prefix matches input.
        assert_eq!(input, &decoded[prefix.len()..]);
    }

    fn qc_decode_into_precisely_sized_slice((input, config): (Vec<u8>, ArbitraryConfig)) {
        let config = config.into();
        let mut encoded = String::new();
        encode_config_buf(&input, config, &mut encoded);
        let mut decoded = vec![0; input.len()];
        let bytes_written = decode_config_slice(&encoded, config, &mut decoded).unwrap();
        assert_eq!(bytes_written, input.len());
        assert_eq!(input, decoded);
    }
}

#[test]
fn because_we_can() {
    compare_decode("alice", "YWxpY2U=");
    compare_decode("alice", &encode(b"alice"));
    compare_decode("alice", &encode(&decode(&encode(b"alice")).unwrap()));
}
