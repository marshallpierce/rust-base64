extern crate base64;
extern crate quickcheck;
extern crate rand;

use rand::Rng;

use base64::*;

mod helpers;
use helpers::*;
use quickcheck::{Arbitrary, Gen, QuickCheck, StdThreadGen};

#[derive(Debug, Clone, Copy)]
pub enum ArbitraryConfig {
    Standard(Standard),
    StandardNoPad(StandardNoPad),
    UrlSafe(UrlSafe),
    UrlSafeNoPad(UrlSafeNoPad),
    Crypt(Crypt),
    CryptNoPad(CryptNoPad),
}

impl Arbitrary for ArbitraryConfig {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        use std::default::Default;
        use ArbitraryConfig::*;
        match g.gen_range(0, 6) {
            0 => Standard(Default::default()),
            1 => StandardNoPad(Default::default()),
            2 => UrlSafe(Default::default()),
            3 => UrlSafeNoPad(Default::default()),
            4 => Crypt(Default::default()),
            5 => CryptNoPad(Default::default()),
            _ => unreachable!(),
        }
    }
}

impl ArbitraryConfig {
    fn encode_buf<T: ?Sized + AsRef<[u8]>>(self, input: &T, buf: &mut String) {
        use ArbitraryConfig::*;
        match self {
            Standard(config) => config.encode_buf(input, buf),
            StandardNoPad(config) => config.encode_buf(input, buf),
            UrlSafe(config) => config.encode_buf(input, buf),
            UrlSafeNoPad(config) => config.encode_buf(input, buf),
            Crypt(config) => config.encode_buf(input, buf),
            CryptNoPad(config) => config.encode_buf(input, buf),
        }
    }

    fn encode_slice<T: ?Sized + AsRef<[u8]>>(self, input: &T, output: &mut [u8]) -> usize {
        use ArbitraryConfig::*;
        match self {
            Standard(config) => config.encode_slice(input, output),
            StandardNoPad(config) => config.encode_slice(input, output),
            UrlSafe(config) => config.encode_slice(input, output),
            UrlSafeNoPad(config) => config.encode_slice(input, output),
            Crypt(config) => config.encode_slice(input, output),
            CryptNoPad(config) => config.encode_slice(input, output),
        }
    }

    fn decode<T: ?Sized + AsRef<[u8]>>(self, input: &T) -> Result<Vec<u8>, DecodeError> {
        use ArbitraryConfig::*;
        match self {
            Standard(config) => config.decode(input),
            StandardNoPad(config) => config.decode(input),
            UrlSafe(config) => config.decode(input),
            UrlSafeNoPad(config) => config.decode(input),
            Crypt(config) => config.decode(input),
            CryptNoPad(config) => config.decode(input),
        }
    }

    fn decode_buf<T: ?Sized + AsRef<[u8]>>(
        self,
        input: &T,
        buf: &mut Vec<u8>,
    ) -> Result<(), DecodeError> {
        use ArbitraryConfig::*;
        match self {
            Standard(config) => config.decode_buf(input, buf),
            StandardNoPad(config) => config.decode_buf(input, buf),
            UrlSafe(config) => config.decode_buf(input, buf),
            UrlSafeNoPad(config) => config.decode_buf(input, buf),
            Crypt(config) => config.decode_buf(input, buf),
            CryptNoPad(config) => config.decode_buf(input, buf),
        }
    }

    fn decode_slice<T: ?Sized + AsRef<[u8]>>(
        self,
        input: &T,
        output: &mut [u8],
    ) -> Result<usize, DecodeError> {
        use ArbitraryConfig::*;
        match self {
            Standard(config) => config.decode_slice(input, output),
            StandardNoPad(config) => config.decode_slice(input, output),
            UrlSafe(config) => config.decode_slice(input, output),
            UrlSafeNoPad(config) => config.decode_slice(input, output),
            Crypt(config) => config.decode_slice(input, output),
            CryptNoPad(config) => config.decode_slice(input, output),
        }
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
        let mut encoded = String::new();
        let mut decoded = Vec::new();
        config.encode_buf(&input, &mut encoded);
        config.decode_buf(&encoded, &mut decoded).unwrap();
        assert_eq!(input, decoded);
    }

    fn qc_display_matches_encoded((input, config): (Vec<u8>, ArbitraryConfig)) {
        use ArbitraryConfig::*;
        use base64::display::Base64Display;
        let mut encoded = String::new();
        config.encode_buf(&input, &mut encoded);
        let display = match config {
            Standard(config) => format!("{}", Base64Display::with_config(&input, config)),
            StandardNoPad(config) => format!("{}", Base64Display::with_config(&input, config)),
            UrlSafe(config) => format!("{}", Base64Display::with_config(&input, config)),
            UrlSafeNoPad(config) => format!("{}", Base64Display::with_config(&input, config)),
            Crypt(config) => format!("{}", Base64Display::with_config(&input, config)),
            CryptNoPad(config) => format!("{}", Base64Display::with_config(&input, config)),
        };
        assert_eq!(display, encoded);
    }


    fn qc_encode_slice((input, config): (Vec<u8>, ArbitraryConfig)) {
        let mut encoded = vec![0xff; input.len()*2+2];  // conservative size for output buffer.
        let bytes_written = config.encode_slice(&input, &mut encoded);
        let decoded = config.decode(&encoded[..bytes_written]).unwrap();

        // Verify that decoded up to bytes_written match input.
        assert_eq!(input, decoded);
        // and that no bytes after bytes_written were modified.
        assert!(encoded[bytes_written..].iter().all(|&x| x == 0xff), "bytes beyond bytes_written were modified");
    }

    fn qc_encode_buf((input, config, prefix): (Vec<u8>, ArbitraryConfig, String)) {
        let mut prefixed_encoded = prefix.clone();
        let mut encoded = String::new();
        config.encode_buf(&input, &mut prefixed_encoded);
        config.encode_buf(&input, &mut encoded);
        let decoded = config.decode(&encoded).unwrap();
        assert_eq!(input, decoded);

        // Ensure that the prefix was not modified.
        assert!(prefixed_encoded.starts_with(&prefix));
        // and that everything after the prefix is the same as normal output.
        assert_eq!(prefixed_encoded[prefix.len()..], encoded);
    }

    fn qc_encode_writer_matches_normal_encode((input, config): (Vec<u8>, ArbitraryConfig)) {
        use std::io::Write;
        let mut normal_output = String::new();
        let mut written_output = Vec::new();
        config.encode_buf(&input, &mut normal_output);
        {
            use ArbitraryConfig::*;
            use write::EncoderWriter;
            match config {
                Standard(config) => {
                    let mut writer = EncoderWriter::new(&mut written_output, config);
                    writer.write_all(&input).expect("writing to vec shouldn't fail");
                }
                StandardNoPad(config) => {
                    let mut writer = EncoderWriter::new(&mut written_output, config);
                    writer.write_all(&input).expect("writing to vec shouldn't fail");
                }
                UrlSafe(config) => {
                    let mut writer = EncoderWriter::new(&mut written_output, config);
                    writer.write_all(&input).expect("writing to vec shouldn't fail");
                }
                UrlSafeNoPad(config) => {
                    let mut writer = EncoderWriter::new(&mut written_output, config);
                    writer.write_all(&input).expect("writing to vec shouldn't fail");
                }
                Crypt(config) => {
                    let mut writer = EncoderWriter::new(&mut written_output, config);
                    writer.write_all(&input).expect("writing to vec shouldn't fail");
                }
                CryptNoPad(config) => {
                    let mut writer = EncoderWriter::new(&mut written_output, config);
                    writer.write_all(&input).expect("writing to vec shouldn't fail");
                }
            }
        }
        assert_eq!(normal_output.as_bytes(), written_output.as_slice());
    }

    fn qc_decode_buf((input, config, prefix): (Vec<u8>, ArbitraryConfig, Vec<u8>)) {
        let mut encoded = String::new();
        config.encode_buf(&input, &mut encoded);
        let mut decoded = prefix.clone();
        config.decode_buf(&encoded, &mut decoded).unwrap();

        // Ensure that the prefix was not modified.
        assert_eq!(&decoded[..prefix.len()], prefix.as_slice());
        // and that everything after the prefix matches input.
        assert_eq!(input, &decoded[prefix.len()..]);
    }

    fn qc_decode_into_precisely_sized_slice((input, config): (Vec<u8>, ArbitraryConfig)) {
        let mut encoded = String::new();
        config.encode_buf(&input, &mut encoded);
        let mut decoded = vec![0; input.len()];
        let bytes_written = config.decode_slice(&encoded, &mut decoded).unwrap();
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
