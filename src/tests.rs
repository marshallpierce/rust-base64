extern crate quickcheck;
extern crate rand;

use encode::encoded_size;
use *;

use std::str;

use self::quickcheck::{Arbitrary, Gen, QuickCheck, StdThreadGen};
use self::rand::Rng;

fn roundtrip_property((input, config): (Vec<u8>, Configs)) {
    let mut encoded = String::new();
    encode_config_buf(&input, config, &mut encoded);
    let decoded = decode_config(&encoded, config).expect("decoding failed");
    assert_eq!(input, decoded);
    assert_eq!(
        encoded.len(),
        encoded_size(input.len(), config).expect("failed to get encoded_size")
    );

    let input_rem = input.len() % 3;
    let (not_padding, padding) = if config.has_padding() && input_rem > 0 {
        let padding_start = encoded.len() - (3 - input_rem);
        (&encoded[..padding_start], &encoded[padding_start..])
    } else {
        (encoded.as_str(), "")
    };

    assert!(padding.bytes().all(|c| c == config.padding_byte().unwrap()));
    assert!(not_padding
        .bytes()
        .all(|c| config.decode_u8(c) != ::tables::INVALID_VALUE));
    let _ = str::from_utf8(encoded.as_bytes()).expect("Base64 should be valid utf8");
}

#[test]
fn roundtrip_short() {
    // exercise the slower encode/decode routines that operate on shorter buffers more vigorously
    let property: fn((Vec<u8>, Configs)) = roundtrip_property;
    QuickCheck::with_gen(StdThreadGen::new(50))
        .tests(1000)
        .quickcheck(property);
}

#[test]
fn roundtrip_long() {
    let property: fn((Vec<u8>, Configs)) = roundtrip_property;
    QuickCheck::with_gen(StdThreadGen::new(1024))
        .tests(1000)
        .quickcheck(property);
}

#[derive(Debug, Clone, Copy)]
pub enum Configs {
    Standard(Standard),
    StandardNoPad(StandardNoPad),
    UrlSafe(UrlSafe),
    UrlSafeNoPad(UrlSafeNoPad),
    Crypt(Crypt),
    CryptNoPad(CryptNoPad),
}

impl Padding for Configs {
    fn padding_byte(self) -> Option<u8> {
        use self::Configs::*;
        match self {
            Standard(x) => x.padding_byte(),
            StandardNoPad(x) => x.padding_byte(),
            UrlSafe(x) => x.padding_byte(),
            UrlSafeNoPad(x) => x.padding_byte(),
            Crypt(x) => x.padding_byte(),
            CryptNoPad(x) => x.padding_byte(),
        }
    }
}

impl Encoding for Configs {
    fn encode_u6(self, input: u8) -> u8 {
        use self::Configs::*;
        match self {
            Standard(x) => x.encode_u6(input),
            StandardNoPad(x) => x.encode_u6(input),
            UrlSafe(x) => x.encode_u6(input),
            UrlSafeNoPad(x) => x.encode_u6(input),
            Crypt(x) => x.encode_u6(input),
            CryptNoPad(x) => x.encode_u6(input),
        }
    }
}

impl Decoding for Configs {
    fn decode_u8(self, input: u8) -> u8 {
        use self::Configs::*;
        match self {
            Standard(x) => x.decode_u8(input),
            StandardNoPad(x) => x.decode_u8(input),
            UrlSafe(x) => x.decode_u8(input),
            UrlSafeNoPad(x) => x.decode_u8(input),
            Crypt(x) => x.decode_u8(input),
            CryptNoPad(x) => x.decode_u8(input),
        }
    }
}

impl ::private::Sealed for Configs {}

impl Arbitrary for Configs {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        use self::Configs::*;
        use std::default::Default;
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
