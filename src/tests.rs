extern crate quickcheck;
extern crate rand;

use encode::encoded_size;
use *;

use std::str;

use self::quickcheck::{Arbitrary, Gen, QuickCheck, StdThreadGen};
use self::rand::Rng;

impl Arbitrary for Config {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        const CHARSETS: &[CharacterSet] = &[
            CharacterSet::UrlSafe,
            CharacterSet::Standard,
            CharacterSet::Crypt,
        ];
        let charset = *g.choose(CHARSETS).unwrap();

        Config::new(charset, g.gen())
    }
}

fn roundtrip_property((input, config): (Vec<u8>, Config)) {
    let mut encoded = String::new();
    encode_config_buf(&input, config, &mut encoded);
    let decoded = decode_config(&encoded, config).expect("decoding failed");
    assert_eq!(input, decoded);
    assert_eq!(
        encoded.len(),
        encoded_size(input.len(), config).expect("failed to get encoded_size")
    );

    let input_rem = input.len() % 3;
    let (not_padding, padding) = if config.pad && input_rem > 0 {
        let padding_start = encoded.len() - (3 - input_rem);
        (&encoded[..padding_start], &encoded[padding_start..])
    } else {
        (encoded.as_str(), "")
    };
    assert!(padding.bytes().all(|c| c == b'='));
    let decode_table = config.char_set.decode_table();
    assert!(
        not_padding
            .bytes()
            .all(|c| decode_table[c as usize] != tables::INVALID_VALUE)
    );
    let _ = str::from_utf8(encoded.as_bytes()).expect("Base64 should be valid utf8");
}

#[test]
fn roundtrip_short() {
    // exercise the slower encode/decode routines that operate on shorter buffers more vigorously
    let property: fn((Vec<u8>, Config)) = roundtrip_property;
    QuickCheck::with_gen(StdThreadGen::new(50))
        .tests(1000)
        .quickcheck(property);
}

#[test]
fn roundtrip_long() {
    let property: fn((Vec<u8>, Config)) = roundtrip_property;
    QuickCheck::with_gen(StdThreadGen::new(1024))
        .tests(1000)
        .quickcheck(property);
}
