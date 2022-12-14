#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate base64;

use base64::engine::{self, general_purpose};

fuzz_target!(|data: &[u8]| {
    let config = general_purpose::GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(engine::DecodePaddingMode::RequireNone);
    let engine = general_purpose::GeneralPurpose::from(&base64::alphabet::STANDARD, config);

    let encoded = base64::encode_engine(data, &engine);
    let decoded = base64::decode_engine(&encoded, &engine).unwrap();
    assert_eq!(data, decoded.as_slice());
});
