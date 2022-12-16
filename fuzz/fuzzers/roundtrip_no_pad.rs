#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate base64;

use base64::{Engine as _, engine::{self, general_purpose}};

fuzz_target!(|data: &[u8]| {
    let config = general_purpose::GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(engine::DecodePaddingMode::RequireNone);
    let engine = general_purpose::GeneralPurpose::new(&base64::alphabet::STANDARD, config);

    let encoded = engine.encode(data);
    let decoded = engine.decode(&encoded).unwrap();
    assert_eq!(data, decoded.as_slice());
});
