#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate base64;

use base64::engine::{self, fast_portable};

fuzz_target!(|data: &[u8]| {
    let config = fast_portable::FastPortableConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(engine::DecodePaddingMode::RequireNone);
    let engine = fast_portable::FastPortable::from(&base64::alphabet::STANDARD, config);

    let encoded = base64::encode_engine(data, &engine);
    let decoded = base64::decode_engine(&encoded, &engine).unwrap();
    assert_eq!(data, decoded.as_slice());
});
