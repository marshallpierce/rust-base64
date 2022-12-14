#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate base64;

use base64::{Engine as _, engine::DEFAULT_ENGINE};

fuzz_target!(|data: &[u8]| {
    let encoded = DEFAULT_ENGINE.encode(data);
    let decoded = base64::decode_engine(&encoded, &DEFAULT_ENGINE).unwrap();
    assert_eq!(data, decoded.as_slice());
});
