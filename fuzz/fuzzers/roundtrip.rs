#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate base64;

use base64::{Engine as _, engine::STANDARD};

fuzz_target!(|data: &[u8]| {
    let encoded = STANDARD.encode(data);
    let decoded = STANDARD.decode(&encoded).unwrap();
    assert_eq!(data, decoded.as_slice());
});
