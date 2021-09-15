#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate base64;

use base64::engine::avx2::{AVX2Encoder, AVX2Config};
fuzz_target!(|data: &[u8]| {
    let engine = AVX2Encoder::from_standard(AVX2Config::new());

    let encoded = base64::encode_engine(&data, &engine);
    let decoded = base64::decode_engine(&encoded, &engine).unwrap();
    assert_eq!(data, decoded.as_slice());
});