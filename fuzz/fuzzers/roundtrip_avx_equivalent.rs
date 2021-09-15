#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate base64;

use base64::engine::DEFAULT_ENGINE;

use base64::engine::avx2::{AVX2Encoder, AVX2Config};
fuzz_target!(|data: &[u8]| {
    let avx_engine = AVX2Encoder::from_standard(AVX2Config::new());

    let avx_encoded = base64::encode_engine(&data, &avx_engine);
    let def_decoded = base64::decode_engine(&avx_encoded, &DEFAULT_ENGINE).unwrap();
    let def_encoded = base64::encode_engine(&data, &DEFAULT_ENGINE);
    let avx_decoded = base64::decode_engine(&def_encoded, &avx_engine).unwrap();

    assert_eq!(data, def_decoded.as_slice());
    assert_eq!(data, avx_decoded.as_slice());
});