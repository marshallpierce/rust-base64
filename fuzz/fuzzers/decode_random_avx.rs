#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate base64;

use base64::decode_engine;
use base64::engine::avx2::{AVX2Encoder, AVX2Config};

fuzz_target!(|data: &[u8]| {
    let engine = AVX2Encoder::from_standard(AVX2Config::new());

    // The data probably isn't valid base64 input, but as long as it returns an error instead
    // of crashing, that's correct behavior.
    let _ = decode_engine(&data, &engine);
});
