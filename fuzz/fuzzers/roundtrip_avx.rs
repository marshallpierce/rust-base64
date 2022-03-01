#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate base64;

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx2"))]
fuzz_target!(|data: &[u8]| {
    use base64::engine::avx2::{AVX2Encoder, AVX2Config};
    let engine = AVX2Encoder::from_standard(AVX2Config::new());

    let encoded = base64::encode_engine(&data, &engine);
    let decoded = base64::decode_engine(&encoded, &engine).unwrap();
    assert_eq!(data, decoded.as_slice());
});
#[cfg(not(target_feature = "avx2"))]
fuzz_target!(|_data: &[u8]| {
    // When not compiled with avx2 there's absolutely nothing we can do.
});
