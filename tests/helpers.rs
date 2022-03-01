extern crate base64;

use base64::*;

#[cfg(not(feature = "avx2"))]
pub fn compare_decode(expected: &str, target: &str) {
    assert_eq!(
        expected,
        String::from_utf8(decode(target).unwrap()).unwrap()
    );
    assert_eq!(
        expected,
        String::from_utf8(decode(target.as_bytes()).unwrap()).unwrap()
    );
}

#[cfg(feature = "avx2")]
pub fn compare_decode(expected: &str, target: &str) {
    let engine = &engine::DEFAULT_ENGINE;
    assert_eq!(
        expected,
        String::from_utf8(decode_engine(target, engine).unwrap()).unwrap()
    );
    assert_eq!(
        expected,
        String::from_utf8(decode_engine(target.as_bytes(), engine).unwrap()).unwrap()
    );

    use base64::engine::avx2::{AVX2Config, AVX2Encoder};
    let engine = AVX2Encoder::from_standard(AVX2Config::new());

    assert_eq!(
        expected,
        String::from_utf8(decode_engine(target, &engine).unwrap()).unwrap()
    );
    assert_eq!(
        expected,
        String::from_utf8(decode_engine(target.as_bytes(), &engine).unwrap()).unwrap()
    );
}
