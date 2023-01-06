#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate base64;

use base64::*;

mod utils;

fuzz_target!(|data: &[u8]| {
    let engine = utils::random_engine(data);

    let encoded = engine.encode(data);
    let decoded = engine.decode(&encoded).unwrap();
    assert_eq!(data, decoded.as_slice());
});
