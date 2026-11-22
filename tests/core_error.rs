//! The error types implement `core::error::Error` even without the `std` feature, on toolchains
//! that have it (stable since 1.81). `build.rs` sets `base64_core_error` for those toolchains.
#![cfg(base64_core_error)]

use base64::{alphabet::ParseAlphabetError, DecodeError, DecodeSliceError, EncodeSliceError};

fn assert_error<E: core::error::Error>() {}

#[test]
fn errors_implement_core_error() {
    assert_error::<DecodeError>();
    assert_error::<DecodeSliceError>();
    assert_error::<EncodeSliceError>();
    assert_error::<ParseAlphabetError>();
}
