//! Implementations of `io::Write` to transparently handle base64.
mod encoder;
mod encoder_utf8;

pub use self::encoder::EncoderWriter;
pub use self::encoder_utf8::Utf8Compat;

#[cfg(test)]
mod encoder_tests;
