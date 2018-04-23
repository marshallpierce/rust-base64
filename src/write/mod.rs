//! Implementations of `io::Write` to transparently handle base64 encoding.
mod encoder;
pub use self::encoder::Base64Encoder;