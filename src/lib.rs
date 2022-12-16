//! # Alphabets
//!
//! An [alphabet::Alphabet] defines what ASCII symbols are used to encode to or decode from.
//!
//! Constants in [alphabet] like [alphabet::STANDARD] or [alphabet::URL_SAFE] provide commonly used
//! alphabets, but you can also build your own custom `Alphabet` if needed.
//!
//! # Engines
//!
//! Once you have an `Alphabet`, you can pick which `Engine` you want. A few parts of the public
//! API provide a default, but otherwise the user must provide an `Engine` to use.
//!
//! See [engine::Engine] for more on what engine to choose, or use [engine::STANDARD] if you
//! just want plain old standard base64 and don't have other requirements. [engine::URL_SAFE] and
//! [engine::URL_SAFE_NO_PAD] are also available.
//!
//! ## Config
//!
//! In addition to an `Alphabet`, constructing an `Engine` also requires an [engine::Config]. Each
//! `Engine` has a corresponding `Config` implementation since different `Engine`s may offer different
//! levels of configurability.
//!
//! [encode()] and [decode()] use the standard alphabet and default engine in an RFC 4648 standard
//! setup.
//!
//! # Encoding
//!
//! Several different encoding methods on [Engine] are available to you depending on your desire for
//! convenience vs performance.
//!
//! | Method           | Output                       | Allocates                      |
//! | ---------------- | ---------------------------- | ------------------------------ |
//! | `encode`         | Returns a new `String`       | Always                         |
//! | `encode_string`  | Appends to provided `String` | Only if `String` needs to grow |
//! | `encode_slice`   | Writes to provided `&[u8]`   | Never - fastest                |
//!
//! All of the encoding methods will pad as per the engine's config.
//!
//! # Decoding
//!
//! Just as for encoding, there are different decoding methods available.
//!
//! | Method           | Output                        | Allocates                      |
//! | ---------------- | ----------------------------- | ------------------------------ |
//! | `decode`         | Returns a new `Vec<u8>`       | Always                         |
//! | `decode_vec`     | Appends to provided `Vec<u8>` | Only if `Vec` needs to grow    |
//! | `decode_slice`   | Writes to provided `&[u8]`    | Never - fastest                |
//!
//! Unlike encoding, where all possible input is valid, decoding can fail (see [DecodeError]).
//!
//! Input can be invalid because it has invalid characters or invalid padding. The nature of how
//! padding is checked depends on the engine's config.
//! Whitespace in the input is invalid, just like any other non-base64 byte.
//!
//! # `Read` and `Write`
//!
//! To decode a [std::io::Read] of b64 bytes, wrap a reader (file, network socket, etc) with
//! [read::DecoderReader].
//!
//! To write raw bytes and have them b64 encoded on the fly, wrap a [std::io::Write] with
//! [write::EncoderWriter].
//!
//! There is some performance overhead (15% or so) because of the necessary buffer shuffling --
//! still fast enough that almost nobody cares. Also, these implementations do not heap allocate.
//!
//! # `Display`
//!
//! See [display] for how to transparently base64 data via a `Display` implementation.
//!
//! # Examples
//!
//! ## Using predefined engines
//!
//! ```
//! use base64::{engine, Engine as _};
//!
//! let orig = b"some data";
//! let encoded: String = engine::STANDARD.encode(orig);
//! assert_eq!(orig.as_slice(), &engine::STANDARD.decode(encoded).unwrap());
//!
//! // or, URL-safe
//! let encoded_url = engine::URL_SAFE_NO_PAD.encode(orig);
//! ```
//!
//! ## Custom alphabet, config, and engine
//!
//! ```
//! use base64::{engine, alphabet, Engine as _};
//!
//! // bizarro-world base64: +/ as the first symbols instead of the last
//! let alphabet =
//!     alphabet::Alphabet::new("+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
//!     .unwrap();
//!
//! // a very weird config that encodes with padding but requires no padding when decoding...?
//! let config = engine::GeneralPurposeConfig::new()
//!     .with_decode_allow_trailing_bits(true)
//!     .with_encode_padding(true)
//!     .with_decode_padding_mode(engine::DecodePaddingMode::RequireNone);
//!
//! let engine = engine::GeneralPurpose::new(&alphabet, config);
//!
//! let encoded = engine.encode(b"abc 123");
//!
//! ```
//!
//! # Panics
//!
//! If length calculations result in overflowing `usize`, a panic will result.
//!
//! The `_slice` flavors of encode or decode will panic if the provided output slice is too small.

#![cfg_attr(feature = "cargo-clippy", allow(clippy::cast_lossless))]
#![deny(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_results,
    variant_size_differences,
    warnings
)]
#![forbid(unsafe_code)]
// Allow globally until https://github.com/rust-lang/rust-clippy/issues/8768 is resolved.
// The desired state is to allow it only for the rstest_reuse import.
#![allow(clippy::single_component_path_imports)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(all(feature = "alloc", not(any(feature = "std", test))))]
extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std as alloc;

// has to be included at top level because of the way rstest_reuse defines its macros
#[cfg(test)]
use rstest_reuse;

mod chunked_encoder;
pub mod display;
#[cfg(any(feature = "std", test))]
pub mod read;
#[cfg(any(feature = "std", test))]
pub mod write;

pub mod engine;
pub use engine::Engine;

pub mod alphabet;

mod encode;
#[allow(deprecated)]
#[cfg(any(feature = "alloc", feature = "std", test))]
pub use crate::encode::{encode, encode_engine, encode_engine_string};
#[allow(deprecated)]
pub use crate::encode::{encode_engine_slice, encoded_len};

mod decode;
#[allow(deprecated)]
#[cfg(any(feature = "alloc", feature = "std", test))]
pub use crate::decode::{decode, decode_engine, decode_engine_vec};
#[allow(deprecated)]
pub use crate::decode::{decode_engine_slice, DecodeError};

#[cfg(test)]
mod tests;

const PAD_BYTE: u8 = b'=';
