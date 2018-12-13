//! # Configs
//!
//! There isn't just one type of Base64; that would be too simple. You need to choose a character
//! set (standard, URL-safe, etc) and padding suffix (yes/no).
//! The `Config` struct encapsulates this info. There are some common configs included: `STANDARD`,
//! `URL_SAFE`, etc. You can also make your own `Config` if needed.
//!
//! The functions that don't have `config` in the name (e.g. `encode()` and `decode()`) use the
//! `STANDARD` config .
//!
//! The functions that write to a slice (the ones that end in `_slice`) are generally the fastest
//! because they don't need to resize anything. If it fits in your workflow and you care about
//! performance, keep using the same buffer (growing as need be) and use the `_slice` methods for
//! the best performance.
//!
//! # Encoding
//!
//! Several different encoding functions are available to you depending on your desire for
//! convenience vs performance.
//!
//! | Function                | Output                       | Allocates                      |
//! | ----------------------- | ---------------------------- | ------------------------------ |
//! | `encode`                | Returns a new `String`       | Always                         |
//! | `encode_config`         | Returns a new `String`       | Always                         |
//! | `encode_config_buf`     | Appends to provided `String` | Only if `String` needs to grow |
//! | `encode_config_slice`   | Writes to provided `&[u8]`   | Never                          |
//!
//! All of the encoding functions that take a `Config` will pad as per the config.
//!
//! # Decoding
//!
//! Just as for encoding, there are different decoding functions available.
//!
//! | Function                | Output                        | Allocates                      |
//! | ----------------------- | ----------------------------- | ------------------------------ |
//! | `decode`                | Returns a new `Vec<u8>`       | Always                         |
//! | `decode_config`         | Returns a new `Vec<u8>`       | Always                         |
//! | `decode_config_buf`     | Appends to provided `Vec<u8>` | Only if `Vec` needs to grow    |
//! | `decode_config_slice`   | Writes to provided `&[u8]`    | Never                          |
//!
//! Unlike encoding, where all possible input is valid, decoding can fail (see `DecodeError`).
//!
//! Input can be invalid because it has invalid characters or invalid padding. (No padding at all is
//! valid, but excess padding is not.) Whitespace in the input is invalid.
//!
//! # Panics
//!
//! If length calculations result in overflowing `usize`, a panic will result.
//!
//! The `_slice` flavors of encode or decode will panic if the provided output slice is too small,

#![cfg_attr(feature = "cargo-clippy", allow(cast_lossless))]
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

extern crate byteorder;
#[macro_use]
extern crate cfg_if;
use std::fmt;

mod chunked_encoder;
pub mod display;
mod tables;
pub mod write;

mod encode;
pub use encode::block::{BlockEncoding, IntoBlockEncoding};
pub use encode::{encode, encode_config, encode_config_buf, encode_config_slice, Encoding};

mod decode;
pub use decode::block::{BlockDecoding, IntoBlockDecoding};
pub use decode::{
    decode, decode_config, decode_config_buf, decode_config_slice, DecodeError, Decoding,
};

#[cfg(test)]
mod tests;

/// Encode + Decode using the standard character set with padding.
///
/// See [RFC 3548](https://tools.ietf.org/html/rfc3548#section-3).
pub const STANDARD: Standard = Config(StdAlphabet, StdPadding);

/// Encode + Decode using the standard character set *without* padding.
///
/// See [RFC 3548](https://tools.ietf.org/html/rfc3548#section-3).
pub const STANDARD_NO_PAD: StandardNoPad = Config(StdAlphabet, NoPadding);

/// Encode + Decode using the URL safe character set with padding.
///
/// See [RFC 3548](https://tools.ietf.org/html/rfc3548#section-3).
pub const URL_SAFE: UrlSafe = Config(UrlSafeAlphabet, StdPadding);
/// Encode + Decode using the URL safe character set *without* padding.
///
/// See [RFC 3548](https://tools.ietf.org/html/rfc3548#section-3).
pub const URL_SAFE_NO_PAD: UrlSafeNoPad = Config(UrlSafeAlphabet, NoPadding);

/// Encode + Decode using the `crypt(3)` character set with padding.
pub const CRYPT: Crypt = Config(CryptAlphabet, StdPadding);

/// Encode + Decode using the `crypt(3)` character set *without* padding.
pub const CRYPT_NO_PAD: CryptNoPad = Config(CryptAlphabet, NoPadding);

/// The type of the standard config with padding.
pub type Standard = Config<StdAlphabet, StdPadding>;

/// The type of the standard config *without* padding.
pub type StandardNoPad = Config<StdAlphabet, NoPadding>;

/// The type of the urlsafe config with padding.
pub type UrlSafe = Config<UrlSafeAlphabet, StdPadding>;

/// The type of the urlsafe config *without* padding.
pub type UrlSafeNoPad = Config<UrlSafeAlphabet, NoPadding>;

/// The type of the crypt config with padding.
pub type Crypt = Config<CryptAlphabet, StdPadding>;

/// The type of the crypt config *without* padding.
pub type CryptNoPad = Config<CryptAlphabet, NoPadding>;

// Module for trait sealing. The configuration traits are part of the public API
// because public functions (e.g. encode_config, decode_config, etc.) are
// bounded by them, but (atleast for now) we don't intend for outside
// crates to implement them. This provides more flexibility if we decide to
// change some of the traits behaviors. By having all the traits require
// private::Sealed to be implemented, we can effectively enforce that nobody
// outside this crate can implement the trait because the `private` module is
// not publicly accessible.
mod private {
    pub trait Sealed {}
}

/// Padding defines whether padding is used when encoding/decoding and if so
/// which character is to be used.
pub trait Padding: private::Sealed + Copy {
    /// The character to use for padding. None indicates no padding.
    fn padding_byte(self) -> Option<u8>;

    /// A boolean indicating whether padding is to be used or not.
    #[inline]
    fn has_padding(self) -> bool {
        self.padding_byte().is_some()
    }
}

/// StdPadding specifies to use the standard padding character b'='.
#[derive(Debug, Default, Clone, Copy)]
pub struct StdPadding;
impl Padding for StdPadding {
    #[inline]
    fn padding_byte(self) -> Option<u8> {
        Some(b'=')
    }
}
impl private::Sealed for StdPadding {}

/// NoPadding specifies that no padding is used when encoding/decoding.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoPadding;
impl Padding for NoPadding {
    #[inline]
    fn padding_byte(self) -> Option<u8> {
        None
    }
}
impl private::Sealed for NoPadding {}

/// Config wraps an `alphabet` (a type that implements Encoding+Decoding) and a
/// Padding. These are the basic requirements to use all the publicly accessible
/// functions.
#[derive(Debug, Default, Clone, Copy)]
pub struct Config<A: Copy, P: Copy>(A, P);

impl<A, P> Padding for Config<A, P>
where
    A: Copy,
    P: Padding,
{
    #[inline]
    fn padding_byte(self) -> Option<u8> {
        self.1.padding_byte()
    }
}

impl<A, P> Encoding for Config<A, P>
where
    A: Encoding,
    P: Copy,
{
    #[inline]
    fn encode_u6(self, input: u8) -> u8 {
        self.0.encode_u6(input)
    }
}

impl<A, P> IntoBlockEncoding for Config<A, P>
where
    A: Encoding,
    P: Copy,
{
    type BlockEncoding = A::BlockEncoding;

    #[inline]
    fn into_block_encoding(self) -> Self::BlockEncoding {
        self.0.into_block_encoding()
    }
}

impl<A, P> Decoding for Config<A, P>
where
    A: Decoding,
    P: Copy,
{
    #[inline]
    fn decode_u8(self, input: u8) -> u8 {
        self.0.decode_u8(input)
    }
}

impl<A, P> IntoBlockDecoding for Config<A, P>
where
    A: Decoding,
    P: Copy,
{
    type BlockDecoding = A::BlockDecoding;

    #[inline]
    fn into_block_decoding(self) -> Self::BlockDecoding {
        self.0.into_block_decoding()
    }
}

impl<A, P> private::Sealed for Config<A, P>
where
    A: Copy,
    P: Copy,
{
}

/// StdAlphabet encodes+decodes using the standard character set (uses `+` and `/``).
///
/// See [RFC 3548](https://tools.ietf.org/html/rfc3548#section-3).
#[derive(Debug, Default, Clone, Copy)]
pub struct StdAlphabet;

/// UrlSafeAlphabet implements Encoding + Decoding using the url safe character set (uses `-` and `_`).
///
/// See [RFC 3548](https://tools.ietf.org/html/rfc3548#section-4).
#[derive(Debug, Default, Clone, Copy)]
pub struct UrlSafeAlphabet;

/// CryptAlphabet implements Encoding + Decoding using the `crypt(3)` character set (uses `./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`).
///
/// Not standardized, but folk wisdom on the net asserts this alphabet is what crypt uses.
#[derive(Debug, Default, Clone, Copy)]
pub struct CryptAlphabet;

impl ::private::Sealed for StdAlphabet {}
impl ::private::Sealed for UrlSafeAlphabet {}
impl ::private::Sealed for CryptAlphabet {}

/// Use ConfigBuilder to build a custom configuration.
#[derive(Clone)]
pub struct ConfigBuilder<'a> {
    alphabet: &'a [u8; 64],
    padding_byte: Option<u8>,
}

impl<'a> fmt::Debug for ConfigBuilder<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ConfigBuilder{{alphabet: {:?}, padding_byte: {:?}}}",
            &self.alphabet[..],
            self.padding_byte
        )
    }
}

impl<'a> ConfigBuilder<'a> {
    /// Provide the set of characters to use when encoding and decoding. The
    /// provided characters will be encoded following the provided alphabet in
    /// the order specified. All characters in the alphabet are required to be
    /// ascii so that encoded values are valid UTF-8.
    pub fn with_alphabet(alphabet: &'a [u8; 64]) -> ConfigBuilder<'a> {
        ConfigBuilder {
            alphabet,
            padding_byte: Some(b'='),
        }
    }

    /// Use the specified padding_byte when encoding and decoding. The default padding is b'='.
    /// The padding is required to be ascii so that encoded values are valid UTF-8.
    pub fn with_padding(mut self, padding_byte: u8) -> ConfigBuilder<'a> {
        self.padding_byte = Some(padding_byte);
        self
    }

    /// Don't use padding when encoding and decoding.
    pub fn no_padding(mut self) -> ConfigBuilder<'a> {
        self.padding_byte = None;
        self
    }

    /// Create a CustomConfig that can be used to encode and decode.
    pub fn build(self) -> Result<CustomConfig, CustomConfigError> {
        if let Some(&b) = self.alphabet.iter().find(|b| !b.is_ascii()) {
            return Err(CustomConfigError::NonAscii(b));
        }
        if let Some(b) = self.padding_byte {
            if !b.is_ascii() {
                return Err(CustomConfigError::NonAscii(b));
            }
        }
        let mut decode_scratch: Vec<u8> = vec![::tables::INVALID_VALUE; 256];
        for (i, b) in self.alphabet.iter().cloned().enumerate() {
            if decode_scratch[b as usize] != ::tables::INVALID_VALUE {
                return Err(CustomConfigError::DuplicateValue(b));
            }
            decode_scratch[b as usize] = i as u8;
        }
        let mut encode_table = [0; 64];
        encode_table.copy_from_slice(self.alphabet);
        let mut decode_table = [0; 256];
        decode_table.copy_from_slice(&decode_scratch);
        Ok(CustomConfig {
            encode_table,
            decode_table,
            padding_byte: self.padding_byte,
        })
    }
}

/// Errors that can be returned when building a CustomConfig.
#[derive(Debug, Clone)]
pub enum CustomConfigError {
    /// There was a non-ascii character in the provided alphabet.
    NonAscii(u8),
    /// There was a duplicate value in the provided alphabet.
    DuplicateValue(u8),
}

/// CustomConfig can be used to encode and decode with a custom alphabet and/or
/// padding character. A configuration is a somewhat large struct (~2.5KB). For
/// this CustomConfig does not implement the Encoding/Decoding traits and instead
/// those traits are implemented for &CustomConfig.
#[derive(Clone)]
pub struct CustomConfig {
    encode_table: [u8; 64],
    decode_table: [u8; 256],
    padding_byte: Option<u8>,
}

impl fmt::Debug for CustomConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CustomConfig{{encode_table: {:?}, decode_table: {:?}, padding_byte: {:?}}}",
            &self.encode_table[..],
            &self.decode_table[..],
            self.padding_byte
        )
    }
}

impl Padding for &CustomConfig {
    #[inline]
    fn padding_byte(self) -> Option<u8> {
        self.padding_byte
    }
}

impl private::Sealed for &CustomConfig {}
