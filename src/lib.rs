//! # Configs
//!
//! There isn't just one type of Base64; that would be too simple. You need to choose a character
//! set (standard or URL-safe), padding suffix (yes/no), and line wrap (line length, line ending).
//! The `Config` struct encapsulates this info. There are some common configs included: `STANDARD`,
//! `MIME`, etc. You can also make your own `Config` if needed.
//!
//! The functions that don't have `config` in the name (e.g. `encode()` and `decode()`) use the
//! `STANDARD` config .
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
//! All of the encoding functions that take a `Config` will pad, line wrap, etc, as per the config.
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
//!
//! Unlike encoding, where all possible input is valid, decoding can fail (see `DecodeError`).
//!
//! Input can be invalid because it has invalid characters or invalid padding. (No padding at all is
//! valid, but incorrect padding is not.)
//!
//! Whitespace in the input is invalid unless `strip_whitespace` is enabled in the `Config` used.
//!
//! # Panics
//!
//! If length calculations result in overflowing `usize`, a panic will result.

#![deny(missing_docs, trivial_casts, trivial_numeric_casts, unused_extern_crates,
        unused_import_braces, unused_results, variant_size_differences, warnings)]

extern crate byteorder;

pub mod display;
mod tables;
mod chunked_encoder;
mod line_wrap;

use line_wrap::{line_wrap, line_wrap_parameters};

mod encode;
pub use encode::{encode, encode_config, encode_config_buf, encode_config_slice};

mod decode;
pub use decode::{decode, decode_config, decode_config_buf, DecodeError};

#[cfg(test)]
mod tests;

/// Available encoding character sets
#[derive(Clone, Copy, Debug)]
pub enum CharacterSet {
    /// The standard character set (uses `+` and `/`)
    Standard,
    /// The URL safe character set (uses `-` and `_`)
    UrlSafe,
}

impl CharacterSet {
    fn encode_table(&self) -> &'static [u8; 64] {
        match *self {
            CharacterSet::Standard => tables::STANDARD_ENCODE,
            CharacterSet::UrlSafe => tables::URL_SAFE_ENCODE,
        }
    }

    fn decode_table(&self) -> &'static [u8; 256] {
        match *self {
            CharacterSet::Standard => tables::STANDARD_DECODE,
            CharacterSet::UrlSafe => tables::URL_SAFE_DECODE,
        }
    }
}

/// Line ending used in optional line wrapping.
#[derive(Clone, Copy, Debug)]
pub enum LineEnding {
    /// Unix-style \n
    LF,
    /// Windows-style \r\n
    CRLF,
}

impl LineEnding {
    fn len(&self) -> usize {
        match *self {
            LineEnding::LF => 1,
            LineEnding::CRLF => 2,
        }
    }
}

/// Line wrap configuration.
#[derive(Clone, Copy, Debug)]
pub enum LineWrap {
    /// Don't wrap.
    NoWrap,
    /// Wrap lines with the specified length and line ending. The length must be > 0.
    Wrap(usize, LineEnding),
}

/// Contains configuration parameters for base64 encoding
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Character set to use
    char_set: CharacterSet,
    /// True to pad output with `=` characters
    pad: bool,
    /// Remove whitespace before decoding, at the cost of an allocation. Whitespace is defined
    /// according to POSIX-locale `isspace`, meaning \n \r \f \t \v and space.
    strip_whitespace: bool,
    /// ADT signifying whether to linewrap output, and if so by how many characters and with what
    /// ending
    line_wrap: LineWrap,
}

impl Config {
    /// Create a new `Config`.
    pub fn new(
        char_set: CharacterSet,
        pad: bool,
        strip_whitespace: bool,
        input_line_wrap: LineWrap,
    ) -> Config {
        let line_wrap = match input_line_wrap {
            LineWrap::Wrap(0, _) => LineWrap::NoWrap,
            _ => input_line_wrap,
        };

        Config {
            char_set,
            pad,
            strip_whitespace,
            line_wrap,
        }
    }
}

/// Standard character set with padding.
pub const STANDARD: Config = Config {
    char_set: CharacterSet::Standard,
    pad: true,
    strip_whitespace: false,
    line_wrap: LineWrap::NoWrap,
};

/// Standard character set without padding.
pub const STANDARD_NO_PAD: Config = Config {
    char_set: CharacterSet::Standard,
    pad: false,
    strip_whitespace: false,
    line_wrap: LineWrap::NoWrap,
};

/// As per standards for MIME encoded messages
pub const MIME: Config = Config {
    char_set: CharacterSet::Standard,
    pad: true,
    strip_whitespace: true,
    line_wrap: LineWrap::Wrap(76, LineEnding::CRLF),
};

/// URL-safe character set with padding
pub const URL_SAFE: Config = Config {
    char_set: CharacterSet::UrlSafe,
    pad: true,
    strip_whitespace: false,
    line_wrap: LineWrap::NoWrap,
};

/// URL-safe character set without padding
pub const URL_SAFE_NO_PAD: Config = Config {
    char_set: CharacterSet::UrlSafe,
    pad: false,
    strip_whitespace: false,
    line_wrap: LineWrap::NoWrap,
};
