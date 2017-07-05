use super::{STANDARD, Config};
use super::chunked_encoder::{ChunkedEncoder, ChunkedEncoderError};
use std::fmt::{Display, Formatter};
use std::{fmt, str};

/// A convenience wrapper for base64'ing bytes into a format string without heap allocation.
pub struct Base64Display<'a> {
    bytes: &'a [u8],
    chunked_encoder: ChunkedEncoder
}

impl<'a> Base64Display<'a> {
    /// Create a Base64Display with default base64 configuration: no line wrapping, with padding.
    pub fn new(bytes: &[u8]) -> Base64Display {
        Self::new_with_config(bytes, STANDARD).expect("STANDARD is always ok")
    }

    fn new_with_config(bytes: &[u8], config: Config) -> Result<Base64Display, ChunkedEncoderError> {
        ChunkedEncoder::new(config).map( |c| Base64Display {
            bytes: bytes,
            chunked_encoder: c
        })
    }
}

impl<'a> Display for Base64Display<'a> {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), fmt::Error> {
        let mut sink = FormatterSink { f: formatter };
        self.chunked_encoder.encode(self.bytes, &mut sink)
    }
}

struct FormatterSink<'a, 'b: 'a> {
    f: &'a mut Formatter<'b>
}

impl<'a, 'b: 'a> super::chunked_encoder::Sink for FormatterSink<'a, 'b> {
    type Error = fmt::Error;

    fn write_encoded_bytes(&mut self, encoded: &[u8]) -> Result<(), Self::Error> {
        // Avoid unsafe. If max performance is needed, write your own display wrapper that uses
        // unsafe here to gain about 10-15%.
        self.f.write_str(str::from_utf8(encoded).expect("base64 data was not utf8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::*;
    use super::super::chunked_encoder::tests::{SinkTestHelper, chunked_encode_matches_normal_encode_random};

    #[test]
    fn basic_display() {
        assert_eq!("~$Zm9vYmFy#*", format!("~${}#*", Base64Display::new("foobar".as_bytes())));
        assert_eq!("~$Zm9vYmFyZg==#*", format!("~${}#*", Base64Display::new("foobarf".as_bytes())));
    }

    #[test]
    fn display_encode_matches_normal_encode() {
        let helper = DisplaySinkTestHelper;
        chunked_encode_matches_normal_encode_random(&helper);
    }

    struct DisplaySinkTestHelper;

    impl SinkTestHelper for DisplaySinkTestHelper {
        fn encode_to_string(&self, config: Config, bytes: &[u8]) -> String {
            format!("{}", Base64Display::new_with_config(bytes, config).unwrap())
        }
    }

}
