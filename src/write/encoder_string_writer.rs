use crate::Config;
use std::io;
use std::io::Write;
use super::encoder::EncoderWriter;

/// A `Write` implementation that base64-encodes data using the provided config and accumulates the
/// resulting base64 in memory, which is then exposed as a String via `finish()`.
///
/// # Examples
///
/// ```
/// use std::io::Write;
///
/// let mut enc = base64::write::EncoderStringWriter::new(base64::STANDARD);
///
/// enc.write_all(b"asdf").unwrap();
///
/// // get the resulting String
/// let b64_string = enc.finish().unwrap();
///
/// assert_eq!("YXNkZg==", &b64_string);
/// ```
///
/// # Panics
///
/// Calling `write()` (or related methods) or `finish()` after `finish()` has completed without
/// error is invalid and will panic.
///
/// # Performance
///
/// B64-encoded data is buffered in the heap since the point is to collect it in a String.
pub struct EncoderStringWriter {
    encoder: EncoderWriter<Vec<u8>>,
}

impl EncoderStringWriter {
    /// Create a new EncoderStringWriter that will encode with the provided config.
    pub fn new(config: Config) -> EncoderStringWriter {
        EncoderStringWriter { encoder: EncoderWriter::new(Vec::new(), config) }
    }

    /// Encode all remaining buffered data, including any trailing incomplete input triples and
    /// associated padding.
    ///
    /// Once this succeeds, no further writes or calls to this method are allowed.
    ///
    /// Returns the base64-encoded form of the accumulated written data.
    ///
    /// # Errors
    ///
    /// The first error that is not of `ErrorKind::Interrupted` will be returned.
    pub fn finish(&mut self) -> io::Result<String> {
        let buf = self.encoder.finish()?;

        let str = String::from_utf8(buf).expect("Base64 should always be valid UTF-8");
        Ok(str)
    }
}

impl<'a> Write for EncoderStringWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.encoder.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.encoder.flush()
    }
}

#[cfg(test)]
mod tests {
    use crate::encode_config_buf;
    use crate::tests::random_config;
    use rand::Rng;
    use std::io::Write;
    use crate::write::encoder_string_writer::EncoderStringWriter;

    #[test]
    fn every_possible_split_of_input() {
        let mut rng = rand::thread_rng();
        let mut orig_data = Vec::<u8>::new();
        let mut normal_encoded = String::new();

        let size = 5_000;

        for i in 0..size {
            orig_data.clear();
            normal_encoded.clear();

            for _ in 0..size {
                orig_data.push(rng.gen());
            }

            let config = random_config(&mut rng);
            encode_config_buf(&orig_data, config, &mut normal_encoded);

            let mut stream_encoder = EncoderStringWriter::new(config);
            // Write the first i bytes, then the rest
            stream_encoder.write_all(&orig_data[0..i]).unwrap();
            stream_encoder.write_all(&orig_data[i..]).unwrap();

            let stream_encoded = stream_encoder.finish().unwrap();

            assert_eq!(normal_encoded, stream_encoded);
        }
    }
}
