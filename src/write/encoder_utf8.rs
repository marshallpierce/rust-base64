use std::fmt;
use std::io;
use std::str::from_utf8;

use crate::engine::Engine;
use crate::write::EncoderWriter;

/// A [`io::Write`] wrapper for types implementing [`fmt::Write`]
///
/// It needn't be used directly, but as a parameter for [`EncoderWriter`].
///
/// # Examples
///
/// Write base64 into a new [`String`]:
///
/// ```
/// use std::io::Write;
/// use base64::engine::general_purpose;
///
/// let mut enc = base64::write::EncoderWriter::string(&general_purpose::STANDARD);
///
/// enc.write_all(b"asdf").unwrap();
///
/// // get the resulting String
/// let b64_string = enc.formatter();
///
/// assert_eq!("YXNkZg==", &b64_string);
/// ```
///
/// Or, append to an existing [`String`], which implements [`fmt::Write`]:
///
/// ```
/// use std::io::Write;
/// use base64::engine::general_purpose;
///
/// let mut buf = String::from("base64: ");
///
/// let mut enc = base64::write::EncoderWriter::utf8(
///     &mut buf,
///     &general_purpose::STANDARD);
///
/// enc.write_all(b"asdf").unwrap();
///
/// // release the &mut reference on buf
/// let _ = enc.formatter();
///
/// assert_eq!("base64: YXNkZg==", &buf);
/// ```
///
/// # Performance
///
/// Because it has to validate that the base64 is UTF-8, it is about 80% as fast as writing plain
/// bytes to a `io::Write`.
pub struct Utf8Compat<W: fmt::Write> {
    inner: W,
}

impl<W: fmt::Write> Utf8Compat<W> {
    /// Create wrapper implementing [`io::Write`] for [`fmt::Write`]
    pub fn new(writer: W) -> Self {
        Self { inner: writer }
    }

    /// Extract the underlying writer
    pub fn writer(self) -> W {
        self.inner
    }
}

impl<W: fmt::Write> From<W> for Utf8Compat<W> {
    fn from(value: W) -> Self {
        Self::new(value)
    }
}

impl<W: fmt::Write> io::Write for Utf8Compat<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner
            .write_str(from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?)
            .map_err(io::Error::other)
            .map(|()| buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'e, E: Engine, W: fmt::Write> EncoderWriter<'e, E, Utf8Compat<W>> {
    /// Create a [`EncoderWriter`] that will write [`&str`]
    pub fn utf8(writer: W, engine: &'e E) -> Self {
        Self::new(Utf8Compat::new(writer), engine)
    }

    /// Encode all remaining buffered data, including any trailing incomplete input triples and
    /// associated padding.
    ///
    /// Returns the base64-encoded form of the accumulated written data.
    pub fn formatter(mut self) -> W {
        self.finish()
            .expect("Writing to a consumer should never fail")
            .writer()
    }
}

impl<'e, E: Engine> EncoderWriter<'e, E, Utf8Compat<String>> {
    /// Create [`EncoderWriter`] writing to [`String`]
    pub fn string(engine: &'e E) -> Self {
        EncoderWriter::utf8(String::new(), engine)
    }
}

#[cfg(test)]
mod tests {
    use std::cmp;
    use std::io::Write;

    use rand::Rng;

    use crate::engine::Engine;
    use crate::tests::random_engine;
    use crate::write::EncoderWriter;

    #[test]
    fn every_possible_split_of_input() {
        let mut rng = rand::thread_rng();
        let mut orig_data = Vec::<u8>::new();
        let mut normal_encoded = String::new();

        let size = 5_000;

        for i in 0..size {
            orig_data.clear();
            normal_encoded.clear();

            orig_data.resize(size, 0);
            rng.fill(&mut orig_data[..]);

            let engine = random_engine(&mut rng);
            engine.encode_string(&orig_data, &mut normal_encoded);

            let mut stream_encoder = EncoderWriter::string(&engine);
            // Write the first i bytes, then the rest
            stream_encoder.write_all(&orig_data[0..i]).unwrap();
            stream_encoder.write_all(&orig_data[i..]).unwrap();

            let stream_encoded = stream_encoder.formatter();

            assert_eq!(normal_encoded, stream_encoded);
        }
    }

    #[test]
    fn incremental_writes() {
        let mut rng = rand::thread_rng();
        let mut orig_data = Vec::<u8>::new();
        let mut normal_encoded = String::new();

        let size = 5_000;

        for _ in 0..size {
            orig_data.clear();
            normal_encoded.clear();

            orig_data.resize(size, 0);
            rng.fill(&mut orig_data[..]);

            let engine = random_engine(&mut rng);
            engine.encode_string(&orig_data, &mut normal_encoded);

            let mut stream_encoder = EncoderWriter::string(&engine);
            // write small nibbles of data
            let mut offset = 0;
            while offset < size {
                let nibble_size = cmp::min(rng.gen_range(0..=64), size - offset);
                let len = stream_encoder
                    .write(&orig_data[offset..offset + nibble_size])
                    .unwrap();
                offset += len;
            }

            let stream_encoded = stream_encoder.formatter();

            assert_eq!(normal_encoded, stream_encoded);
        }
    }
}
