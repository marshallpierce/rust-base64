use crate::{engine::Engine, DecodeError};
use std::{cmp, fmt, io};

// 4 bytes of base64 data encode 3 bytes of raw data (modulo padding).
const BASE64_CHUNK_SIZE: usize = 4;
const DECODED_CHUNK_SIZE: usize = 3;

/// A `Read` implementation that decodes base64 data read from an underlying reader.
///
/// # Examples
///
/// ```
/// use std::io::Read;
/// use std::io::Cursor;
/// use base64::engine::general_purpose;
///
/// // use a cursor as the simplest possible `Read` -- in real code this is probably a file, etc.
/// let mut wrapped_reader = Cursor::new(b"YXNkZg==");
/// let mut decoder = base64::read::DecoderReader::new(
///     &mut wrapped_reader,
///     &general_purpose::STANDARD);
///
/// // handle errors as you normally would
/// let mut result = Vec::new();
/// decoder.read_to_end(&mut result).unwrap();
///
/// assert_eq!(b"asdf", &result[..]);
///
/// ```
pub struct DecoderReader<'e, E: Engine, R: io::BufRead> {
    engine: &'e E,
    /// Where b64 data is read from
    inner: R,

    // Since the caller may provide us with a buffer of size 1 or 2 that's too small to copy a
    // decoded chunk in to, we have to be able to hang on to a few decoded bytes.
    // Technically we only need to hold 2 bytes but then we'd need a separate temporary buffer to
    // decode 3 bytes into and then juggle copying one byte into the provided read buf and the rest
    // into here, which seems like a lot of complexity for 1 extra byte of storage.
    decoded_buffer: [u8; 3],
    // index of start of decoded data
    decoded_offset: usize,
    // length of decoded data
    decoded_len: usize,
    // used to provide accurate offsets in errors
    total_b64_decoded: usize,
}

impl<'e, E: Engine, R: io::BufRead> fmt::Debug for DecoderReader<'e, E, R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("DecoderReader")
            .field("decoded_buffer", &self.decoded_buffer)
            .field("decoded_offset", &self.decoded_offset)
            .field("decoded_len", &self.decoded_len)
            .field("total_b64_decoded", &self.total_b64_decoded)
            .finish()
    }
}

impl<'e, E: Engine, R: io::BufRead> DecoderReader<'e, E, R> {
    /// Create a new decoder that will read from the provided reader `r`.
    pub fn new(reader: R, engine: &'e E) -> Self {
        DecoderReader {
            engine,
            inner: reader,
            decoded_buffer: [0; DECODED_CHUNK_SIZE],
            decoded_offset: 0,
            decoded_len: 0,
            total_b64_decoded: 0,
        }
    }

    /// Write as much as possible of the decoded buffer into the target buffer.
    /// Must only be called when there is something to write and space to write into.
    /// Returns a Result with the number of (decoded) bytes copied.
    fn flush_decoded_buf(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert!(self.decoded_len > 0);
        debug_assert!(!buf.is_empty());

        let copy_len = cmp::min(self.decoded_len, buf.len());
        debug_assert!(copy_len > 0);
        debug_assert!(copy_len <= self.decoded_len);

        buf[..copy_len].copy_from_slice(
            &self.decoded_buffer[self.decoded_offset..self.decoded_offset + copy_len],
        );

        self.decoded_offset += copy_len;
        self.decoded_len -= copy_len;

        debug_assert!(self.decoded_len < DECODED_CHUNK_SIZE);

        Ok(copy_len)
    }

    /// Unwraps this `DecoderReader`, returning the base reader which it reads base64 encoded
    /// input from.
    ///
    /// Because `DecoderReader` performs internal buffering, the state of the inner reader is
    /// unspecified. This function is mainly provided because the inner reader type may provide
    /// additional functionality beyond the `Read` implementation which may still be useful.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

fn map_error_offset(total_b64_decoded: usize) -> impl FnOnce(DecodeError) -> io::Error {
    move |error| {
        let error = match error {
            DecodeError::InvalidByte(offset, byte) => {
                DecodeError::InvalidByte(total_b64_decoded + offset, byte)
            }
            DecodeError::InvalidLength => DecodeError::InvalidLength,
            DecodeError::InvalidLastSymbol(offset, byte) => {
                DecodeError::InvalidLastSymbol(total_b64_decoded + offset, byte)
            }
            DecodeError::InvalidPadding => DecodeError::InvalidPadding,
        };
        io::Error::new(io::ErrorKind::InvalidData, error)
    }
}

impl<'e, E: Engine, R: io::BufRead> io::Read for DecoderReader<'e, E, R> {
    /// Decode input from the wrapped reader.
    ///
    /// Under non-error circumstances, this returns `Ok` with the value being the number of bytes
    /// written in `buf`.
    ///
    /// Where possible, this function buffers base64 to minimize the number of read() calls to the
    /// delegate reader.
    ///
    /// # Errors
    ///
    /// Any errors emitted by the delegate reader are returned. Decoding errors due to invalid
    /// base64 are also possible, and will have `io::ErrorKind::InvalidData`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        debug_assert!(if self.decoded_len == 0 {
            // can be = when we were able to copy the complete chunk
            self.decoded_offset <= DECODED_CHUNK_SIZE
        } else {
            self.decoded_offset < DECODED_CHUNK_SIZE
        });

        // We shouldn't ever decode into here when we can't immediately write at least one byte into
        // the provided buf, so the effective length should only be 3 momentarily between when we
        // decode and when we copy into the target buffer.
        debug_assert!(self.decoded_len < DECODED_CHUNK_SIZE);
        debug_assert!(self.decoded_len + self.decoded_offset <= DECODED_CHUNK_SIZE);

        if self.decoded_len > 0 {
            // we have a few leftover decoded bytes; flush that rather than pull in more b64
            self.flush_decoded_buf(buf)
        } else {
            let mut b64_bytes = self.inner.fill_buf()?;

            if b64_bytes.is_empty() {
                return Ok(0);
            };

            let mut b64_bytes_tmp;
            let mut at_eof = false;
            let mut short = false;
            if b64_bytes.len() < BASE64_CHUNK_SIZE {
                short = true;
                // Read as much as we can, trying to have a full chunk.
                b64_bytes_tmp = [0; BASE64_CHUNK_SIZE];
                b64_bytes_tmp[..b64_bytes.len()].copy_from_slice(b64_bytes);
                let mut pos = b64_bytes.len();
                self.inner.consume(pos);
                while pos < BASE64_CHUNK_SIZE {
                    let bytes_read = match self.inner.read(&mut b64_bytes_tmp[pos..]) {
                        Ok(len) => len,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    };
                    if bytes_read == 0 {
                        at_eof = true;
                        break;
                    }
                    pos += bytes_read;
                }
                b64_bytes = &b64_bytes_tmp[..pos];
            }

            debug_assert!(if at_eof {
                // if we are at eof, we may not have a complete chunk
                b64_bytes.len() > 0
            } else {
                // otherwise, we must have at least one chunk
                b64_bytes.len() >= BASE64_CHUNK_SIZE
            });

            debug_assert_eq!(0, self.decoded_len);

            if buf.len() < DECODED_CHUNK_SIZE {
                // caller requested an annoyingly short read
                // if we are at eof, could have less than BASE64_CHUNK_SIZE, in which case we have
                // to assume that these last few tokens are, in fact, valid (i.e. must be 2-4 b64
                // tokens, not 1, since 1 token can't decode to 1 byte).
                let to_decode = cmp::min(b64_bytes.len(), BASE64_CHUNK_SIZE);
                debug_assert!(b64_bytes.len() > BASE64_CHUNK_SIZE || to_decode == b64_bytes.len());

                let decoded = self
                    .engine
                    .internal_decode(
                        &b64_bytes[..to_decode],
                        &mut self.decoded_buffer,
                        self.engine.internal_decoded_len_estimate(to_decode),
                    )
                    .map_err(map_error_offset(self.total_b64_decoded))?;

                self.total_b64_decoded += to_decode;
                if !short { self.inner.consume(to_decode); }

                self.decoded_offset = 0;
                self.decoded_len = decoded;

                // can be less than 3 on last block due to padding
                debug_assert!(decoded <= 3);


                self.flush_decoded_buf(buf)
            } else {
                let b64_bytes_that_can_decode_into_buf = (buf.len() / DECODED_CHUNK_SIZE)
                    .checked_mul(BASE64_CHUNK_SIZE)
                    .expect("too many chunks");
                debug_assert!(b64_bytes_that_can_decode_into_buf >= BASE64_CHUNK_SIZE);

                let b64_bytes_available_to_decode = if at_eof {
                    b64_bytes.len()
                } else {
                    // only use complete chunks
                    b64_bytes.len() - b64_bytes.len() % 4
                };

                let actual_decode_len = cmp::min(
                    b64_bytes_that_can_decode_into_buf,
                    b64_bytes_available_to_decode,
                );
                let decoded = self
                    .engine
                    .internal_decode(
                        &b64_bytes[..actual_decode_len],
                        buf,
                        self.engine.internal_decoded_len_estimate(actual_decode_len),
                    )
                    .map_err(map_error_offset(self.total_b64_decoded))?;

                self.total_b64_decoded += actual_decode_len;
                if !short { self.inner.consume(actual_decode_len); }
                Ok(decoded)
            }
        }
    }
}
