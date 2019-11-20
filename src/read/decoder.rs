use crate::{decode_config_slice, Config};
use std::cmp;
use std::fmt;
use std::io::{Error, ErrorKind, Read, Result};

// This should be large, but it has to fit on the stack.
pub(crate) const BUF_SIZE: usize = 1024;

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
///
/// // use a cursor as the simplest possible `Read` -- in real code this is probably a file, etc.
/// let mut wrapped_reader = Cursor::new(b"YXNkZg==");
/// let mut decoder = base64::read::DecoderReader::new(
///     &mut wrapped_reader, base64::STANDARD);
///
/// // handle errors as you normally would
/// let mut result = Vec::new();
/// decoder.read_to_end(&mut result).unwrap();
///
/// assert_eq!(b"asdf", &result[..]);
///
/// ```
pub struct DecoderReader<'a, R: 'a + Read> {
    config: Config,
    /// Where encoded data is read from
    r: &'a mut R,

    // The maximum of decoded base64 data that we'll buffer at once.
    buffer: [u8; BUF_SIZE],
    // The start of the unreturned buffered data.
    buffer_offset: usize,
    // The amount of buffered data.
    buffer_amount: usize,
}

impl<'a, R: Read> fmt::Debug for DecoderReader<'a, R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("DecoderReader")
            .field("config", &self.config)
            .field("buffer_offset", &self.buffer_offset)
            .field("buffer_amount", &self.buffer_amount)
            .finish()
    }
}

impl<'a, R: Read> DecoderReader<'a, R> {
    /// Create a new decoder that will read from the provided reader `r`.
    pub fn new(r: &'a mut R, config: Config) -> Self {
        DecoderReader {
            config,
            r,
            buffer: [0; BUF_SIZE],
            buffer_offset: 0,
            buffer_amount: 0,
        }
    }
}

impl<'a, R: Read> Read for DecoderReader<'a, R> {
    /// Decode input from the wrapped reader.
    ///
    /// Under non-error circumstances, this returns `Ok` with the value being the number of bytes
    /// returned in `buf`.
    ///
    /// If the caller performs a short read, then this function reads in a large chunk of data,
    /// decodes that, and buffers the result.  The intent is to amortize the decoding cost
    /// of many small reads.
    ///
    /// # Errors
    ///
    /// Any errors emitted by the delegate reader are returned.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Check some invariants.
        assert!(self.buffer_offset < BUF_SIZE);
        assert!(self.buffer_amount <= BUF_SIZE);
        assert!(self.buffer_offset + self.buffer_amount <= BUF_SIZE);

        if self.buffer_amount > 0 {
            // We have something buffered, use that.

            let amount = cmp::min(buf.len(), self.buffer_amount);
            buf[..amount]
                .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + amount]);
            self.buffer_offset += amount;
            self.buffer_amount -= amount;

            Ok(amount)
        } else if buf.len() >= 2 * DECODED_CHUNK_SIZE {
            // The caller wants at least two chunks.  Round down to a
            // multiple of the chunk size and decode directly into the
            // caller-provided buffer.
            let base64_bytes = cmp::min(
                BUF_SIZE,
                (buf.len() / DECODED_CHUNK_SIZE) * BASE64_CHUNK_SIZE,
            );
            assert!(base64_bytes > 0);

            // TODO what if read provides less data than we asked for?
            // borrow our buffer since it has nothing of value in it
            let read = self.r.read(&mut self.buffer[..base64_bytes])?;

            // TODO only decode complete chunks
            let decoded = decode_config_slice(&self.buffer[..read], self.config, buf)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
            // TODO keep track of any data we didn't decode (i.e. incomplete chunks)

            Ok(decoded)
        } else {
            // The caller wants less than a chunk of decoded data
            // (i.e., one or two bytes).  We have to buffer something.
            // Double buffer a large amount in case short reads turn
            // out to be common.

            // TODO maybe store base64 in the buffer, and keep a separate decode buffer that holds
            // only a decoded chunk (3 bytes) to handle very short read calls?

            let mut base64_data = [0u8; BUF_SIZE];
            let read = self.r.read(&mut base64_data)?;

            let decoded = decode_config_slice(&base64_data[..read], self.config, &mut self.buffer)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

            let returning = cmp::min(buf.len(), decoded);
            buf[..returning].copy_from_slice(&self.buffer[..returning]);

            self.buffer_offset = returning;
            self.buffer_amount = decoded - returning;

            Ok(returning)
        }
    }
}
