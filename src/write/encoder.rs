use encode::encode_to_slice;
use std::fmt;
use std::io::{Result, Write};
use {encode_config_slice, Config};

// TODO clearer name
/// A `Write` proxy that base64-encodes written data and hands the result off to another writer.
pub struct Base64Encoder<'a> {
    config: Config,
    w: &'a mut Write,
    /// Holds a partial chunk, if any, after the last `write()`, so that we may then fill the chunk
    /// with the next `write()`, encode it, then proceed with the rest of the input normally.
    extra: [u8; 3],
    /// How much of `extra` is occupied.
    extra_len: usize,
    /// Buffer to encode into
    output: [u8; 1024],
    /// True iff padding / partial last chunk has been written.
    output_finished: bool,
}

impl<'a> fmt::Debug for Base64Encoder<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "extra:{:?} extra_len:{:?} output[..5]: {:?}",
            self.extra,
            self.extra_len,
            &self.output[0..5]
        )
    }
}

impl<'a> Base64Encoder<'a> {
    /// Create a new encoder around an existing writer.
    pub fn new(w: &'a mut Write, config: Config) -> Base64Encoder<'a> {
        // TODO decide what to do about line wraps
        assert_eq!(::LineWrap::NoWrap, config.line_wrap);
        Base64Encoder {
            config,
            w,                   // writer to write encoded data to
            extra: [0u8; 3],     // extra data left over from previous write
            extra_len: 0,        // how much extra data
            output: [0u8; 1024], // output buffer
            output_finished: false,
        }
    }

    /// Flush all buffered data, including any padding or trailing incomplete triples.
    ///
    /// Once this is called, no further writes can be performed.
    pub fn finish(&mut self) -> Result<()> {
        if self.output_finished {
            // TODO disallow subsequent writes?
            return Ok(());
        };

        self.output_finished = true;

        if self.extra_len > 0 {
            let sz = encode_config_slice(
                &self.extra[..self.extra_len],
                self.config,
                &mut self.output[..],
            );
            let _ = self.w.write(&self.output[..sz])?;
        }

        self.flush()
    }
}

impl<'a> Write for Base64Encoder<'a> {
    fn write(&mut self, input: &[u8]) -> Result<usize> {
        if self.output_finished {
            panic!("Cannot write more after writing the trailing padding/partial chunk");
        }

        // TODO handle line breaks
        let mut input = input;
        let mut input_read_cnt = 0;

        // process leftover stuff from last write
        if self.extra_len > 0 {
            let mut i = 0;
            while i < input.len() && self.extra_len < 3 {
                self.extra[self.extra_len] = input[i];
                self.extra_len += 1;
                i += 1;
            }
            input_read_cnt += i;
            input = &input[i..];

            if self.extra_len < 3 {
                // not enough to actually encode, yet.
                return Ok(input_read_cnt);
            }

            let encoded_size = encode_to_slice(
                &self.extra[..3],
                &mut self.output[..],
                self.config.char_set.encode_table(),
            );
            self.extra_len = 0;
            let _ = self.w.write(&self.output[..encoded_size])?;
        }

        // encode in big chunks where possible
        let max_input_chunk_len = (self.output.len() / 4) * 3;
        // only handle complete triples
        let input_triples_len = input.len() - (input.len() % 3);
        for ref chunk in input[0..input_triples_len].chunks(max_input_chunk_len) {
            let encoded_size = encode_to_slice(
                &chunk,
                &mut self.output[..],
                self.config.char_set.encode_table(),
            );
            input_read_cnt += chunk.len();
            let _ = self.w.write(&self.output[..encoded_size])?;
        }
        input = &input[input_triples_len..];

        // stash leftover bytes
        let mut i = 0;
        while i < input.len() {
            self.extra[i] = input[i];
            i += 1;
        }
        input_read_cnt += input.len();
        self.extra_len = input.len();

        return Ok(input_read_cnt);
    }

    /// Because this is usually treated as OK to call multiple times, it will *not* flush any
    /// incomplete chunks of input or write padding.
    fn flush(&mut self) -> Result<()> {
        self.w.flush()
    }
}

impl<'a> Drop for Base64Encoder<'a> {
    fn drop(&mut self) {
        // TODO error handling?
        let _ = self.finish();
    }
}

