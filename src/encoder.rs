use std::fmt;
use encode::encode_to_slice;
use {encode_config_slice, Config};
use std::io::{Result, Write};

/// A `Write` proxy that base64-encodes written data and hands the result off to another writer.
pub struct Base64Encoder<'a> {
    config: Config,
    w: &'a mut Write,
    extra: [u8; 3],
    extra_len: usize,
    output: [u8; 1024],
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
        Base64Encoder {
            config,
            w,                   // writer to write encoded data to
            extra: [0u8; 3],     // extra data left over from previous write
            extra_len: 0,        // how much extra data
            output: [0u8; 1024], // output buffer
        }
    }
}

impl<'a> Write for Base64Encoder<'a> {
    fn write(&mut self, input: &[u8]) -> Result<usize> {
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

        // process chunks, 768 bytes -> 1024 (encoded) bytes, at a time
        // TODO try using `chunks()`
        while input.len() >= 3 {
            let mut bytes_to_encode = (self.output.len() / 4) * 3;
            if bytes_to_encode > input.len() {
                // force nn to be a multiple of three o we can encode cleanly
                bytes_to_encode = input.len();
                bytes_to_encode -= bytes_to_encode % 3;
            }
            let encoded_size = encode_to_slice(
                &input[..bytes_to_encode],
                &mut self.output[..],
                self.config.char_set.encode_table(),
            );
            input_read_cnt += bytes_to_encode;
            input = &input[bytes_to_encode..];
            let _ = self.w.write(&self.output[..encoded_size])?;
        }

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

    fn flush(&mut self) -> Result<()> {
        if self.extra_len > 0 {
            // TODO should not write padding on each flush() -- should be able to flush() > 1x
            let sz = encode_config_slice(
                &self.extra[..self.extra_len],
                self.config,
                &mut self.output[..],
            );
            let _ = self.w.write(&self.output[..sz])?;
        }

        self.w.flush()
    }
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use super::Base64Encoder;
    use {encode_config, encode_config_buf, URL_SAFE};
    use tests::random_config;

    use std::io::{Cursor, Write};
    use std::str;

    use self::rand::Rng;
    use self::rand::distributions::range;

    #[test]
    fn encode_three_bytes() {
        let mut c = Cursor::new(Vec::new());
        {
            let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

            let sz = enc.write(b"abc").unwrap();
            assert_eq!(sz, 3);
        }
        assert_eq!(&c.get_ref()[..], encode_config("abc", URL_SAFE).as_bytes());
    }

    #[test]
    fn encode_nine_bytes_two_writes() {
        let mut c = Cursor::new(Vec::new());
        {
            let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

            let sz = enc.write(b"abcdef").unwrap();
            assert_eq!(sz, 6);
            let sz = enc.write(b"ghi").unwrap();
            assert_eq!(sz, 3);
        }
        assert_eq!(
            &c.get_ref()[..],
            encode_config("abcdefghi", URL_SAFE).as_bytes()
        );
    }

    #[test]
    fn encode_one_two() {
        let mut c = Cursor::new(Vec::new());
        {
            let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

            let sz = enc.write(b"a").unwrap();
            assert_eq!(sz, 1);
            let sz = enc.write(b"bc").unwrap();
            assert_eq!(sz, 2);
        }
        assert_eq!(&c.get_ref()[..], encode_config("abc", URL_SAFE).as_bytes());
    }

    #[test]
    fn encode_one_five() {
        let mut c = Cursor::new(Vec::new());
        {
            let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

            let sz = enc.write(b"a").unwrap();
            assert_eq!(sz, 1);
            let sz = enc.write(b"bcdef").unwrap();
            assert_eq!(sz, 5);
        }
        assert_eq!(
            &c.get_ref()[..],
            encode_config("abcdef", URL_SAFE).as_bytes()
        );
    }

    #[test]
    fn encode_1_2_3() {
        let mut c = Cursor::new(Vec::new());
        {
            let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

            let sz = enc.write(b"a").unwrap();
            assert_eq!(sz, 1);
            let sz = enc.write(b"bc").unwrap();
            assert_eq!(sz, 2);
            let sz = enc.write(b"def").unwrap();
            assert_eq!(sz, 3);
        }
        assert_eq!(
            &c.get_ref()[..],
            encode_config("abcdef", URL_SAFE).as_bytes()
        );
    }

    #[test]
    fn encode_with_padding() {
        let mut c = Cursor::new(Vec::new());
        {
            let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

            let sz = enc.write(b"abcd").unwrap();
            assert_eq!(sz, 4);

            enc.flush().unwrap();
        }
        assert_eq!(&c.get_ref()[..], encode_config("abcd", URL_SAFE).as_bytes());
    }

    #[test]
    fn encode_with_padding_multiple_writes() {
        let mut c = Cursor::new(Vec::new());
        {
            let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

            let _ = enc.write(b"a").unwrap();
            let _ = enc.write(b"bcd").unwrap();
            let _ = enc.write(b"ef").unwrap();
            let _ = enc.write(b"g").unwrap();

            enc.flush().unwrap();
        }
        assert_eq!(
            &c.get_ref()[..],
            encode_config("abcdefg", URL_SAFE).as_bytes()
        );
    }

    #[test]
    fn encode_random_config_matches_normal_encode() {
        let mut rng = rand::thread_rng();
        let mut orig_data = Vec::<u8>::new();
        let mut stream_encoded = Vec::<u8>::new();
        let mut normal_encoded = String::new();
        let line_len_range = range::Range::new(1, 2000);

        for _ in 0..1_000 {
            orig_data.clear();
            stream_encoded.clear();
            normal_encoded.clear();

            // TODO for now, ignore configs with line wraps
            let mut config = random_config(&mut rng, &line_len_range);
            while let ::LineWrap::Wrap(_, _) = config.line_wrap {
                config = random_config(&mut rng, &line_len_range)
            }

            let orig_len: usize = rng.gen_range(100, 10_000);
            for _ in 0..orig_len {
                orig_data.push(rng.gen());
            }

            // encode the normal way
            encode_config_buf(&orig_data, config, &mut normal_encoded);

            // encode via the stream encoder
            {
                let mut stream_encoder = Base64Encoder::new(&mut stream_encoded, config);
                let mut bytes_consumed = 0;
                while bytes_consumed < orig_len {
                    let input_len: usize = rng.gen_range(0, orig_len - bytes_consumed + 1);

                    // write a little bit of the data
                    bytes_consumed += stream_encoder
                        .write(&orig_data[bytes_consumed..bytes_consumed + input_len])
                        .unwrap();
                }

                // TODO final write should be done by drop()
                stream_encoder.flush().unwrap();

                assert_eq!(orig_len, bytes_consumed);
            }

            assert_eq!(normal_encoded, str::from_utf8(&stream_encoded).unwrap());
        }
    }
}
