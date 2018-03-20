use std::fmt;
use {Config, encode_config_slice};
use std::io::{Result, Write};

pub struct Base64Encoder<'a> {
    config: Config,
    w: &'a mut Write,
    extra: [u8; 3],
    extra_len: usize,
    output: [u8; 1024],
}

impl<'a> fmt::Debug for Base64Encoder<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "extra:{:?} extra_len:{:?} output[..5]: {:?}", self.extra, self.extra_len, &self.output[0..5])
    }
}

impl<'a> Base64Encoder<'a> {
    fn new(w: &'a mut Write, config: Config) -> Base64Encoder<'a> {
        Base64Encoder {
            config,
            w,                // writer to write encoded data to
            extra: [0u8; 3],     // extra data left over from previous write
            extra_len: 0,     // how much extra data
            output: [0u8; 1024], // output buffer
        }
    }
}

impl<'a> Write for Base64Encoder<'a> {
    fn write(&mut self, input: &[u8]) -> Result<usize> {
        let mut p = input;
        let mut input_read_cnt = 0;

        // process leftover stuff from last write
        if self.extra_len > 0 {
            let mut i = 0;
            while i < p.len() && self.extra_len < 3 {
                self.extra[self.extra_len] = p[i];
                self.extra_len += 1;
                i += 1;
            }
            input_read_cnt += i;
            p = &p[i..];
            if self.extra_len < 3 {
                // not enough to actually encode, yet.
                return Ok(input_read_cnt);
            }
            let sz = encode_config_slice(&self.extra[..3],
                                                 self.config,
                                                 &mut self.output[..]);
            self.extra_len = 0;
            self.w.write(&self.output[..sz])?;
        }

        // process chunks, 768 bytes -> 1024 (encoded) bytes, at a time
        let mut output_cnt = 0;
        while p.len() >= 3 {
            let mut nn = (self.output.len() / 4) * 3;
            if nn > p.len() {
                // force nn to be a multiple of three o we can encode cleanly
                nn = p.len();
                nn -= nn % 3;
            }
            let sz = encode_config_slice(&p[..nn],
                                                 self.config,
                                                 &mut self.output[..]);
            input_read_cnt += nn;
            output_cnt += sz;
            p = &p[nn..];
        }

        // stash leftover bytes
        let mut i = 0;
        while i < p.len() {
            self.extra[i] = p[i];
            i += 1;
        }
        input_read_cnt += p.len();
        self.extra_len = p.len();

        self.w.write(&self.output[..output_cnt])?;

        return Ok(input_read_cnt);
    }

    fn flush(&mut self) -> Result<()> {
        if self.extra_len > 0 {
            let sz = encode_config_slice(&self.extra[..self.extra_len],
                                                 self.config,
                                                 &mut self.output[..]);
            self.w.write(&self.output[..sz])?;
        }

        self.w.flush()
    }
}

#[cfg(test)]
mod tests {
    use encoder::Base64Encoder;
    use {encode_config, URL_SAFE};
    use std::io::{Cursor, Write};

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
        assert_eq!(&c.get_ref()[..], encode_config("abcdefghi", URL_SAFE).as_bytes());
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
        assert_eq!(&c.get_ref()[..], encode_config("abcdef", URL_SAFE).as_bytes());
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
        assert_eq!(&c.get_ref()[..], encode_config("abcdef", URL_SAFE).as_bytes());
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

            enc.write(b"a").unwrap();
            enc.write(b"bcd").unwrap();
            enc.write(b"ef").unwrap();
            enc.write(b"g").unwrap();

            enc.flush().unwrap();
        }
        assert_eq!(&c.get_ref()[..], encode_config("abcdefg", URL_SAFE).as_bytes());
    }
}

