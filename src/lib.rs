extern crate byteorder;

use std::{fmt, error, str};

use byteorder::{BigEndian, ByteOrder};

mod tables;

/// Available encoding character sets
#[derive(Clone, Copy, Debug)]
pub enum CharacterSet {
    /// The standard character set (uses `+` and `/`)
    Standard,
    /// The URL safe character set (uses `-` and `_`)
    UrlSafe
}

#[derive(Clone, Copy, Debug)]
pub enum LineEnding {
    LF,
    CRLF,
}

/// Contains configuration parameters for base64 encoding
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Character set to use
    pub char_set: CharacterSet,
    /// True to pad output with `=` characters
    pub pad: bool,
    /// Remove whitespace before decoding, at the cost of an allocation
    pub strip_whitespace: bool,
    /// Characters per line, None (or Some(0), but less "proper") for no linebreaks
    pub line_size: Option<usize>,
    /// Unix or Windows line endings, ignored if above None/Some(0)
    pub line_ending: LineEnding,
}

pub static STANDARD: Config = Config {
    char_set: CharacterSet::Standard,
    pad: true,
    strip_whitespace: false,
    line_size: None,
    line_ending: LineEnding::LF,
};

pub static MIME: Config = Config {
    char_set: CharacterSet::Standard,
    pad: true,
    strip_whitespace: true,
    line_size: Some(76),
    line_ending: LineEnding::CRLF,
};

pub static URL_SAFE: Config = Config {
    char_set: CharacterSet::UrlSafe,
    pad: true,
    strip_whitespace: false,
    line_size: None,
    line_ending: LineEnding::LF,
};

pub static URL_SAFE_NO_PAD: Config = Config {
    char_set: CharacterSet::UrlSafe,
    pad: false,
    strip_whitespace: false,
    line_size: None,
    line_ending: LineEnding::LF,
};


#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    InvalidByte(usize, u8),
    InvalidLength,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecodeError::InvalidByte(index, byte) =>
                write!(f, "Invalid byte {}, offset {}.", byte, index),
            DecodeError::InvalidLength =>
                write!(f, "Encoded text cannot have a 6-bit remainder.")
        }
    }
}

impl error::Error for DecodeError {
    fn description(&self) -> &str {
        match *self {
            DecodeError::InvalidByte(_, _) => "invalid byte",
            DecodeError::InvalidLength => "invalid length"
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

///Encode arbitrary octets as base64.
///Returns a String.
///Convenience for `encode_config(input, base64::STANDARD);`.
///
///# Example
///
///```rust
///extern crate base64;
///
///fn main() {
///    let b64 = base64::encode(b"hello world");
///    println!("{}", b64);
///}
///```
pub fn encode(input: &[u8]) -> String {
    encode_config(input, STANDARD)
}

///Decode from string reference as octets.
///Returns a Result containing a Vec<u8>.
///Convenience `decode_config(input, base64::STANDARD);`.
///
///# Example
///
///```rust
///extern crate base64;
///
///fn main() {
///    let bytes = base64::decode("aGVsbG8gd29ybGQ=").unwrap();
///    println!("{:?}", bytes);
///}
///```
pub fn decode<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, DecodeError> {
    decode_config(input, STANDARD)
}

///Encode arbitrary octets as base64.
///Returns a String.
///
///# Example
///
///```rust
///extern crate base64;
///
///fn main() {
///    let b64 = base64::encode_config(b"hello world~", base64::STANDARD);
///    println!("{}", b64);
///
///    let b64_url = base64::encode_config(b"hello internet~", base64::URL_SAFE);
///    println!("{}", b64_url);
///}
///```
pub fn encode_config(input: &[u8], config: Config) -> String {
    let mut buf = String::with_capacity(encoded_size(input.len(), config));

    encode_config_buf(input, config, &mut buf);

    buf
}

/// calculate the base64 encoded string size, including padding
fn encoded_size(bytes_len: usize, config: Config) -> usize {
    let rem = bytes_len % 3;

    let complete_input_chunks = bytes_len / 3;
    let complete_output_chars = complete_input_chunks * 4;
    let printing_output_chars = if rem == 0 {
        complete_output_chars
    } else {
        complete_output_chars + 4
    };
    let line_ending_length = match config.line_ending {
        LineEnding::CRLF => 2,
        LineEnding::LF => 1,
    };
    let line_ending_output_chars = match config.line_size {
        Some(0) | None => 0,
        Some(n) => printing_output_chars / n * line_ending_length,
    };

    return printing_output_chars + line_ending_output_chars;
}

///Encode arbitrary octets as base64.
///Writes into the supplied buffer to avoid allocations.
///
///# Example
///
///```rust
///extern crate base64;
///
///fn main() {
///    let mut buf = String::new();
///    base64::encode_config_buf(b"hello world~", base64::STANDARD, &mut buf);
///    println!("{}", buf);
///
///    buf.clear();
///    base64::encode_config_buf(b"hello internet~", base64::URL_SAFE, &mut buf);
///    println!("{}", buf);
///}
///```
pub fn encode_config_buf(input: &[u8], config: Config, buf: &mut String) {
    let ref charset = match config.char_set {
        CharacterSet::Standard => tables::STANDARD_ENCODE,
        CharacterSet::UrlSafe => tables::URL_SAFE_ENCODE,
    };

    // reserve to make sure the memory we'll be writing to with unsafe is allocated
    buf.reserve(encoded_size(input.len(), config));

    let orig_buf_len = buf.len();
    let mut fast_loop_output_buf_len = orig_buf_len;

    let input_chunk_len = 6;

    let last_fast_index = input.len().saturating_sub(8);

    // we're only going to insert valid utf8
    let mut raw = unsafe { buf.as_mut_vec() };
    // start at the first free part of the output buf
    let mut output_ptr = unsafe { raw.as_mut_ptr().offset(orig_buf_len as isize) };
    let mut input_index: usize = 0;
    if input.len() >= 8 {
        while input_index <= last_fast_index {
            let input_chunk = BigEndian::read_u64(&input[input_index..(input_index + 8)]);

            // strip off 6 bits at a time for the first 6 bytes
            unsafe {
                std::ptr::write(output_ptr, charset[((input_chunk >> 58) & 0x3F) as usize]);
                std::ptr::write(output_ptr.offset(1), charset[((input_chunk >> 52) & 0x3F) as usize]);
                std::ptr::write(output_ptr.offset(2), charset[((input_chunk >> 46) & 0x3F) as usize]);
                std::ptr::write(output_ptr.offset(3), charset[((input_chunk >> 40) & 0x3F) as usize]);
                std::ptr::write(output_ptr.offset(4), charset[((input_chunk >> 34) & 0x3F) as usize]);
                std::ptr::write(output_ptr.offset(5), charset[((input_chunk >> 28) & 0x3F) as usize]);
                std::ptr::write(output_ptr.offset(6), charset[((input_chunk >> 22) & 0x3F) as usize]);
                std::ptr::write(output_ptr.offset(7), charset[((input_chunk >> 16) & 0x3F) as usize]);
                output_ptr = output_ptr.offset(8);
            }

            input_index += input_chunk_len;
            fast_loop_output_buf_len += 8;
        }
    }

    unsafe {
        // expand len to include the bytes we just wrote
        raw.set_len(fast_loop_output_buf_len);
    }

    // encode the 0 to 7 bytes left after the fast loop

    let rem = input.len() % 3;
    let start_of_rem = input.len() - rem;

    // start at the first index not handled by fast loop, which may be 0.
    let mut leftover_index = input_index;

    while leftover_index < start_of_rem {
        raw.push(charset[(input[leftover_index] >> 2) as usize]);
        raw.push(charset[((input[leftover_index] << 4 | input[leftover_index + 1] >> 4) & 0x3f) as usize]);
        raw.push(charset[((input[leftover_index + 1] << 2 | input[leftover_index + 2] >> 6) & 0x3f) as usize]);
        raw.push(charset[(input[leftover_index + 2] & 0x3f) as usize]);

        leftover_index += 3;
    }

    if rem == 2 {
        raw.push(charset[(input[start_of_rem] >> 2) as usize]);
        raw.push(charset[((input[start_of_rem] << 4 | input[start_of_rem + 1] >> 4) & 0x3f) as usize]);
        raw.push(charset[(input[start_of_rem + 1] << 2 & 0x3f) as usize]);
    } else if rem == 1 {
        raw.push(charset[(input[start_of_rem] >> 2) as usize]);
        raw.push(charset[(input[start_of_rem] << 4 & 0x3f) as usize]);
    }

    if config.pad {
        for _ in 0..((3 - rem) % 3) {
            raw.push(0x3d);
        }
    }

    if config.line_size.is_some() && config.line_size.unwrap() > 0 {
        let line_size = config.line_size.unwrap();
        let len = raw.len();
        let mut i = 0;
        let mut j = 0;

        while i < len {
            if i > 0 && i % line_size == 0 {
                match config.line_ending {
                    LineEnding::LF => { raw.insert(j, b'\n'); j += 1; }
                    LineEnding::CRLF => { raw.insert(j, b'\r'); raw.insert(j + 1, b'\n'); j += 2; }
                }
            }

            i += 1;
            j += 1;
        }
    }
}

///Decode from string reference as octets.
///Returns a Result containing a Vec<u8>.
///
///# Example
///
///```rust
///extern crate base64;
///
///fn main() {
///    let bytes = base64::decode_config("aGVsbG8gd29ybGR+Cg==", base64::STANDARD).unwrap();
///    println!("{:?}", bytes);
///
///    let bytes_url = base64::decode_config("aGVsbG8gaW50ZXJuZXR-Cg==", base64::URL_SAFE).unwrap();
///    println!("{:?}", bytes_url);
///}
///```
pub fn decode_config<T: ?Sized + AsRef<[u8]>>(input: &T, config: Config) -> Result<Vec<u8>, DecodeError> {
    let mut buffer = Vec::<u8>::with_capacity(input.as_ref().len() * 4 / 3);

    decode_config_buf(input, config, &mut buffer).map(|_| buffer)
}

///Decode from string reference as octets.
///Writes into the supplied buffer to avoid allocation.
///Returns a Result containing an empty tuple, aka ().
///
///# Example
///
///```rust
///extern crate base64;
///
///fn main() {
///    let mut buffer = Vec::<u8>::new();
///    base64::decode_config_buf("aGVsbG8gd29ybGR+Cg==", base64::STANDARD, &mut buffer).unwrap();
///    println!("{:?}", buffer);
///
///    buffer.clear();
///
///    base64::decode_config_buf("aGVsbG8gaW50ZXJuZXR-Cg==", base64::URL_SAFE, &mut buffer).unwrap();
///    println!("{:?}", buffer);
///}
///```
pub fn decode_config_buf<T: ?Sized + AsRef<[u8]>>(input: &T,
                                                  config: Config,
                                                  buffer: &mut Vec<u8>)
                                                  -> Result<(), DecodeError> {
    let mut input_copy;
    let input_bytes = if config.strip_whitespace {
        input_copy = Vec::<u8>::with_capacity(input.as_ref().len());
        input_copy.extend(input.as_ref().iter().filter(|b| !b" \n\t\r\x0c".contains(b)));

        input_copy.as_ref()
    } else {
        input.as_ref()
    };

    let ref decode_table = match config.char_set {
        CharacterSet::Standard => tables::STANDARD_DECODE,
        CharacterSet::UrlSafe => tables::URL_SAFE_DECODE,
    };

    buffer.reserve(input_bytes.len() * 3 / 4);

    // the fast loop only handles complete chunks of 8 input bytes without padding
    let chunk_len = 8;
    let decoded_chunk_len = 6;
    let remainder_len = input_bytes.len() % chunk_len;
    let trailing_bytes_to_skip = if remainder_len == 0 {
        // if input is a multiple of the chunk size, ignore the last chunk as it may have padding
        chunk_len
    } else {
        remainder_len
    };

    let length_of_full_chunks = input_bytes.len().saturating_sub(trailing_bytes_to_skip);

    let starting_output_index = buffer.len();
    // Resize to hold decoded output from fast loop. Need the extra two bytes because
    // we write a full 8 bytes for the last 6-byte decoded chunk and then truncate off two
    let new_size = starting_output_index
        + length_of_full_chunks / chunk_len * decoded_chunk_len
        + (chunk_len - decoded_chunk_len);
    buffer.resize(new_size, 0);

    let mut output_index = starting_output_index;

    {
        let buffer_slice = buffer.as_mut_slice();

        let mut input_index = 0;
        // initial value is never used; always set if fast loop breaks
        let mut bad_byte_index: usize = 0;
        // a non-invalid value means it's not an error if fast loop never runs
        let mut morsel: u8 = 0;

        // fast loop of 8 bytes at a time
        while input_index < length_of_full_chunks {
            let mut accum: u64;

            let input_chunk = BigEndian::read_u64(&input_bytes[input_index..(input_index + 8)]);
            morsel = decode_table[(input_chunk >> 56) as usize];
            if morsel == tables::INVALID_VALUE {
                bad_byte_index = input_index;
                break;
            };
            accum = (morsel as u64) << 58;

            morsel = decode_table[(input_chunk >> 48 & 0xFF) as usize];
            if morsel == tables::INVALID_VALUE {
                bad_byte_index = input_index + 1;
                break;
            };
            accum |= (morsel as u64) << 52;

            morsel = decode_table[(input_chunk >> 40 & 0xFF) as usize];
            if morsel == tables::INVALID_VALUE {
                bad_byte_index = input_index + 2;
                break;
            };
            accum |= (morsel as u64) << 46;

            morsel = decode_table[(input_chunk >> 32 & 0xFF) as usize];
            if morsel == tables::INVALID_VALUE {
                bad_byte_index = input_index + 3;
                break;
            };
            accum |= (morsel as u64) << 40;

            morsel = decode_table[(input_chunk >> 24 & 0xFF) as usize];
            if morsel == tables::INVALID_VALUE {
                bad_byte_index = input_index + 4;
                break;
            };
            accum |= (morsel as u64) << 34;

            morsel = decode_table[(input_chunk >> 16 & 0xFF) as usize];
            if morsel == tables::INVALID_VALUE {
                bad_byte_index = input_index + 5;
                break;
            };
            accum |= (morsel as u64) << 28;

            morsel = decode_table[(input_chunk >> 8 & 0xFF) as usize];
            if morsel == tables::INVALID_VALUE {
                bad_byte_index = input_index + 6;
                break;
            };
            accum |= (morsel as u64) << 22;

            morsel = decode_table[(input_chunk & 0xFF) as usize];
            if morsel == tables::INVALID_VALUE {
                bad_byte_index = input_index + 7;
                break;
            };
            accum |= (morsel as u64) << 16;

            BigEndian::write_u64(&mut buffer_slice[(output_index)..(output_index + 8)],
                                 accum);

            output_index += 6;
            input_index += chunk_len;
        };

        if morsel == tables::INVALID_VALUE {
            // we got here from a break
            return Err(DecodeError::InvalidByte(bad_byte_index, input_bytes[bad_byte_index]));
        }
    }

    // Truncate off the last two bytes from writing the last u64.
    // Unconditional because we added on the extra 2 bytes in the resize before the loop,
    // so it will never underflow.
    let new_len = buffer.len() - (chunk_len - decoded_chunk_len);
    buffer.truncate(new_len);

    // handle leftovers (at most 8 bytes, decoded to 6).
    // Use a u64 as a stack-resident 8 bytes buffer.
    let mut leftover_bits: u64 = 0;
    let mut morsels_in_leftover = 0;
    let mut padding_bytes = 0;
    let mut first_padding_index: usize = 0;
    for (i, b) in input_bytes[length_of_full_chunks..].iter().enumerate() {
        // '=' padding
        if *b == 0x3D {
            // There can be bad padding in a few ways:
            // 1 - Padding with non-padding characters after it
            // 2 - Padding after zero or one non-padding characters before it
            //     in the current quad.
            // 3 - More than two characters of padding. If 3 or 4 padding chars
            //     are in the same quad, that implies it will be caught by #2.
            //     If it spreads from one quad to another, it will be caught by
            //     #2 in the second quad.

            if i % 4 < 2 {
                // Check for case #2.
                // TODO InvalidPadding error
                return Err(DecodeError::InvalidByte(length_of_full_chunks + i, *b));
            };

            if padding_bytes == 0 {
                first_padding_index = i;
            };

            padding_bytes += 1;
            continue;
        };

        // Check for case #1.
        // To make '=' handling consistent with the main loop, don't allow
        // non-suffix '=' in trailing chunk either. Report error as first
        // erroneous padding.
        if padding_bytes > 0 {
            return Err(DecodeError::InvalidByte(
                length_of_full_chunks + first_padding_index, 0x3D));
        };

        // can use up to 8 * 6 = 48 bits of the u64, if last chunk has no padding.
        // To minimize shifts, pack the leftovers from left to right.
        let shift = 64 - (morsels_in_leftover + 1) * 6;
        // tables are all 256 elements, cannot overflow from a u8 index
        let morsel = decode_table[*b as usize];
        if morsel == tables::INVALID_VALUE {
            return Err(DecodeError::InvalidByte(length_of_full_chunks + i, *b));
        };

        leftover_bits |= (morsel as u64) << shift;
        morsels_in_leftover += 1;
    };

    let leftover_bits_ready_to_append = match morsels_in_leftover {
        0 => 0,
        1 => return Err(DecodeError::InvalidLength),
        2 => 8,
        3 => 16,
        4 => 24,
        5 => return Err(DecodeError::InvalidLength),
        6 => 32,
        7 => 40,
        8 => 48,
        _ => panic!("Impossible: must only have 0 to 4 input bytes in last quad")
    };

    let mut leftover_bits_appended_to_buf = 0;
    while leftover_bits_appended_to_buf < leftover_bits_ready_to_append {
        // `as` simply truncates the higher bits, which is what we want here
        let selected_bits = (leftover_bits >> (56 - leftover_bits_appended_to_buf)) as u8;
        buffer.push(selected_bits);

        leftover_bits_appended_to_buf += 8;
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{encoded_size, STANDARD, MIME, Config, CharacterSet, LineEnding};

    #[test]
    fn encoded_size_correct() {
        assert_eq!(0, encoded_size(0, STANDARD));

        assert_eq!(4, encoded_size(1, STANDARD));
        assert_eq!(4, encoded_size(2, STANDARD));
        assert_eq!(4, encoded_size(3, STANDARD));

        assert_eq!(8, encoded_size(4, STANDARD));
        assert_eq!(8, encoded_size(5, STANDARD));
        assert_eq!(8, encoded_size(6, STANDARD));

        assert_eq!(12, encoded_size(7, STANDARD));
        assert_eq!(12, encoded_size(8, STANDARD));
        assert_eq!(12, encoded_size(9, STANDARD));

        assert_eq!(72, encoded_size(54, STANDARD));

        assert_eq!(76, encoded_size(55, STANDARD));
        assert_eq!(76, encoded_size(56, STANDARD));
        assert_eq!(76, encoded_size(57, STANDARD));

        assert_eq!(80, encoded_size(58, STANDARD));
    }

    #[test]
    fn encoded_size_correct_mime() {
        assert_eq!(0, encoded_size(0, MIME));

        assert_eq!(4, encoded_size(1, MIME));
        assert_eq!(4, encoded_size(2, MIME));
        assert_eq!(4, encoded_size(3, MIME));

        assert_eq!(8, encoded_size(4, MIME));
        assert_eq!(8, encoded_size(5, MIME));
        assert_eq!(8, encoded_size(6, MIME));

        assert_eq!(12, encoded_size(7, MIME));
        assert_eq!(12, encoded_size(8, MIME));
        assert_eq!(12, encoded_size(9, MIME));

        assert_eq!(72, encoded_size(54, MIME));

        assert_eq!(78, encoded_size(55, MIME));
        assert_eq!(78, encoded_size(56, MIME));
        assert_eq!(78, encoded_size(57, MIME));

        assert_eq!(82, encoded_size(58, MIME));
    }

    #[test]
    fn encoded_size_correct_lf() {
        let config = Config {
            char_set: CharacterSet::Standard,
            pad: true,
            strip_whitespace: false,
            line_size: Some(76),
            line_ending: LineEnding::LF,
        };

        assert_eq!(0, encoded_size(0, config));

        assert_eq!(4, encoded_size(1, config));
        assert_eq!(4, encoded_size(2, config));
        assert_eq!(4, encoded_size(3, config));

        assert_eq!(8, encoded_size(4, config));
        assert_eq!(8, encoded_size(5, config));
        assert_eq!(8, encoded_size(6, config));

        assert_eq!(12, encoded_size(7, config));
        assert_eq!(12, encoded_size(8, config));
        assert_eq!(12, encoded_size(9, config));

        assert_eq!(72, encoded_size(54, config));

        assert_eq!(77, encoded_size(55, config));
        assert_eq!(77, encoded_size(56, config));
        assert_eq!(77, encoded_size(57, config));

        assert_eq!(81, encoded_size(58, config));
    }
}
