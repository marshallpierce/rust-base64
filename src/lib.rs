extern crate byteorder;

use std::{fmt, error, str};

use byteorder::{BigEndian, ByteOrder};

mod tables;

pub enum Base64Mode {
    Standard,
    UrlSafe,
    //TODO MIME
}

#[derive(Debug, PartialEq, Eq)]
pub enum Base64Error {
    Utf8(str::Utf8Error),
    InvalidByte(usize, u8),
    InvalidLength,
}

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Base64Error::Utf8(ref err) => err.fmt(f),
            Base64Error::InvalidByte(index, byte) =>
                write!(f, "Invalid byte {}, offset {}.", byte, index),
            Base64Error::InvalidLength =>
                write!(f, "Encoded text cannot have a 6-bit remainder.")
        }
    }
}

impl error::Error for Base64Error {
    fn description(&self) -> &str {
        match *self {
            Base64Error::Utf8(ref err) => err.description(),
            Base64Error::InvalidByte(_,_) => "invalid byte",
            Base64Error::InvalidLength => "invalid length"
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Base64Error::Utf8(ref err) => Some(err as &error::Error),
            _ => None
        }
    }
}

impl From<str::Utf8Error> for Base64Error {
    fn from(err: str::Utf8Error) -> Base64Error {
        Base64Error::Utf8(err)
    }
}

///Encode arbitrary octets as base64.
///Returns a String.
///Convenience for `encode_mode(input, Base64Mode::Standard);`.
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
    encode_mode(input, Base64Mode::Standard)
}

///Decode from string reference as octets.
///Returns a Result containing a Vec<u8>.
///Convenience `decode_mode(input, Base64Mode::Standard);`.
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
pub fn decode(input: &str) -> Result<Vec<u8>, Base64Error> {
    decode_mode(input, Base64Mode::Standard)
}

///DEPRECATED -- will be replaced by `decode_mode(input, Base64Mode::MIME);`
///
///Decode from string reference as octets.
///Returns a Result containing a Vec<u8>.
///Ignores extraneous whitespace.
///
///# Example
///
///```rust
///extern crate base64;
///
///fn main() {
///    let bytes = base64::decode_ws("aG VsbG8gd2\r\n9ybGQ=").unwrap();
///    println!("{:?}", bytes);
///}
///```
pub fn decode_ws(input: &str) -> Result<Vec<u8>, Base64Error> {
    let mut raw = Vec::<u8>::with_capacity(input.len());
    raw.extend(input.bytes().filter(|b| !b" \n\t\r\x0c".contains(b)));

    let sans_ws = String::from_utf8(raw).unwrap();
    decode_mode(&sans_ws, Base64Mode::Standard)
}

///Encode arbitrary octets as base64.
///Returns a String.
///
///# Example
///
///```rust
///extern crate base64;
///use base64::Base64Mode;
///
///fn main() {
///    let b64 = base64::encode_mode(b"hello world~", Base64Mode::Standard);
///    println!("{}", b64);
///
///    let b64_url = base64::encode_mode(b"hello internet~", Base64Mode::UrlSafe);
///    println!("{}", b64_url);
///}
///```
pub fn encode_mode(bytes: &[u8], mode: Base64Mode) -> String {
    let mut buf = String::with_capacity(encoded_size(bytes.len()));

    encode_mode_buf(bytes, mode, &mut buf);

    buf
}

/// calculate the base64 encoded string size, including padding
fn encoded_size(bytes_len: usize) -> usize {
    let rem = bytes_len % 3;

    let complete_input_chunks = bytes_len / 3;
    let complete_output_chars = complete_input_chunks * 4;
    let leftover_output_chars = if rem == 0 {
        0
    } else {
        4
    };

    return complete_output_chars + leftover_output_chars;
}

///Encode arbitrary octets as base64.
///Writes into the supplied buffer to avoid allocations.
///
///# Example
///
///```rust
///extern crate base64;
///use base64::Base64Mode;
///
///fn main() {
///    let mut buf = String::new();
///    base64::encode_mode_buf(b"hello world~", Base64Mode::Standard, &mut buf);
///    println!("{}", buf);
///
///    buf.clear();
///    base64::encode_mode_buf(b"hello internet~", Base64Mode::UrlSafe, &mut buf);
///    println!("{}", buf);
///}
///```
pub fn encode_mode_buf(input: &[u8], mode: Base64Mode, buf: &mut String) {
    let (ref charset, _) = match mode {
        Base64Mode::Standard => (tables::STANDARD_ENCODE, false),
        Base64Mode::UrlSafe => (tables::URL_SAFE_ENCODE, false),
        //TODO Base64Mode::MIME => (STANDARD, true)
    };

    buf.reserve(encoded_size(input.len()));

    let mut fast_loop_len = buf.len();

    let input_chunk_len = 6;

    let last_fast_index = input.len().saturating_sub(8);

    // we're only going to insert valid utf8
    let mut raw = unsafe { buf.as_mut_vec() };
    // start at the first free part of the output buf
    let mut output_ptr = unsafe { raw.as_mut_ptr().offset(fast_loop_len as isize) };
    let mut input_index = 0;
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
            fast_loop_len += 8;
        }
    }

    unsafe {
        raw.set_len(fast_loop_len);
    }

    let rem = input.len() % 3;
    let end_of_last_triple = input.len() - rem;

    let first_leftover_index = if input_index > 0 {
        // fast loop has run. This will always be a multiple of input_chunk_len.
        // Between 2 (because last 6 bytes were the first of 8) and 7 (if there was
        // 8, fast loop would have run again) bytes left over.
        input_index
    } else {
        0
    };

    let mut leftover_index = first_leftover_index;

    while leftover_index < end_of_last_triple {
        raw.push(charset[(input[leftover_index] >> 2) as usize]);
        raw.push(charset[((input[leftover_index] << 4 | input[leftover_index + 1] >> 4) & 0x3f) as usize]);
        raw.push(charset[((input[leftover_index + 1] << 2 | input[leftover_index + 2] >> 6) & 0x3f) as usize]);
        raw.push(charset[(input[leftover_index + 2] & 0x3f) as usize]);

        leftover_index += 3;
    }

    if rem == 2 {
        raw.push(charset[(input[end_of_last_triple] >> 2) as usize]);
        raw.push(charset[((input[end_of_last_triple] << 4 | input[end_of_last_triple + 1] >> 4) & 0x3f) as usize]);
        raw.push(charset[(input[end_of_last_triple + 1] << 2 & 0x3f) as usize]);
    } else if rem == 1 {
        raw.push(charset[(input[end_of_last_triple] >> 2) as usize]);
        raw.push(charset[(input[end_of_last_triple] << 4 & 0x3f) as usize]);
    }

    for _ in 0..((3 - rem) % 3) {
        raw.push(0x3d);
    }
}

///Decode from string reference as octets.
///Returns a Result containing a Vec<u8>.
///
///# Example
///
///```rust
///extern crate base64;
///use base64::Base64Mode;
///
///fn main() {
///    let bytes = base64::decode_mode("aGVsbG8gd29ybGR+Cg==", Base64Mode::Standard).unwrap();
///    println!("{:?}", bytes);
///
///    let bytes_url = base64::decode_mode("aGVsbG8gaW50ZXJuZXR-Cg==", Base64Mode::UrlSafe).unwrap();
///    println!("{:?}", bytes_url);
///}
///```
pub fn decode_mode(input: &str, mode: Base64Mode) -> Result<Vec<u8>, Base64Error> {
    let mut buffer = Vec::<u8>::with_capacity(input.len() * 4 / 3);

    decode_mode_buf(input, mode, &mut buffer).map(|_| buffer)
}

///Decode from string reference as octets.
///Writes into the supplied buffer to avoid allocation.
///Returns a Result containing an empty tuple, aka ().
///
///# Example
///
///```rust
///extern crate base64;
///use base64::Base64Mode;
///
///fn main() {
///    let mut buffer = Vec::<u8>::new();
///    base64::decode_mode_buf("aGVsbG8gd29ybGR+Cg==", Base64Mode::Standard, &mut buffer).unwrap();
///    println!("{:?}", buffer);
///
///    buffer.clear();
///
///    base64::decode_mode_buf("aGVsbG8gaW50ZXJuZXR-Cg==", Base64Mode::UrlSafe, &mut buffer).unwrap();
///    println!("{:?}", buffer);
///}
///```
pub fn decode_mode_buf(input: &str, mode: Base64Mode, buffer: &mut Vec<u8>) -> Result<(), Base64Error> {
    let (ref decode_table, _) = match mode {
        Base64Mode::Standard => (tables::STANDARD_DECODE, false),
        Base64Mode::UrlSafe => (tables::URL_SAFE_DECODE, false),
        //TODO Base64Mode::MIME => (STANDARD, true)
    };

    buffer.reserve(input.len() * 3 / 4);

    // the fast loop only handles complete chunks of 8 input bytes without padding
    let chunk_len = 8;
    let decoded_chunk_len = 6;
    let remainder_len = input.len() % chunk_len;
    let trailing_bytes_to_skip = if remainder_len == 0 {
        // if input is a multiple of the chunk size, ignore the last chunk as it may have padding
        chunk_len
    } else {
        remainder_len
    };

    let length_of_full_chunks = input.len().saturating_sub(trailing_bytes_to_skip);

    let starting_output_index = buffer.len();
    // Resize to hold decoded output from fast loop. Need the extra two bytes because
    // we write a full 8 bytes for the last 6-byte decoded chunk and then truncate off two
    let new_size = starting_output_index
        + length_of_full_chunks / chunk_len * decoded_chunk_len
        + (chunk_len - decoded_chunk_len);
    buffer.resize(new_size, 0);

    let mut output_index = starting_output_index;

    let input_bytes = input.as_bytes();
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
            return Err(Base64Error::InvalidByte(bad_byte_index, input_bytes[bad_byte_index]));
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
    for (i, b) in input.as_bytes()[length_of_full_chunks..].iter().enumerate() {
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
                return Err(Base64Error::InvalidByte(length_of_full_chunks + i, *b));
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
            return Err(Base64Error::InvalidByte(
                length_of_full_chunks + first_padding_index, 0x3D));
        };

        // can use up to 8 * 6 = 48 bits of the u64, if last chunk has no padding.
        // To minimize shifts, pack the leftovers from left to right.
        let shift = 64 - (morsels_in_leftover + 1) * 6;
        // tables are all 256 elements, cannot overflow from a u8 index
        let morsel = decode_table[*b as usize];
        if morsel == tables::INVALID_VALUE {
            return Err(Base64Error::InvalidByte(length_of_full_chunks + i, *b));
        };

        leftover_bits |= (morsel as u64) << shift;
        morsels_in_leftover += 1;
    };

    let leftover_bits_ready_to_append = match morsels_in_leftover {
        0 => 0,
        1 => return Err(Base64Error::InvalidLength),
        2 => 8,
        3 => 16,
        4 => 24,
        5 => return Err(Base64Error::InvalidLength),
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
    use super::encoded_size;

    #[test]
    fn encoded_size_correct() {
        assert_eq!(0, encoded_size(0));

        assert_eq!(4, encoded_size(1));
        assert_eq!(4, encoded_size(2));
        assert_eq!(4, encoded_size(3));

        assert_eq!(8, encoded_size(4));
        assert_eq!(8, encoded_size(5));
        assert_eq!(8, encoded_size(6));

        assert_eq!(12, encoded_size(7));
        assert_eq!(12, encoded_size(8));
        assert_eq!(12, encoded_size(9));
    }
}
