extern crate byteorder;

use std::{fmt, error, string};

use byteorder::{BigEndian, ByteOrder};

const STANDARD: [u8; 64] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
    0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x78, 0x79, 0x7A, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2B, 0x2F
];

const URL_SAFE: [u8; 64] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
    0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x78, 0x79, 0x7A, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2D, 0x5F
];

mod decode_tables;

pub enum Base64Mode {
    Standard,
    UrlSafe,
    //TODO MIME
}

#[derive(Debug)]
pub enum Base64Error {
    Utf8(string::FromUtf8Error),
    InvalidByte(usize, u8),
    InvalidLength
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

impl From<string::FromUtf8Error> for Base64Error {
    fn from(err: string::FromUtf8Error) -> Base64Error {
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

/// calculate the base64 encoded string size
fn encoded_size(bytes_len: usize) -> usize {
    let rem = bytes_len % 3;
    let div = bytes_len - rem;

    return 4 * div / 3 + if rem == 0 { 4 } else { 0 };
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
pub fn encode_mode_buf(bytes: &[u8], mode: Base64Mode, buf: &mut String) {
    let (ref charset, _) = match mode {
        Base64Mode::Standard => (STANDARD, false),
        Base64Mode::UrlSafe => (URL_SAFE, false),
        //TODO Base64Mode::MIME => (STANDARD, true)
    };

    buf.reserve(encoded_size(bytes.len()));

    let rem = bytes.len() % 3;
    let div = bytes.len() - rem;

    let mut raw: &mut Vec<u8>;

    unsafe {
        // we're only going to insert valid utf8
        raw = buf.as_mut_vec();
    }

    let mut i = 0;

    while i < div {
        raw.push(charset[(bytes[i] >> 2) as usize]);
        raw.push(charset[((bytes[i] << 4 | bytes[i+1] >> 4) & 0x3f) as usize]);
        raw.push(charset[((bytes[i+1] << 2 | bytes[i+2] >> 6) & 0x3f) as usize]);
        raw.push(charset[(bytes[i+2] & 0x3f) as usize]);

        i+=3;
    }

    if rem == 2 {
        raw.push(charset[(bytes[div] >> 2) as usize]);
        raw.push(charset[((bytes[div] << 4 | bytes[div+1] >> 4) & 0x3f) as usize]);
        raw.push(charset[(bytes[div+1] << 2 & 0x3f) as usize]);
    } else if rem == 1 {
        raw.push(charset[(bytes[div] >> 2) as usize]);
        raw.push(charset[(bytes[div] << 4 & 0x3f) as usize]);
    }

    for _ in 0..(3-rem)%3 {
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
        Base64Mode::Standard => (decode_tables::STANDARD, false),
        Base64Mode::UrlSafe => (decode_tables::URL_SAFE, false),
        //TODO Base64Mode::MIME => (STANDARD, true)
    };

    buffer.reserve(input.len() * 3 / 4);

    // the fast loop only handles complete blocks of 8 input morsels
    let chunk_len = std::mem::size_of::<u64>();
    let chunk_rem = input.len() % chunk_len;
    let trailing_bytes_to_skip = if chunk_rem == 0 {
        // if input is a multiple of the chunk size, ignore the last chunk as it may have padding
        chunk_len
    } else {
        chunk_rem
    };
    let length_of_full_chunks = input.len().saturating_sub(trailing_bytes_to_skip);

    // make sure buffer can hold enough for the fast loop
    let starting_index = buffer.len();
    // need the extra two bytes because we write a full 8 bytes for the last chunk
    // and then truncate off two
    buffer.resize(starting_index + length_of_full_chunks / 8 * 6 + 2, 0);

    let mut output_index = starting_index;

    let input_bytes = input.as_bytes();
    {
        let buffer_slice = buffer.as_mut_slice();

        let mut input_index = 0;

        while input_index < length_of_full_chunks {
            let mut accum: u64;

            let input_chunk = BigEndian::read_u64(&input_bytes[input_index..(input_index + 8)]);
            let morsel = decode_table[(input_chunk >> 56) as usize];
            if morsel == decode_tables::INVALID_VALUE {
                return Err(Base64Error::InvalidByte(input_index, (input_chunk >> 56) as u8));
            }
            accum = (morsel as u64) << 58;
            let morsel = decode_table[((input_chunk >> 48) & 0xFF) as usize];
            if morsel == decode_tables::INVALID_VALUE {
                return Err(Base64Error::InvalidByte(input_index + 1, (input_chunk >> 48) as u8));
            }
            accum |= (morsel as u64) << 52;
            let morsel = decode_table[((input_chunk >> 40) & 0xFF) as usize];
            if morsel == decode_tables::INVALID_VALUE {
                return Err(Base64Error::InvalidByte(input_index + 2, (input_chunk >> 40) as u8));
            }
            accum |= (morsel as u64) << 46;
            let morsel = decode_table[((input_chunk >> 32) & 0xFF) as usize];
            if morsel == decode_tables::INVALID_VALUE {
                return Err(Base64Error::InvalidByte(input_index + 3, (input_chunk >> 32) as u8));
            }
            accum |= (morsel as u64) << 40;
            let morsel = decode_table[((input_chunk >> 24) & 0xFF) as usize];
            if morsel == decode_tables::INVALID_VALUE {
                return Err(Base64Error::InvalidByte(input_index + 4, (input_chunk >> 24) as u8));
            }
            accum |= (morsel as u64) << 34;
            let morsel = decode_table[((input_chunk >> 16) & 0xFF) as usize];
            if morsel == decode_tables::INVALID_VALUE {
                return Err(Base64Error::InvalidByte(input_index + 5, (input_chunk >> 16) as u8));
            }
            accum |= (morsel as u64) << 28;
            let morsel = decode_table[((input_chunk >> 8) & 0xFF) as usize];
            if morsel == decode_tables::INVALID_VALUE {
                return Err(Base64Error::InvalidByte(input_index + 6, (input_chunk >> 8) as u8));
            }
            accum |= (morsel as u64) << 22;
            let morsel = decode_table[(input_chunk & 0xFF) as usize];
            if morsel == decode_tables::INVALID_VALUE {
                return Err(Base64Error::InvalidByte(input_index + 7, (input_chunk & 0xFF) as u8));
            }
            accum |= (morsel as u64) << 16;

            BigEndian::write_u64(&mut buffer_slice[(output_index)..(output_index + 8)],
                                 accum);

            output_index += 6;
            input_index += chunk_len;
        };
    }

    // Truncate off the last two bytes from writing the last u64.
    // Unconditional because we added on the extra 2 bytes in the resize before the loop.
    let new_len = buffer.len() - 2;
    buffer.truncate(new_len);

    // handle leftovers (at most 8 bytes).
    // Use a u64 as a stack-resident 8-byte Vec.
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
        if morsel == decode_tables::INVALID_VALUE {
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
