use std::{fmt, error, string};

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
    let (ref decode_table, _) = match mode {
        Base64Mode::Standard => (decode_tables::STANDARD, false),
        Base64Mode::UrlSafe => (decode_tables::URL_SAFE, false),
        //TODO Base64Mode::MIME => (STANDARD, true)
    };

    let mut buffer = Vec::<u8>::with_capacity(input.len() * 3 / 4);

    // the fast loop only handles complete blocks of 4 input morsels ("quads")
    let quad_rem = input.len() % 4;
    let trailing_bytes_to_skip = if quad_rem == 0 {
        // if input is a multiple of 4, ignore the last quad as it may have padding
        4
    } else {
        quad_rem
    };
    let length_of_full_quads = input.len().saturating_sub(trailing_bytes_to_skip);

    let input_bytes = input.as_bytes();

    let mut i = 0;

    while i < length_of_full_quads {
        // decode tables all hold 256 elements; cannot overflow with a u8.
        // it's not quite a byte; it's a morsel...
        let morsel1 = decode_table[input_bytes[i] as usize];
        let morsel2 = decode_table[input_bytes[i + 1] as usize];
        let morsel3 = decode_table[input_bytes[i + 2] as usize];
        let morsel4 = decode_table[input_bytes[i + 3] as usize];

        // NB: this will detect an inner '=' as an error
        if morsel1 == decode_tables::INVALID_VALUE {
            return Err(Base64Error::InvalidByte(i, input_bytes[i]));
        }
        if morsel2 == decode_tables::INVALID_VALUE {
            return Err(Base64Error::InvalidByte(i + 1, input_bytes[i + 1]));
        }
        if morsel3 == decode_tables::INVALID_VALUE {
            return Err(Base64Error::InvalidByte(i + 2, input_bytes[i + 2]));
        }
        if morsel4 == decode_tables::INVALID_VALUE {
            return Err(Base64Error::InvalidByte(i + 3, input_bytes[i + 3]));
        }

        // bit layout of 3 bytes into 4 morsels:
        // 00111111 00112222 00222233 00333333

        let b1 = morsel1 << 2 | morsel2 >> 4;
        let b2 = morsel2 << 4 | morsel3 >> 2;
        let b3 = morsel3 << 6 | morsel4;

        buffer.push(b1);
        buffer.push(b2);
        buffer.push(b3);
        i+= 4;
    }

    // handle leftovers (at most 4 bytes).
    // Use a u32 as a stack-resident 4-byte Vec.
    let mut leftover_bits: u32 = 0;
    let mut morsels_in_leftover = 0;
    let mut seen_padding = false;
    let mut first_padding_index: usize = 0;
    for (i, b) in input.as_bytes()[length_of_full_quads..].iter().enumerate() {
        // '=' padding
        if *b == 0x3D {
            if !seen_padding {
                seen_padding = true;
                first_padding_index = i;
            }
            continue;
        }

        // to make '=' handling consistent with the main loop, don't allow
        // non-suffix '=' in trailing quad either. Report error as first
        // erroneous padding.
        if seen_padding {
            return Err(Base64Error::InvalidByte(
                length_of_full_quads + first_padding_index, 0x3D));
        }


        // can use up to 4 * 6 = 24 bits of the u32, if last quad has no padding.
        // To minimize shifts, pack the u32 from left to right.
        let shift = 32 - (morsels_in_leftover + 1) * 6;
        // tables are all 256 elements, cannot overflow from a u8 index
        let morsel = decode_table[*b as usize];
        if morsel == decode_tables::INVALID_VALUE {
            return Err(Base64Error::InvalidByte(length_of_full_quads + i, *b));
        }

        leftover_bits |= (morsel as u32) << shift;
        morsels_in_leftover += 1;
    }

    let leftover_bits_ready_to_append = match morsels_in_leftover {
        0 => 0,
        1 => return Err(Base64Error::InvalidLength),
        2 => 8,
        3 => 16,
        4 => 24,
        _ => panic!("Impossible: must only have 0 to 4 input bytes in last quad")
    };

    let mut leftover_bits_appended_to_buf = 0;
    while leftover_bits_appended_to_buf < leftover_bits_ready_to_append {
        // `as` simply truncates the higher bits, which is what we want here
        let selected_bits = (leftover_bits >> (24 - leftover_bits_appended_to_buf)) as u8;
        buffer.push(selected_bits);

        leftover_bits_appended_to_buf += 8;
    }

    Ok(buffer)
}
