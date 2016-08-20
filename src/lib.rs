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
    let (ref charset, _) = match mode {
        Base64Mode::Standard => (STANDARD, false),
        Base64Mode::UrlSafe => (URL_SAFE, false),
        //TODO Base64Mode::MIME => (STANDARD, true)
    };

    let rem = bytes.len() % 3;
    let div = bytes.len() - rem;

    let mut raw = Vec::<u8>::with_capacity(4*div/3 + if rem == 0 {4} else {0});
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

    //this should never panic, all bytes from charset so always valid ascii
    String::from_utf8(raw).unwrap()
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
    let (ref charset, _) = match mode {
        Base64Mode::Standard => (STANDARD, false),
        Base64Mode::UrlSafe => (URL_SAFE, false),
        //TODO Base64Mode::MIME => (STANDARD, true)
    };

    let (penult_byte, ult_byte) = (charset[62], charset[63]);

    let mut buffer = Vec::<u8>::with_capacity(input.len());

    for (i, b) in input.bytes().enumerate() {
        if b > 0x40 && b < 0x5b {
            buffer.push(b - 0x41);
        } else if b > 0x60 && b < 0x7b {
            buffer.push(b - 0x61 + 0x1a);
        } else if b > 0x2f && b < 0x3a {
            buffer.push(b - 0x30 + 0x34);
        } else if b == penult_byte {
            buffer.push(0x3e);
        } else if b == ult_byte {
            buffer.push(0x3f);
        } else if b == 0x3d {
            ;
        } else {
            return Err(Base64Error::InvalidByte(i, b));
        }
    }

    let rem = buffer.len() % 4;

    if rem == 1 {
        return Err(Base64Error::InvalidLength);
    }

    let div = buffer.len() - rem;

    let mut raw = Vec::<u8>::with_capacity(3*div/4 + rem);
    let mut i = 0;

    while i < div {
        raw.push(buffer[i] << 2 | buffer[i+1] >> 4);
        raw.push(buffer[i+1] << 4 | buffer[i+2] >> 2);
        raw.push(buffer[i+2] << 6 | buffer[i+3]);

        i+=4;
    }

    if rem > 1 {
        raw.push(buffer[div] << 2 | buffer[div+1] >> 4);
    }
    if rem > 2 {
        raw.push(buffer[div+1] << 4 | buffer[div+2] >> 2);
    }

    Ok(raw)
}
