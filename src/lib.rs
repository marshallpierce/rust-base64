use std::{fmt, error, string};
use std::error::Error;
use std::string::FromUtf8Error;

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
    let bytes = input.as_bytes();
    let mut raw = Vec::<u8>::with_capacity(input.len());

    for i in 0..input.len() {
        if !(bytes[i] == 0x20 || bytes[i] == 0x9 || bytes[i] == 0xa ||
        bytes[i] == 0xc || bytes[i] == 0xd) {
            raw.push(bytes[i]);
        }
    }

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
    let bytes = input.as_bytes();
    let bytes_len = bytes.iter().filter(|byte| {**byte != 0x3d}).count();

    let mut bytes = bytes.iter().enumerate().filter_map(|(index, byte)| {
        if byte > &0x40 && byte < &0x5b {
            Some(Ok(byte - &0x41))
        } else if byte > &0x60 && byte < &0x7b {
            Some(Ok(byte - &0x61 + &0x1a))
        } else if byte > &0x2f && byte < &0x3a {
            Some(Ok(byte - &0x30 + &0x34))
        } else if byte == &penult_byte {
            Some(Ok(0x3e))
        } else if byte == &ult_byte {
            Some(Ok(0x3f))
        }  else if byte == &0x3d {
            None
        }
        else {
            Some(Err(Base64Error::InvalidByte(index, *byte)))
        }
    });

    let mut raw = Vec::<u8>::with_capacity((3*bytes_len + 3)/4);
    let mut out_byte:u8;
    loop {
        if let Some(in_byte) = bytes.next() {
            let in_byte = try!(in_byte);
            out_byte = in_byte << 2;
        } else {
            break
        }
        if let Some(in_byte) = bytes.next() {
            let in_byte = try!(in_byte);
            out_byte |= in_byte >> 4;
            raw.push(out_byte);
            out_byte = in_byte << 4;
        } else {
            return Err(Base64Error::InvalidLength)
        }
        if let Some(in_byte) = bytes.next() {
            let in_byte = try!(in_byte);
            out_byte |= in_byte >> 2;
            raw.push(out_byte);
            out_byte = in_byte << 6;
        } else {
            break;
        }
        if let Some(in_byte) = bytes.next() {
            let in_byte = try!(in_byte);
            out_byte |= in_byte;
            raw.push(out_byte);
        } else {
            break;
        }
    }

    Ok(raw)
}
