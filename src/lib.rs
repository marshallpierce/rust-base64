use std::{fmt, error, string};
use std::error::Error;
use std::string::FromUtf8Error;

const CHARMAP: [u8; 64] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
    0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
    0x77, 0x78, 0x79, 0x7A, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2B, 0x2F
];

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

pub fn encode(input: &str) -> Result<String, Base64Error> {
    match u8en(input.as_bytes()) {
        Ok(bytes) => Ok(try!(String::from_utf8(bytes))),
        Err(err) => Err(err)
    }
}

pub fn decode(input: &str) -> Result<String, Base64Error> {
    match u8de(input.as_bytes()) {
        Ok(bytes) => Ok(try!(String::from_utf8(bytes))),
        Err(err) => Err(err)
    }
}

pub fn decode_ws(input: &str) -> Result<String, Base64Error> {
    let bytes = input.as_bytes();
    let mut raw = Vec::<u8>::with_capacity(input.len());

    for i in 0..input.len() {
        if !(bytes[i] == 0x20 || bytes[i] == 0x9 || bytes[i] == 0xa ||
        bytes[i] == 0xc || bytes[i] == 0xd) {
            raw.push(bytes[i]);
        }
    }

    match u8de(&raw) {
        Ok(bytes) => Ok(try!(String::from_utf8(bytes))),
        Err(err) => Err(err)
    }
}

pub fn u8en(bytes: &[u8]) -> Result<Vec<u8>, Base64Error> {
    let rem = bytes.len() % 3;
    let div = bytes.len() - rem;

    let mut raw = Vec::<u8>::with_capacity(4*div/3 + if rem == 0 {4} else {0});
    let mut i = 0;

    while i < div {
        raw.push(CHARMAP[(bytes[i] >> 2) as usize]);
        raw.push(CHARMAP[((bytes[i] << 4 | bytes[i+1] >> 4) & 0x3f) as usize]);
        raw.push(CHARMAP[((bytes[i+1] << 2 | bytes[i+2] >> 6) & 0x3f) as usize]);
        raw.push(CHARMAP[(bytes[i+2] & 0x3f) as usize]);

        i+=3;
    }

    if rem == 2 {
        raw.push(CHARMAP[(bytes[div] >> 2) as usize]);
        raw.push(CHARMAP[((bytes[div] << 4 | bytes[div+1] >> 4) & 0x3f) as usize]);
        raw.push(CHARMAP[(bytes[div+1] << 2 & 0x3f) as usize]);
    } else if rem == 1 {
        raw.push(CHARMAP[(bytes[div] >> 2) as usize]);
        raw.push(CHARMAP[(bytes[div] << 4 & 0x3f) as usize]);
    }

    for _ in 0..(3-rem)%3 {
        raw.push(0x3d);
    }

    Ok(raw)
}

pub fn u8de(bytes: &[u8]) -> Result<Vec<u8>, Base64Error> {
    let mut buffer = Vec::<u8>::with_capacity(bytes.len());

    for i in 0..bytes.len() {
        if bytes[i] > 0x40 && bytes[i] < 0x5b {
            buffer.push(bytes[i] - 0x41);
        } else if bytes[i] > 0x60 && bytes[i] < 0x7b {
            buffer.push(bytes[i] - 0x61 + 0x1a);
        } else if bytes[i] > 0x2f && bytes[i] < 0x3a {
            buffer.push(bytes[i] - 0x30 + 0x34);
        } else if bytes[i] == 0x2b {
            buffer.push(0x3e);
        } else if bytes[i] == 0x2f {
            buffer.push(0x3f);
        } else if bytes[i] == 0x3d {
            ;
        } else {
            return Err(Base64Error::InvalidByte(i, bytes[i]));
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
