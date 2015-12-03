/*
    generic notes for the program
    atob() and btoa() are what we want to copy, perfectly, and nothing else. atob takes ascii, throws immediately if anything else. err. atob takes 0 through 0xff so I can't just assert 0x7f or below or go fuck yourself. assume clean input on that front for now, it's a one- or two-line fix.

    https://html.spec.whatwg.org/multipage/webappapis.html#atob
    https://tools.ietf.org/html/rfc4648#section-4

    random things:
    * Cursor, Seek, and Byte in std::io do what you'd expect. probably unecessary. ideally I'd like to be able to avoid depending on stdlib but I'm not sure what all is in there, like do programs depend on it to do for loops? iteration in general? I dunno. there's libcore but you don't want to use that in non-bare metal rust code. look into it
    * obv I'm using u8 and str for everything
    * b"hello" casts str to u8
    * 65u8 as char does what it says
    * 0x 0b 0o are all normal
    * C-style bitwise ops thank the goddess
    * js implementations of error-checking are untrustworthy, utf16
*/

//use std::collections::FromUtf8Error;

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
enum Base64Error {
    Utf8(collections::string::FromUtf8Error),
    BadChar,
    InvalidLength
}

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Base64Error::Utf8(ref err) => err.fmt(f),
            Base64Error::BadChar => write!(f, "Excuse me this char is bad."),
            Base64Error::InvalidLength => write!(f, "Excuse me the fuck is this.")
        }
    }
}

impl Error for Base64Error {
    fn description(&self) -> &str {
        match *self {
            Base64Error::Utf8(ref err) => err.description(),
            Base64Error::BadChar => "bad char",
            Base64Error::InvalidLength => "length sux"
        }
    }
}

impl From<FromUtf8Error> for Base64Error {
    fn from(err: FromUtf8Error) -> Base64Error {
        Base64::Utf8(err)
    }
}

pub fn atob(input: &str) -> Result<String, Base64Error> {
    let bytes = input.as_bytes();
    let rem = input.len() % 3;
    let div = input.len() - rem;

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

    String::from_utf8(raw)
}

pub fn btoa(input: &str) -> Result<String, Base64Error> {
    let bytes = input.as_bytes();

    //I don't particularly like allocating two vecs but not sure if avoidable
    let mut signif = Vec::<u8>::new();//with_capacity(input.len());

    for (offset, codepoint) in input.char_indices() {
        let c = codepoint as u32;

        if c > 0x40 && c < 0x5b {
            signif.push(bytes[offset] - 0x41);
        } else if c > 0x60 && c < 0x7b {
            signif.push(bytes[offset] - 0x61 + 0x1a);
        } else if c > 0x29 && c < 0x3a {
            signif.push(bytes[offset] - 0x30 + 0x34);
        } else if c == 0x2b {
            signif.push(0x3e);
        } else if c == 0x2f {
            signif.push(0x3f);
        } else if codepoint.is_whitespace() || c == 0x3d {
            ;
        } else {
            //let e = format!("char '{}' at byte offset {}", codepoint, offset);
            return Err(Base64Error::BadChar);
        }
    }

    let rem = signif.len() % 4;

    if rem == 1 {
        panic!("this too");
    }

    let div = signif.len() - rem;
    println!("len: {:?}", signif.len());
    println!("div: {:?}", div);
    println!("rem: {:?}", rem);

    let mut raw = Vec::<u8>::new();//::with_capacity(3*div/4 + rem);
    let mut i = 0;

    while i < div {
        raw.push(signif[i] << 2 | signif[i+1] >> 4);
        raw.push(signif[i+1] << 4 | signif[i+2] >> 2);
        raw.push(signif[i+2] << 6 | signif[i+3]);

        i+=4;
    }

    if rem > 1 {
        raw.push(signif[div] << 2 | signif[div+1] >> 4);
    }
    if rem > 2 {
        raw.push(signif[div+1] << 4 | signif[div+2] >> 2);
    }

    String::from_utf8(raw)
}
