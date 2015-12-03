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

pub fn atob(input: &str) -> Result<String, std::string::FromUtf8Error> {
    let bytes = input.as_bytes();
    let rem = input.len() % 3;
    let div = input.len() - rem;

    let mut raw = Vec::<u8>::new();
    let mut i = 0;

    while i < div {
        raw.push(bytes[i] >> 2);
        raw.push((bytes[i] << 4) + (bytes[i+1] >> 4) & 0x3f);
        raw.push((bytes[i+1] << 2) + (bytes[i+2] >> 6) & 0x3f);
        raw.push(bytes[i+2] & 0x3f);

        raw.push(bytes[i] >> 2);
        raw.push((bytes[i] << 4) + (bytes[i+1] >> 4) & 0x3f);
        raw.push((bytes[i+1] << 2) + (bytes[i+2] >> 6) & 0x3f);
        raw.push(bytes[i+2] & 0x3f);

        i+=3;
    }

    if rem == 2 {
        raw.push(bytes[div] >> 2);
        raw.push((bytes[div] << 4) + (bytes[div+1] >> 4) & 0x3f);
        raw.push(bytes[div+1] << 2 & 0x3f);
    } else if rem == 1 {
        raw.push(bytes[div] >> 2);
        raw.push(bytes[div] << 4 & 0x3f);
    }

    for i in 0..raw.len() {
        raw[i] = CHARMAP[raw[i] as usize];
    }

    for _ in 0..rem {
        raw.push(0x3d);
    }

    String::from_utf8(raw)
}

    //ok if I have two bytes left I want to push...
    //1111 1111, 1111 1111
    //right shift first byte 2
    //0011 1111
    //left shift the first byte 4...
    //1111 0000
    //...right shift the second byte by 4...
    //0000 1111
    //...add and and 63
    //0011 1111
    //left shift 2 and 63
    //0011 1100
    //fourth byte is =, here aka 64
    //
    //with one byte
    //1111 1111
    //first right shift 2 second left shift 4 and 63
        

    //println!("{:?}\n{:?}", bytes, raw);
