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

    let mut raw = Vec::<u8>::with_capacity(4*div/3 + if rem == 0 {4} else {0});
    let mut i = 0;

    while i < div {
        raw.push(CHARMAP[(bytes[i] >> 2) as usize]);
        raw.push(CHARMAP[((bytes[i] << 4) + (bytes[i+1] >> 4) & 0x3f) as usize]);
        raw.push(CHARMAP[((bytes[i+1] << 2) + (bytes[i+2] >> 6) & 0x3f) as usize]);
        raw.push(CHARMAP[(bytes[i+2] & 0x3f) as usize]);

        i+=3;
    }

    if rem == 2 {
        raw.push(CHARMAP[(bytes[div] >> 2) as usize]);
        raw.push(CHARMAP[((bytes[div] << 4) + (bytes[div+1] >> 4) & 0x3f) as usize]);
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

pub fn btoa(input: &str) {
    let bytes = input.as_bytes();
    //FIXME I don't really want to allocate twice
    //could do work in the loop, but mixing validation with processing, so not langsec
    //could keep a vec of "offsets to avoid" but that'd overcomplicate
    //whatever whatever finish the damn thing first
    let mut signif = Vec::<u8>::new();//with_capacity(input.len());

    for (offset, codepoint) in input.char_indices() {
        let c = codepoint as u32;

        if (c > 0x40 && c < 0x5b) || (c > 0x60 && c < 0x7b) ||
        (c > 0x29 && c < 0x3a) || c == 0x2b || c == 0x2f {
            signif.push(bytes[offset]);
        } else if codepoint.is_whitespace() || c == 0x3d {
            ;
        } else {
            panic!("change this to error when I add return type");
        }
    }

    let rem = input.len() % 4;

    if rem == 1 {
        panic!("this too");
    }

    let div = signif.len() - rem;

    let mut raw = Vec::<u8>::new();//::with_capacity(3*div/4 + rem);
    let mut i = 0;

    while i < div {
        //FIXME this is horrible
        //change the for loop to have an if for each range
        //and push the indexes to signif rather than do this
        let a = CHARMAP.iter().position(|v| CHARMAP[(*v - 1) as usize] == signif[i]).unwrap() as u8;
        let b = CHARMAP.iter().position(|v| CHARMAP[(*v - 1) as usize] == signif[i+1]).unwrap() as u8;
        let c = CHARMAP.iter().position(|v| CHARMAP[(*v - 1) as usize] == signif[i+2]).unwrap() as u8;
        let d = CHARMAP.iter().position(|v| CHARMAP[(*v - 1) as usize] == signif[i+3]).unwrap() as u8;

        raw.push((a << 2) | (b >> 4));
        raw.push((b << 4) | (c >> 2));
        raw.push(c << 6 | d);

        i+=4;
    }


    println!("len: {:?}", raw.len());
    println!("test!\n{:?}", String::from_utf8(raw));
        
        
    /*
        println!("{}: {}", offset, codepoint);
        println!("whitespace? {}", codepoint.is_whitespace());
        println!("pad? {}", codepoint as u32 == 0x3d);
    */
}

//0011 1111, 0011 1111, 0011 1111, 0011 1111
