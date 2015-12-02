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

pub fn atob(input: &str) /*-> &str*/ {
    //TODO check latin1 here
    //wait actually is that even possi
    //come on of course it is rust has to provide a back door into its own abstraction

    let bytes = input.as_bytes();
    let pad = input.len() % 3;
    let block_len = input.len() - pad;

    let mut output = Vec::<u8>::new();
    let mut i = 0;

    //FIXME this is kind of silly
    //also those lets are probably all allocations which, do not want
    //but I reaaally don't want to just make bytes a [u32] like an asshole
    while i < block_len {
        let a0 = (bytes[i] as u32) << 16;
        let a1 = (bytes[i+1] as u32) << 8;
        let a2 = bytes[i+2] as u32;

        let block: u32 = a0+a1+a2;

        let b0 = block >> 18 & 0x3f;
        let b1 = block >> 12 & 0x3f;
        let b2 = block >> 6 & 0x3f;
        let b3 = block & 0x3f;

        output.push(b0 as u8);
        output.push(b1 as u8);
        output.push(b2 as u8);
        output.push(b3 as u8);

        let x0 = bytes[i] >> 2;
        let x1 = (bytes[i] << 4) + (bytes[i+1] >> 4) & 0x3f;
        let x2 = (bytes[i+1] << 2) + (bytes[i+2] >> 6) & 0x3f;
        let x3 = bytes[i+2] & 0x3f;

        println!("{} {}", b0, x0);
        println!("{} {}", b1, x1);
        println!("{} {}", b2, x2);
        println!("{} {}", b3, x3);

        i+=3;
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
        

    println!("{:?}\n{:?}", bytes, output);
}
