#[cfg(test)]
extern crate base64;

use base64::*;

//-------
//decode

#[test]
fn decode_rfc4648_0() {
    assert_eq!("", decode("").unwrap());
}

#[test]
fn decode_rfc4648_1() {
    assert_eq!("f", decode("Zg==").unwrap());
}

#[test]
fn decode_rfc4648_2() {
    assert_eq!("fo", decode("Zm8=").unwrap());
}

#[test]
fn decode_rfc4648_3() {
    assert_eq!("foo", decode("Zm9v").unwrap());
}

#[test]
fn decode_rfc4648_4() {
    assert_eq!("foob", decode("Zm9vYg==").unwrap());
}

#[test]
fn decode_rfc4648_5() {
    assert_eq!("fooba", decode("Zm9vYmE=").unwrap());
}

#[test]
fn decode_rfc4648_6() {
    assert_eq!("foobar", decode("Zm9vYmFy").unwrap());
}

//this is a MAY in the rfc
#[test]
fn decode_allow_extra_pad() {
    assert_eq!("alice", decode("YWxpY2U=====").unwrap());
}

//same
#[test]
fn decode_allow_absurd_pad() {
    assert_eq!("alice", decode("==Y=Wx===pY=2U=====").unwrap());
}

//TODO like, write a thing to test every ascii val lol
//prolly just yankput the 64 array and a 256 one later
//is there a way to like, not have to write a fn every time
//"hi test harness this should panic 192 times" would be nice
//oh well whatever this is better done by a fuzzer

//strip yr whitespace kids
#[test]
#[should_panic]
fn decode_reject_space() {
    assert!(decode("YWx pY2U=").is_ok());
}

#[test]
#[should_panic]
fn decode_reject_tab() {
    assert!(decode("YWx\tpY2U=").is_ok());
}

#[test]
#[should_panic]
fn decode_reject_nl() {
    assert!(decode("YWx\npY2U=").is_ok());
}

#[test]
#[should_panic]
fn decode_reject_crnl() {
    assert!(decode("YWx\r\npY2U=").is_ok());
}

#[test]
#[should_panic]
fn decode_reject_null() {
    assert!(decode("YWx\0pY2U=").is_ok());
}

//TODO unicode tests
//put in a seperate file so this remains valid ascii

#[test]
fn decode_ws_absurd_whitespace() {
    assert_eq!("how could you let this happen",
        decode_ws("\n aG93I\n\nGNvd\r\nWxkI HlvdSB \tsZXQgdGh\rpcyBo\x0cYXBwZW4 =   ")
        .unwrap());
}

//-------
//encode

#[test]
fn encode_rfc4648_0() {
    assert_eq!(encode("").unwrap(), "");
}

#[test]
fn encode_rfc4648_1() {
    assert_eq!(encode("f").unwrap(), "Zg==");
}

#[test]
fn encode_rfc4648_2() {
    assert_eq!(encode("fo").unwrap(), "Zm8=");
}

#[test]
fn encode_rfc4648_3() {
    assert_eq!(encode("foo").unwrap(), "Zm9v");
}

#[test]
fn encode_rfc4648_4() {
    assert_eq!(encode("foob").unwrap(), "Zm9vYg==");
}

#[test]
fn encode_rfc4648_5() {
    assert_eq!(encode("fooba").unwrap(), "Zm9vYmE=");
}

#[test]
fn encode_rfc4648_6() {
    assert_eq!(encode("foobar").unwrap(), "Zm9vYmFy");
}

#[test]
fn u8en_all_ascii() {
    let mut ascii = Vec::<u8>::with_capacity(128);

    for i in 0..128 {
        ascii.push(i);
    }

    assert!(u8en(&ascii).is_ok());
}

//this doesn't actually overflow lol
#[test]
#[allow(overflowing_literals)]
fn u8en_all_bytes() {
    let mut bytes = Vec::<u8>::with_capacity(256);
    
    for i in 0..256 {
        bytes.push(i);
    }

    assert!(u8en(&bytes).is_ok());
}

#[test]
fn because_we_can() {
    assert_eq!("alice", decode("YWxpY2U=").unwrap());
    assert_eq!("alice", decode(&(encode("alice").unwrap())).unwrap());
    assert_eq!("alice", decode(&(encode(&(decode(&(encode("alice").unwrap())).unwrap())).unwrap())).unwrap());
}
