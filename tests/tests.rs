#[cfg(test)]
extern crate base64;

use base64::*;

fn compare_encode(expected: &str, target: &[u8]) {
    assert_eq!(expected, encode(target));
}

fn compare_decode(expected: &str, target: &str) {
    assert_eq!(expected, String::from_utf8(decode(target).unwrap()).unwrap());
}

fn compare_decode_ws(expected: &str, target: &str) {
    assert_eq!(expected, String::from_utf8(decode_ws(target).unwrap()).unwrap());
}

//-------
//decode

#[test]
fn decode_rfc4648_0() {
    compare_decode("", "");
}

#[test]
fn decode_rfc4648_1() {
    compare_decode("f", "Zg==");
}

#[test]
fn decode_rfc4648_2() {
    compare_decode("fo", "Zm8=");
}

#[test]
fn decode_rfc4648_3() {
    compare_decode("foo", "Zm9v");
}

#[test]
fn decode_rfc4648_4() {
    compare_decode("foob", "Zm9vYg==");
}

#[test]
fn decode_rfc4648_5() {
    compare_decode("fooba", "Zm9vYmE=");
}

#[test]
fn decode_rfc4648_6() {
    compare_decode("foobar", "Zm9vYmFy");
}

//this is a MAY in the rfc
#[test]
fn decode_allow_extra_pad() {
    compare_decode("alice", "YWxpY2U=====");
}

//same
#[test]
fn decode_allow_absurd_pad() {
    compare_decode("alice", "==Y=Wx===pY=2U=====");
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
    compare_decode_ws("how could you let this happen",
        "\n aG93I\n\nGNvd\r\nWxkI HlvdSB \tsZXQgdGh\rpcyBo\x0cYXBwZW4 =   ");
}

//-------
//encode

#[test]
fn encode_rfc4648_0() {
    compare_encode("", b"");
}

#[test]
fn encode_rfc4648_1() {
    compare_encode("Zg==", b"f");
}

#[test]
fn encode_rfc4648_2() {
    compare_encode("Zm8=", b"fo");
}

#[test]
fn encode_rfc4648_3() {
    compare_encode("Zm9v", b"foo");
}

#[test]
fn encode_rfc4648_4() {
    compare_encode("Zm9vYg==", b"foob");
}

#[test]
fn encode_rfc4648_5() {
    compare_encode("Zm9vYmE=", b"fooba");
}

#[test]
fn encode_rfc4648_6() {
    compare_encode("Zm9vYmFy", b"foobar");
}

#[test]
fn encode_all_ascii() {
    let mut ascii = Vec::<u8>::with_capacity(128);

    for i in 0..128 {
        ascii.push(i);
    }

    compare_encode("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8=", &ascii);
}

#[test]
fn encode_all_bytes() {
    let mut bytes = Vec::<u8>::with_capacity(256);
    
    for i in 0..255 {
        bytes.push(i);
    }
    bytes.push(255); //bug with "overflowing" ranges?

    compare_encode("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w==", &bytes);
}

#[test]
fn because_we_can() {
    compare_decode("alice", "YWxpY2U=");
    compare_decode("alice", &encode(b"alice"));
    compare_decode("alice", &encode(&decode(&encode(b"alice")).unwrap()));
}
