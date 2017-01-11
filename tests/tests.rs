extern crate base64;
extern crate rand;

use rand::Rng;

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

// generate every possible byte string recursively and test encode/decode roundtrip
fn roundtrip_append_recurse(byte_buf: &mut Vec<u8>, str_buf: &mut String, remaining_bytes: usize) {
    let orig_length = byte_buf.len();
    for b in 0..256 {
        byte_buf.push(b as u8);

        if remaining_bytes > 1 {
            roundtrip_append_recurse(byte_buf, str_buf, remaining_bytes - 1)
        } else {
            encode_mode_buf(&byte_buf, Base64Mode::Standard, str_buf);
            let roundtrip_bytes = decode_mode(&str_buf, Base64Mode::Standard).unwrap();
            assert_eq!(*byte_buf, roundtrip_bytes);

            str_buf.clear();

        }

        byte_buf.truncate(orig_length);
    }
}

// generate every possible byte string recursively and test encode/decode roundtrip with
// padding removed
fn roundtrip_append_recurse_strip_padding(byte_buf: &mut Vec<u8>, str_buf: &mut String,
                                          remaining_bytes: usize) {
    let orig_length = byte_buf.len();
    for b in 0..256 {
        byte_buf.push(b as u8);

        if remaining_bytes > 1 {
            roundtrip_append_recurse_strip_padding(byte_buf, str_buf, remaining_bytes - 1)
        } else {
            encode_mode_buf(&byte_buf, Base64Mode::Standard, str_buf);
            {
                let trimmed = str_buf.trim_right_matches('=');
                let roundtrip_bytes = decode_mode(&trimmed, Base64Mode::Standard).unwrap();
                assert_eq!(*byte_buf, roundtrip_bytes);
            }
            str_buf.clear();
        }

        byte_buf.truncate(orig_length);
    }
}

// generate random contents of the specified length and test encode/decode roundtrip
fn roundtrip_random(byte_buf: &mut Vec<u8>, str_buf: &mut String, byte_len: usize,
                    approx_values_per_byte: u8) {
    let num_rounds = calculate_number_of_rounds(byte_len, approx_values_per_byte, 10);
    let mut r = rand::weak_rng();

    for _ in 0..num_rounds {
        byte_buf.clear();
        str_buf.clear();
        while byte_buf.len() < byte_len {
            byte_buf.push(r.gen::<u8>());
        }

        encode_mode_buf(&byte_buf, Base64Mode::Standard, str_buf);
        let roundtrip_bytes = decode_mode(&str_buf, Base64Mode::Standard).unwrap();

        assert_eq!(*byte_buf, roundtrip_bytes);
    }
}

// generate random contents of the specified length and test encode/decode roundtrip
fn roundtrip_random_strip_padding(byte_buf: &mut Vec<u8>, str_buf: &mut String, byte_len: usize,
                    approx_values_per_byte: u8) {
    // let the short ones be short but don't let it get too crazy large
    let num_rounds = calculate_number_of_rounds(byte_len, approx_values_per_byte, 10);
    let mut r = rand::weak_rng();

    for _ in 0..num_rounds {
        byte_buf.clear();
        str_buf.clear();
        while byte_buf.len() < byte_len {
            byte_buf.push(r.gen::<u8>());
        }

        encode_mode_buf(&byte_buf, Base64Mode::Standard, str_buf);
        let trimmed = str_buf.trim_right_matches('=');
        let roundtrip_bytes = decode_mode(&trimmed, Base64Mode::Standard).unwrap();

        assert_eq!(*byte_buf, roundtrip_bytes);
    }
}

fn calculate_number_of_rounds(byte_len: usize, approx_values_per_byte: u8, max: u64) -> u64 {
    // don't overflow
    let mut prod = approx_values_per_byte as u64;

    for i in 0..byte_len {
        if prod > max {
            return max;
        }

        prod = prod.saturating_mul(prod);
    }

    return prod;
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
fn decode_rfc4648_1_no_padding() {
    compare_decode("f", "Zg");
}

#[test]
fn decode_rfc4648_2() {
    compare_decode("fo", "Zm8=");
}

#[test]
fn decode_rfc4648_2_no_padding() {
    compare_decode("fo", "Zm8");
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
fn decode_rfc4648_4_no_padding() {
    compare_decode("foob", "Zm9vYg");
}

#[test]
fn decode_rfc4648_5() {
    compare_decode("fooba", "Zm9vYmE=");
}

#[test]
fn decode_rfc4648_5_no_padding() {
    compare_decode("fooba", "Zm9vYmE");
}

#[test]
fn decode_rfc4648_6() {
    compare_decode("foobar", "Zm9vYmFy");
}

//this is a MAY in the rfc: https://tools.ietf.org/html/rfc4648#section-3.3
#[test]
fn decode_pad_inside_fast_loop_chunk_error() {
    // can't PartialEq Base64Error, so we do this the hard way
    match decode("YWxpY2U=====").unwrap_err() {
        Base64Error::InvalidByte(offset, byte) => {
            // since the first 8 bytes are handled in the fast loop, the
            // padding is an error. Could argue that the *next* padding
            // byte is technically the first erroneous one, but reporting
            // that accurately is more complex and probably nobody cares
            assert_eq!(7, offset);
            assert_eq!(0x3D, byte);
        }
        _ => assert!(false)
    }
}

#[test]
fn decode_extra_pad_after_fast_loop_chunk_error() {
    match decode("YWxpY2UABB===").unwrap_err() {
        Base64Error::InvalidByte(offset, byte) => {
            // extraneous third padding byte
            assert_eq!(12, offset);
            assert_eq!(0x3D, byte);
        }
        _ => assert!(false)
    };
}


//same
#[test]
fn decode_absurd_pad_error() {
    match decode("==Y=Wx===pY=2U=====").unwrap_err() {
        Base64Error::InvalidByte(size, byte) => {
            assert_eq!(0, size);
            assert_eq!(0x3D, byte);
        }
        _ => assert!(false)
    }
}

#[test]
fn decode_starts_with_padding_single_quad_error() {
    match decode("====").unwrap_err() {
        Base64Error::InvalidByte(offset, byte) => {
            // with no real input, first padding byte is bogus
            assert_eq!(0, offset);
            assert_eq!(0x3D, byte);
        }
        _ => assert!(false)
    }
}

#[test]
fn decode_extra_padding_in_trailing_quad_returns_error() {
    match decode("zzz==").unwrap_err() {
        Base64Error::InvalidByte(size, byte) => {
            // first unneeded padding byte
            assert_eq!(4, size);
            assert_eq!(0x3D, byte);
        }
        _ => assert!(false)
    }
}

#[test]
fn decode_extra_padding_in_trailing_quad_2_returns_error() {
    match decode("zz===").unwrap_err() {
        Base64Error::InvalidByte(size, byte) => {
            // first unneeded padding byte
            assert_eq!(4, size);
            assert_eq!(0x3D, byte);
        }
        _ => assert!(false)
    }
}


#[test]
fn decode_start_second_quad_with_padding_returns_error() {
    match decode("zzzz=").unwrap_err() {
        Base64Error::InvalidByte(size, byte) => {
            // first unneeded padding byte
            assert_eq!(4, size);
            assert_eq!(0x3D, byte);
        }
        _ => assert!(false)
    }
}

#[test]
fn decode_padding_in_last_quad_followed_by_non_padding_returns_error() {
    match decode("zzzz==z").unwrap_err() {
        Base64Error::InvalidByte(size, byte) => {
            assert_eq!(4, size);
            assert_eq!(0x3D, byte);
        }
        _ => assert!(false)
    }
}

#[test]
fn decode_too_short_with_padding_error() {
    match decode("z==").unwrap_err() {
        Base64Error::InvalidByte(size, byte) => {
            // first unneeded padding byte
            assert_eq!(1, size);
            assert_eq!(0x3D, byte);
        }
        _ => assert!(false)
    }
}

#[test]
fn decode_too_short_without_padding_error() {
    match decode("z").unwrap_err() {
        Base64Error::InvalidLength => {}
        _ => assert!(false)
    }
}

#[test]
fn decode_too_short_second_quad_without_padding_error() {
    match decode("zzzzX").unwrap_err() {
        Base64Error::InvalidLength => {}
        _ => assert!(false)
    }
}

#[test]
fn roundtrip_random_no_fast_loop() {
    let mut byte_buf: Vec<u8> = Vec::new();
    let mut str_buf = String::new();

    for input_len in 0..9 {
        roundtrip_random(&mut byte_buf, &mut str_buf, input_len, 4);
    }
}

#[test]
fn roundtrip_random_with_fast_loop() {
    let mut byte_buf: Vec<u8> = Vec::new();
    let mut str_buf = String::new();

    for input_len in 9..24 {
        roundtrip_random(&mut byte_buf, &mut str_buf, input_len, 4);
    }
}

#[test]
fn roundtrip_random_no_fast_loop_no_padding() {
    let mut byte_buf: Vec<u8> = Vec::new();
    let mut str_buf = String::new();

    for input_len in 0..9 {
        roundtrip_random_strip_padding(&mut byte_buf, &mut str_buf, input_len, 4);
    }
}

#[test]
fn roundtrip_random_with_fast_loop_no_padding() {
    let mut byte_buf: Vec<u8> = Vec::new();
    let mut str_buf = String::new();

    for input_len in 9..24 {
        roundtrip_random_strip_padding(&mut byte_buf, &mut str_buf, input_len, 4);
    }
}

#[test]
fn roundtrip_all_1_byte() {
    let mut byte_buf: Vec<u8> = Vec::new();
    let mut str_buf = String::new();
    roundtrip_append_recurse(&mut byte_buf, &mut str_buf, 1);
}

#[test]
fn roundtrip_all_1_byte_no_padding() {
    let mut byte_buf: Vec<u8> = Vec::new();
    let mut str_buf = String::new();
    roundtrip_append_recurse_strip_padding(&mut byte_buf, &mut str_buf, 1);
}

#[test]
fn roundtrip_all_2_byte() {
    let mut byte_buf: Vec<u8> = Vec::new();
    let mut str_buf = String::new();
    roundtrip_append_recurse(&mut byte_buf, &mut str_buf, 2);
}

#[test]
fn roundtrip_all_2_byte_no_padding() {
    let mut byte_buf: Vec<u8> = Vec::new();
    let mut str_buf = String::new();
    roundtrip_append_recurse_strip_padding(&mut byte_buf, &mut str_buf, 2);
}

#[test]
fn roundtrip_all_3_byte() {
    let mut byte_buf: Vec<u8> = Vec::new();
    let mut str_buf = String::new();
    roundtrip_append_recurse(&mut byte_buf, &mut str_buf, 3);
}

#[test]
fn roundtrip_random_4_byte() {
    let mut byte_buf: Vec<u8> = Vec::new();
    let mut str_buf = String::new();

    roundtrip_random(&mut byte_buf, &mut str_buf, 4, 48);
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
fn encode_all_bytes_url() {
    let mut bytes = Vec::<u8>::with_capacity(256);
    
    for i in 0..255 {
        bytes.push(i);
    }
    bytes.push(255); //bug with "overflowing" ranges?

    assert_eq!("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w==", encode_mode(&bytes, Base64Mode::UrlSafe));
}

#[test]
fn because_we_can() {
    compare_decode("alice", "YWxpY2U=");
    compare_decode("alice", &encode(b"alice"));
    compare_decode("alice", &encode(&decode(&encode(b"alice")).unwrap()));
}
