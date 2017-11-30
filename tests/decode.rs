extern crate base64;

use base64::*;

mod helpers;
use helpers::*;

fn compare_decode_mime(expected: &str, target: &str) {
    assert_eq!(
        expected,
        String::from_utf8(decode_config(target, MIME).unwrap()).unwrap()
    );
}

#[test]
fn decode_rfc4648_0() {
    compare_decode("", "");
}

#[test]
fn decode_rfc4648_1() {
    compare_decode("f", "Zg==");
}

#[test]
fn decode_rfc4648_1_just_a_bit_of_padding() {
    // allows less padding than required
    compare_decode("f", "Zg=");
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

#[test]
fn decode_mime_allow_space() {
    assert!(decode_config("YWx pY2U=", MIME).is_ok());
}

#[test]
fn decode_mime_allow_tab() {
    assert!(decode_config("YWx\tpY2U=", MIME).is_ok());
}

#[test]
fn decode_mime_allow_ff() {
    assert!(decode_config("YWx\x0cpY2U=", MIME).is_ok());
}

#[test]
fn decode_mime_allow_vtab() {
    assert!(decode_config("YWx\x0bpY2U=", MIME).is_ok());
}

#[test]
fn decode_mime_allow_nl() {
    assert!(decode_config("YWx\npY2U=", MIME).is_ok());
}

#[test]
fn decode_mime_allow_crnl() {
    assert!(decode_config("YWx\r\npY2U=", MIME).is_ok());
}

#[test]
fn decode_mime_reject_null() {
    assert_eq!(
        DecodeError::InvalidByte(3, 0x0),
        decode_config("YWx\0pY2U=", MIME).unwrap_err()
    );
}

#[test]
fn decode_mime_absurd_whitespace() {
    compare_decode_mime(
        "how could you let this happen",
        "\n aG93I\n\nG\x0bNvd\r\nWxkI HlvdSB \tsZXQgdGh\rpcyBo\x0cYXBwZW4 =   ",
    );
}

//this is a MAY in the rfc: https://tools.ietf.org/html/rfc4648#section-3.3
#[test]
fn decode_pad_inside_fast_loop_chunk_error() {
    for num_quads in 0..25 {
        let mut s: String = std::iter::repeat("ABCD").take(num_quads).collect();
        s.push_str("YWxpY2U=====");

        // since the first 8 bytes are handled in the fast loop, the
        // padding is an error. Could argue that the *next* padding
        // byte is technically the first erroneous one, but reporting
        // that accurately is more complex and probably nobody cares
        assert_eq!(
            DecodeError::InvalidByte(num_quads * 4 + 7, b'='),
            decode(&s).unwrap_err()
        );
    }
}

#[test]
fn decode_extra_pad_after_fast_loop_chunk_error() {
    for num_quads in 0..25 {
        let mut s: String = std::iter::repeat("ABCD").take(num_quads).collect();
        s.push_str("YWxpY2UABB===");

        // first padding byte
        assert_eq!(
            DecodeError::InvalidByte(num_quads * 4 + 10, b'='),
            decode(&s).unwrap_err()
        );
    }
}

#[test]
fn decode_absurd_pad_error() {
    for num_quads in 0..25 {
        let mut s: String = std::iter::repeat("ABCD").take(num_quads).collect();
        s.push_str("==Y=Wx===pY=2U=====");

        // first padding byte
        assert_eq!(
            DecodeError::InvalidByte(num_quads * 4, b'='),
            decode(&s).unwrap_err()
        );
    }
}

#[test]
fn decode_extra_padding_in_trailing_quad_returns_error() {
    for num_quads in 0..25 {
        let mut s: String = std::iter::repeat("ABCD").take(num_quads).collect();
        s.push_str("EEE==");

        // first padding byte -- which would be legal if it was by itself
        assert_eq!(
            DecodeError::InvalidByte(num_quads * 4 + 3, b'='),
            decode(&s).unwrap_err()
        );
    }
}

#[test]
fn decode_extra_padding_in_trailing_quad_2_returns_error() {
    for num_quads in 0..25 {
        let mut s: String = std::iter::repeat("ABCD").take(num_quads).collect();
        s.push_str("EE===");

        // first padding byte -- which would be legal if it was by itself
        assert_eq!(
            DecodeError::InvalidByte(num_quads * 4 + 2, b'='),
            decode(&s).unwrap_err()
        );
    }
}

#[test]
fn decode_start_second_quad_with_padding_returns_error() {
    for num_quads in 0..25 {
        let mut s: String = std::iter::repeat("ABCD").take(num_quads).collect();
        s.push_str("=");

        // first padding byte -- must have two non-padding bytes in a quad
        assert_eq!(
            DecodeError::InvalidByte(num_quads * 4, b'='),
            decode(&s).unwrap_err()
        );

        // two padding bytes -- same
        s.push_str("=");
        assert_eq!(
            DecodeError::InvalidByte(num_quads * 4, b'='),
            decode(&s).unwrap_err()
        );

        s.push_str("=");
        assert_eq!(
            DecodeError::InvalidByte(num_quads * 4, b'='),
            decode(&s).unwrap_err()
        );

        s.push_str("=");
        assert_eq!(
            DecodeError::InvalidByte(num_quads * 4, b'='),
            decode(&s).unwrap_err()
        );
    }
}

#[test]
fn decode_padding_in_last_quad_followed_by_non_padding_returns_error() {
    for num_quads in 0..25 {
        let mut s: String = std::iter::repeat("ABCD").take(num_quads).collect();
        s.push_str("==E");

        // first padding byte -- must have two non-padding bytes in a quad
        assert_eq!(
            DecodeError::InvalidByte(num_quads * 4, b'='),
            decode(&s).unwrap_err()
        );
    }
}

#[test]
fn decode_one_char_in_quad_with_padding_error() {
    for num_quads in 0..25 {
        let mut s: String = std::iter::repeat("ABCD").take(num_quads).collect();
        s.push_str("E=");

        assert_eq!(
            DecodeError::InvalidByte(num_quads * 4 + 1, b'='),
            decode(&s).unwrap_err()
        );

        // more padding doesn't change the error
        s.push_str("=");
        assert_eq!(
            DecodeError::InvalidByte(num_quads * 4 + 1, b'='),
            decode(&s).unwrap_err()
        );

        s.push_str("=");
        assert_eq!(
            DecodeError::InvalidByte(num_quads * 4 + 1, b'='),
            decode(&s).unwrap_err()
        );
    }
}

#[test]
fn decode_one_char_in_quad_without_padding_error() {
    for num_quads in 0..25 {
        let mut s: String = std::iter::repeat("ABCD").take(num_quads).collect();
        s.push('E');

        assert_eq!(DecodeError::InvalidLength, decode(&s).unwrap_err());
    }
}

#[test]
fn decode_reject_invalid_bytes_with_correct_error() {
    for length in 1..100 {
        for index in 0_usize..length {
            for invalid_byte in " \t\n\r\x0C\x0B\x00%*.".bytes() {
                let prefix: String = std::iter::repeat("A").take(index).collect();
                let suffix: String = std::iter::repeat("B").take(length - index - 1).collect();

                let input = prefix + &String::from_utf8(vec![invalid_byte]).unwrap() + &suffix;
                assert_eq!(
                    length,
                    input.len(),
                    "length {} error position {}",
                    length,
                    index
                );

                assert_eq!(
                    DecodeError::InvalidByte(index, invalid_byte),
                    decode(&input).unwrap_err()
                );
            }
        }
    }
}
