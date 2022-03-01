extern crate base64;

use base64::engine::fast_portable::{FastPortable, NO_PAD};
use base64::engine::DEFAULT_ENGINE;
use base64::*;

use self::helpers::*;

mod helpers;

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
fn decode_reject_null() {
    assert_eq!(
        DecodeError::InvalidByte(3, 0x0),
        decode_engine("YWx\0pY2U==", &DEFAULT_ENGINE).unwrap_err()
    );
}

#[test]
fn decode_imap() {
    assert_eq!(
        decode_engine(b"+,,+", &FastPortable::from(&alphabet::IMAP_MUTF7, NO_PAD),),
        decode_engine(b"+//+", &DEFAULT_ENGINE)
    );
}

#[test]
fn decode_urlsafe() {
    let engine = FastPortable::from(&alphabet::URL_SAFE, NO_PAD);
    let out = decode_engine(
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0\
         -P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn\
         -AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq\
         -wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy\
         8_T19vf4-fr7_P3-_w==",
        &engine,
    )
    .unwrap();
    let mut bytes: Vec<u8> = (0..255).collect();
    bytes.push(255);

    assert_eq!(out, bytes);
}

#[cfg(feature = "avx2")]
mod avx2test {
    use super::*;

    use base64::engine::avx2::{AVX2Config, AVX2Encoder};

    #[test]
    fn decode_long() {
        let engine = AVX2Encoder::from_standard(AVX2Config::new());
        let out = decode_engine(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0\
            BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+Ag\
            YKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHC\
            w8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w==",
            &engine
        ).unwrap();
        println!("{:?}", out);
        for (a, b) in out.iter().enumerate() {
            assert_eq!(a as u8, *b);
        }
    }

    #[test]
    fn decode_long_err() {
        let engine = AVX2Encoder::from_standard(AVX2Config::new());
        let out = decode_engine(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0.P0\
            BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+Ag\
            YKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHC\
            w8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w==",
            &engine
        ).unwrap_err();

        assert_eq!(DecodeError::InvalidByte(83, '.' as u8), out);
    }

    #[test]
    fn decode_reject_null() {
        let engine = AVX2Encoder::from_standard(AVX2Config::new());
        assert_eq!(
            DecodeError::InvalidByte(3, 0x0),
            decode_engine("YWx\0pY2U==", &engine).unwrap_err()
        );
    }

    #[test]
    fn decode_urlsafe() {
        let engine = AVX2Encoder::from_url_safe(AVX2Config::new());
        let out = decode_engine(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0\
             -P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn\
             -AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq\
             -wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy\
             8_T19vf4-fr7_P3-_w==",
             &engine
        ).unwrap();
        let mut bytes: Vec<u8> = (0..255).collect();
        bytes.push(255);

        assert_eq!(out, bytes);
    }
}
