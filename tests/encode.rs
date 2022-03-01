extern crate base64;

use base64::alphabet::URL_SAFE;
use base64::engine::fast_portable::{NO_PAD, PAD};
use base64::*;

#[cfg(not(feature = "avx2"))]
fn compare_encode(expected: &str, target: &[u8]) {
    assert_eq!(expected, encode(target));
}

#[cfg(feature = "avx2")]
fn compare_encode(expected: &str, target: &[u8]) {
    assert_eq!(expected, encode(target));

    use base64::engine::avx2::{AVX2Config, AVX2Encoder};
    let engine: AVX2Encoder = AVX2Encoder::from_standard(AVX2Config::new());

    assert_eq!(expected, encode_engine(target, &engine));
}

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

    compare_encode(
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7P\
         D0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8\
         =",
        &ascii,
    );
}

#[test]
fn encode_all_bytes() {
    let mut bytes = Vec::<u8>::with_capacity(256);

    for i in 0..255 {
        bytes.push(i);
    }
    bytes.push(255); //bug with "overflowing" ranges?

    compare_encode(
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7P\
         D0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn\
         +AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6\
         /wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w==",
        &bytes,
    );
}

#[test]
fn encode_all_bytes_url() {
    let mut bytes = Vec::<u8>::with_capacity(256);

    for i in 0..255 {
        bytes.push(i);
    }
    bytes.push(255); //bug with "overflowing" ranges?

    assert_eq!(
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0\
         -P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn\
         -AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq\
         -wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy\
         8_T19vf4-fr7_P3-_w==",
        encode_engine(
            &bytes,
            &engine::fast_portable::FastPortable::from(&URL_SAFE, PAD)
        )
    );
}

#[test]
fn encode_url_safe_without_padding() {
    let encoded = encode_engine(
        b"alice",
        &engine::fast_portable::FastPortable::from(&URL_SAFE, NO_PAD),
    );
    assert_eq!(&encoded, "YWxpY2U");
    assert_eq!(
        String::from_utf8(decode(&encoded).unwrap()).unwrap(),
        "alice"
    );
}

#[cfg(feature = "avx2")]
mod avx2tests {
    use super::*;

    use base64::engine::avx2::{AVX2Config, AVX2Encoder};

    #[test]
    fn encode_all_bytes_url() {
        let engine: AVX2Encoder = AVX2Encoder::from_url_safe(AVX2Config::new());
        let mut bytes = Vec::<u8>::with_capacity(256);

        for i in 0..255 {
            bytes.push(i);
        }
        bytes.push(255); //bug with "overflowing" ranges?

        assert_eq!(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0\
             -P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn\
             -AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq\
             -wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy\
             8_T19vf4-fr7_P3-_w==",
            encode_engine(
                &bytes,
                &engine
            )
        );
    }
}
