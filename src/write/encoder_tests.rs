extern crate rand;

use super::Base64Encoder;
use tests::random_config;
use {encode_config, encode_config_buf, URL_SAFE};

use std::io::{Cursor, Write};
use std::str;

use self::rand::distributions::uniform;
use self::rand::Rng;

#[test]
fn encode_three_bytes() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

        let sz = enc.write(b"abc").unwrap();
        assert_eq!(sz, 3);
    }
    assert_eq!(&c.get_ref()[..], encode_config("abc", URL_SAFE).as_bytes());
}

#[test]
fn encode_nine_bytes_two_writes() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

        let sz = enc.write(b"abcdef").unwrap();
        assert_eq!(sz, 6);
        let sz = enc.write(b"ghi").unwrap();
        assert_eq!(sz, 3);
    }
    assert_eq!(
        &c.get_ref()[..],
        encode_config("abcdefghi", URL_SAFE).as_bytes()
    );
}

#[test]
fn encode_one_then_two_bytes() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

        let sz = enc.write(b"a").unwrap();
        assert_eq!(sz, 1);
        let sz = enc.write(b"bc").unwrap();
        assert_eq!(sz, 2);
    }
    assert_eq!(&c.get_ref()[..], encode_config("abc", URL_SAFE).as_bytes());
}

#[test]
fn encode_one_then_five_bytes() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

        let sz = enc.write(b"a").unwrap();
        assert_eq!(sz, 1);
        let sz = enc.write(b"bcdef").unwrap();
        assert_eq!(sz, 5);
    }
    assert_eq!(
        &c.get_ref()[..],
        encode_config("abcdef", URL_SAFE).as_bytes()
    );
}

#[test]
fn encode_1_2_3_bytes() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

        let sz = enc.write(b"a").unwrap();
        assert_eq!(sz, 1);
        let sz = enc.write(b"bc").unwrap();
        assert_eq!(sz, 2);
        let sz = enc.write(b"def").unwrap();
        assert_eq!(sz, 3);
    }
    assert_eq!(
        &c.get_ref()[..],
        encode_config("abcdef", URL_SAFE).as_bytes()
    );
}

#[test]
fn encode_with_padding() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

        let sz = enc.write(b"abcd").unwrap();
        assert_eq!(sz, 4);

        enc.flush().unwrap();
    }
    assert_eq!(&c.get_ref()[..], encode_config("abcd", URL_SAFE).as_bytes());
}

#[test]
fn encode_with_padding_multiple_writes() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

        let _ = enc.write(b"a").unwrap();
        let _ = enc.write(b"bcd").unwrap();
        let _ = enc.write(b"ef").unwrap();
        let _ = enc.write(b"g").unwrap();

        enc.flush().unwrap();
    }
    assert_eq!(
        &c.get_ref()[..],
        encode_config("abcdefg", URL_SAFE).as_bytes()
    );
}

#[test]
fn finish_writes_extra_byte() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = Base64Encoder::new(&mut c, URL_SAFE);

        assert_eq!(6, enc.write(b"abcdef").unwrap());

        // will be in extra
        assert_eq!(1, enc.write(b"g").unwrap());

        // 1 trailing byte = 2 encoded chars
        let _ = enc.finish().unwrap();
    }
    assert_eq!(
        &c.get_ref()[..],
        encode_config("abcdefg", URL_SAFE).as_bytes()
    );
}

#[test]
fn encode_random_config_matches_normal_encode() {
    let mut rng = rand::thread_rng();
    let mut orig_data = Vec::<u8>::new();
    let mut stream_encoded = Vec::<u8>::new();
    let mut normal_encoded = String::new();
    let line_len_range = uniform::Uniform::new(1, 2000);

    for _ in 0..1_000 {
        orig_data.clear();
        stream_encoded.clear();
        normal_encoded.clear();

        // TODO for now, ignore configs with line wraps
        let mut config = random_config(&mut rng, &line_len_range);
        while let ::LineWrap::Wrap(_, _) = config.line_wrap {
            config = random_config(&mut rng, &line_len_range)
        }

        let orig_len: usize = rng.gen_range(100, 10_000);
        for _ in 0..orig_len {
            orig_data.push(rng.gen());
        }

        // encode the normal way
        encode_config_buf(&orig_data, config, &mut normal_encoded);

        // encode via the stream encoder
        {
            let mut stream_encoder = Base64Encoder::new(&mut stream_encoded, config);
            let mut bytes_consumed = 0;
            while bytes_consumed < orig_len {
                let input_len: usize = rng.gen_range(0, orig_len - bytes_consumed + 1);

                // write a little bit of the data
                bytes_consumed += stream_encoder
                    .write(&orig_data[bytes_consumed..bytes_consumed + input_len])
                    .unwrap();
            }

            // TODO final write should be done by drop()
            stream_encoder.flush().unwrap();

            assert_eq!(orig_len, bytes_consumed);
        }

        assert_eq!(normal_encoded, str::from_utf8(&stream_encoded).unwrap());
    }
}