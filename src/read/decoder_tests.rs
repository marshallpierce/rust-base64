use std::io::{self, Read};

use rand::{Rng, RngCore};
use std::iter;

use super::decoder::{DecoderReader, BUF_SIZE};
use crate::encode::encode_config_buf;
use crate::tests::random_config;
use crate::STANDARD;

#[test]
fn simple() {
    let tests: &[(&[u8], &[u8])] = &[
        (&b"0"[..], &b"MA=="[..]),
        (b"01", b"MDE="),
        (b"012", b"MDEy"),
        (b"0123", b"MDEyMw=="),
        (b"01234", b"MDEyMzQ="),
        (b"012345", b"MDEyMzQ1"),
        (b"0123456", b"MDEyMzQ1Ng=="),
        (b"01234567", b"MDEyMzQ1Njc="),
        (b"012345678", b"MDEyMzQ1Njc4"),
        (b"0123456789", b"MDEyMzQ1Njc4OQ=="),
    ][..];

    for (text_expected, base64data) in tests.iter() {
        // Read n bytes at a time.
        for n in 1..base64data.len() + 1 {
            let mut wrapped_reader = io::Cursor::new(base64data);
            let mut decoder = DecoderReader::new(&mut wrapped_reader, STANDARD);

            // handle errors as you normally would
            let mut text_got = Vec::new();
            let mut buffer = vec![0u8; n];
            while let Ok(read) = decoder.read(&mut buffer[..]) {
                if read == 0 {
                    break;
                }
                text_got.extend_from_slice(&buffer[..read]);
            }

            assert_eq!(
                text_got,
                *text_expected,
                "\nGot: {}\nExpected: {}",
                String::from_utf8_lossy(&text_got[..]),
                String::from_utf8_lossy(text_expected)
            );
        }
    }
}

#[test]
fn big() {
    let mut rng = rand::thread_rng();

    for _ in 0..100 {
        // The size.  Not even multiples of BUF_SIZE.
        let size = rng.gen_range(0, 10 * BUF_SIZE);

        // Create the random content.
        let mut data_orig = Vec::with_capacity(size);
        for _ in 0..size {
            data_orig.push(rng.gen());
        }

        let config = random_config(&mut rng);

        // Encode it.
        let mut encoded = String::new();
        encode_config_buf(&data_orig, config, &mut encoded);

        // Amount to read at a time: small, medium, large and XL.
        for &n in &[
            rng.gen_range(1, 10),
            rng.gen_range(1, 100),
            rng.gen_range(1, BUF_SIZE),
            BUF_SIZE + 1,
        ] {
            let mut wrapped_reader = io::Cursor::new(encoded.clone());
            let mut decoder = DecoderReader::new(&mut wrapped_reader, config);

            let mut data_got = Vec::new();
            let mut buffer = vec![0u8; n];
            while let Ok(read) = decoder.read(&mut buffer[..]) {
                if read == 0 {
                    break;
                }
                data_got.extend_from_slice(&buffer[..read]);
            }

            if data_got != data_orig {
                panic!(
                    "\nGot: {}\nExpected: {}",
                    String::from_utf8_lossy(&data_got[..]),
                    String::from_utf8_lossy(&data_orig[..])
                );
            }
        }
    }
}

// Make sure we error out on trailing junk.
#[test]
fn trailing_junk() {
    let tests: &[&[u8]] = &[&b"MDEyMzQ1Njc4*!@#$%^&"[..], b"MDEyMzQ1Njc4OQ== "][..];

    for base64data in tests.iter() {
        // Read n bytes at a time.
        for n in 1..base64data.len() + 1 {
            let mut wrapped_reader = io::Cursor::new(base64data);
            let mut decoder = DecoderReader::new(&mut wrapped_reader, STANDARD);

            // handle errors as you normally would
            let mut buffer = vec![0u8; n];
            let mut saw_error = false;
            loop {
                match decoder.read(&mut buffer[..]) {
                    Err(_) => saw_error = true,
                    Ok(read) if read == 0 => break,
                    Ok(_) => (),
                }
            }

            assert!(saw_error);
        }
    }
}

#[test]
fn handles_short_read() {
    let mut rng = rand::thread_rng();
    let mut bytes = Vec::new();
    let mut b64 = String::new();
    let mut decoded = Vec::new();

    for _ in 0..10_000 {
        bytes.clear();
        b64.clear();
        decoded.clear();

        let size = rng.gen_range(0, 10 * BUF_SIZE);
        bytes.extend(iter::repeat(0).take(size));
        bytes.truncate(size);
        rng.fill_bytes(&mut bytes[..size]);
        assert_eq!(size, bytes.len());

        let config = random_config(&mut rng);
        encode_config_buf(&bytes[..], config, &mut b64);

        let mut wrapped_reader = io::Cursor::new(b64.as_bytes());
        let mut short_reader = RandomShortRead {
            delegate: &mut wrapped_reader,
            rng: &mut rng,
        };

        let mut decoder = DecoderReader::new(&mut short_reader, config);

        let decoded_len = decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(size, decoded_len);
        assert_eq!(&bytes[..], &decoded[..]);

    }
}

// exercise code that depends on
struct RandomShortRead<'a, 'b, R: io::Read, N: rand::Rng> {
    delegate: &'b mut R,
    rng: &'a mut N,
}

impl<'a, 'b, R: io::Read, N: rand::Rng> io::Read for RandomShortRead<'a, 'b, R, N> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let effective_len = self.rng.gen_range(0, 20);
        println!("buf {} effective {}", buf.len(), effective_len);

        self.delegate.read(&mut buf[..effective_len])
    }
}
