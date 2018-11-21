extern crate quickcheck;
extern crate rand;

use super::EncoderWriter;
use {encode_config, encode_config_buf, Config, STANDARD_NO_PAD, URL_SAFE};

use std::io::{Cursor, Write};
use std::{cmp, io};

use self::quickcheck::{QuickCheck, StdThreadGen};
use self::rand::Rng;

#[test]
fn encode_three_bytes() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = EncoderWriter::new(&mut c, URL_SAFE);

        let sz = enc.write(b"abc").unwrap();
        assert_eq!(sz, 3);
    }
    assert_eq!(&c.get_ref()[..], encode_config("abc", URL_SAFE).as_bytes());
}

#[test]
fn encode_nine_bytes_two_writes() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = EncoderWriter::new(&mut c, URL_SAFE);

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
        let mut enc = EncoderWriter::new(&mut c, URL_SAFE);

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
        let mut enc = EncoderWriter::new(&mut c, URL_SAFE);

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
        let mut enc = EncoderWriter::new(&mut c, URL_SAFE);

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
        let mut enc = EncoderWriter::new(&mut c, URL_SAFE);

        enc.write_all(b"abcd").unwrap();

        enc.flush().unwrap();
    }
    assert_eq!(&c.get_ref()[..], encode_config("abcd", URL_SAFE).as_bytes());
}

#[test]
fn encode_with_padding_multiple_writes() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = EncoderWriter::new(&mut c, URL_SAFE);

        assert_eq!(1, enc.write(b"a").unwrap());
        assert_eq!(2, enc.write(b"bc").unwrap());
        assert_eq!(3, enc.write(b"def").unwrap());
        assert_eq!(1, enc.write(b"g").unwrap());

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
        let mut enc = EncoderWriter::new(&mut c, URL_SAFE);

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
fn write_partial_chunk_encodes_partial_chunk() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = EncoderWriter::new(&mut c, STANDARD_NO_PAD);

        // nothing encoded yet
        assert_eq!(2, enc.write(b"ab").unwrap());
        // encoded here
        let _ = enc.finish().unwrap();
    }
    assert_eq!(
        &c.get_ref()[..],
        encode_config("ab", STANDARD_NO_PAD).as_bytes()
    );
    assert_eq!(3, c.get_ref().len());
}

#[test]
fn write_1_chunk_encodes_complete_chunk() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = EncoderWriter::new(&mut c, STANDARD_NO_PAD);

        assert_eq!(3, enc.write(b"abc").unwrap());
        let _ = enc.finish().unwrap();
    }
    assert_eq!(
        &c.get_ref()[..],
        encode_config("abc", STANDARD_NO_PAD).as_bytes()
    );
    assert_eq!(4, c.get_ref().len());
}

#[test]
fn write_1_chunk_and_partial_encodes_only_complete_chunk() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = EncoderWriter::new(&mut c, STANDARD_NO_PAD);

        // "d" not written
        assert_eq!(3, enc.write(b"abcd").unwrap());
        let _ = enc.finish().unwrap();
    }
    assert_eq!(
        &c.get_ref()[..],
        encode_config("abc", STANDARD_NO_PAD).as_bytes()
    );
    assert_eq!(4, c.get_ref().len());
}

#[test]
fn write_2_partials_to_exactly_complete_chunk_encodes_complete_chunk() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = EncoderWriter::new(&mut c, STANDARD_NO_PAD);

        assert_eq!(1, enc.write(b"a").unwrap());
        assert_eq!(2, enc.write(b"bc").unwrap());
        let _ = enc.finish().unwrap();
    }
    assert_eq!(
        &c.get_ref()[..],
        encode_config("abc", STANDARD_NO_PAD).as_bytes()
    );
    assert_eq!(4, c.get_ref().len());
}

#[test]
fn write_partial_then_enough_to_complete_chunk_but_not_complete_another_chunk_encodes_complete_chunk_without_consuming_remaining(
) {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = EncoderWriter::new(&mut c, STANDARD_NO_PAD);

        assert_eq!(1, enc.write(b"a").unwrap());
        // doesn't consume "d"
        assert_eq!(2, enc.write(b"bcd").unwrap());
        let _ = enc.finish().unwrap();
    }
    assert_eq!(
        &c.get_ref()[..],
        encode_config("abc", STANDARD_NO_PAD).as_bytes()
    );
    assert_eq!(4, c.get_ref().len());
}

#[test]
fn write_partial_then_enough_to_complete_chunk_and_another_chunk_encodes_complete_chunks() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = EncoderWriter::new(&mut c, STANDARD_NO_PAD);

        assert_eq!(1, enc.write(b"a").unwrap());
        // completes partial chunk, and another chunk
        assert_eq!(5, enc.write(b"bcdef").unwrap());
        let _ = enc.finish().unwrap();
    }
    assert_eq!(
        &c.get_ref()[..],
        encode_config("abcdef", STANDARD_NO_PAD).as_bytes()
    );
    assert_eq!(8, c.get_ref().len());
}

#[test]
fn write_partial_then_enough_to_complete_chunk_and_another_chunk_and_another_partial_chunk_encodes_only_complete_chunks(
) {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = EncoderWriter::new(&mut c, STANDARD_NO_PAD);

        assert_eq!(1, enc.write(b"a").unwrap());
        // completes partial chunk, and another chunk, with one more partial chunk that's not
        // consumed
        assert_eq!(5, enc.write(b"bcdefe").unwrap());
        let _ = enc.finish().unwrap();
    }
    assert_eq!(
        &c.get_ref()[..],
        encode_config("abcdef", STANDARD_NO_PAD).as_bytes()
    );
    assert_eq!(8, c.get_ref().len());
}

#[test]
fn drop_calls_finish_for_you() {
    let mut c = Cursor::new(Vec::new());
    {
        let mut enc = EncoderWriter::new(&mut c, STANDARD_NO_PAD);
        assert_eq!(1, enc.write(b"a").unwrap());
    }
    assert_eq!(
        &c.get_ref()[..],
        encode_config("a", STANDARD_NO_PAD).as_bytes()
    );
    assert_eq!(2, c.get_ref().len());
}

#[test]
fn every_possible_split_of_input() {
    fn property((input, config): (Vec<u8>, Config)) {
        let mut normal_output = String::new();
        encode_config_buf(&input, config, &mut normal_output);
        let mut stream_output = Vec::new();
        for i in 0..input.len() {
            stream_output.clear();
            {
                let mut stream_encoder = EncoderWriter::new(&mut stream_output, config);
                // Write the first i bytes, then the rest
                stream_encoder.write_all(&input[0..i]).unwrap();
                stream_encoder.write_all(&input[i..]).unwrap();
            }
            assert_eq!(normal_output.as_bytes(), stream_output.as_slice());
        }
    }
    let property: fn((Vec<u8>, Config)) = property;
    QuickCheck::with_gen(StdThreadGen::new(5000))
        .tests(2)
        .quickcheck(property);
}

#[test]
fn qc_encode_matches_normal_encode_reasonable_input_len() {
    // exercise the slower encode/decode routines that operate on shorter buffers more vigorously
    let property: fn((Vec<u8>, Config)) = encode_matches_normal_encode;
    QuickCheck::with_gen(StdThreadGen::new(super::encoder::BUF_SIZE * 2))
        .tests(1000)
        .quickcheck(property);
}

#[test]
fn qc_encode_matches_normal_encode_tiny_input_len() {
    // exercise the slower encode/decode routines that operate on shorter buffers more vigorously
    let property: fn((Vec<u8>, Config)) = encode_matches_normal_encode;
    QuickCheck::with_gen(StdThreadGen::new(10))
        .tests(1000)
        .quickcheck(property);
}

fn encode_matches_normal_encode((input, config): (Vec<u8>, Config)) {
    let mut stream_output = Vec::new();
    let mut normal_output = String::new();
    encode_config_buf(&input, config, &mut normal_output);
    {
        let mut rng = rand::thread_rng();
        let mut stream_encoder = EncoderWriter::new(&mut stream_output, config);
        let mut bytes_consumed = 0;
        while bytes_consumed < input.len() {
            let input_len: usize = cmp::min(rng.gen_range(0, 10), input.len() - bytes_consumed);

            // write a little bit of the data
            stream_encoder
                .write_all(&input[bytes_consumed..bytes_consumed + input_len])
                .unwrap();

            bytes_consumed += input_len;
        }
        stream_encoder.finish().unwrap();
        assert_eq!(input.len(), bytes_consumed);
    }
    assert_eq!(normal_output.as_bytes(), stream_output.as_slice())
}

#[test]
fn retrying_writes_that_error_with_interrupted_works() {
    fn property((input, config): (Vec<u8>, Config)) {
        let mut stream_output = Vec::new();
        let mut normal_output = String::new();
        encode_config_buf(&input, config, &mut normal_output);
        {
            let mut interrupt_rng = rand::thread_rng();
            let mut interrupting_writer = InterruptingWriter {
                w: &mut stream_output,
                rng: &mut interrupt_rng,
                fraction: 0.8,
            };
            let mut rng = rand::thread_rng();
            let mut stream_encoder = EncoderWriter::new(&mut interrupting_writer, config);
            let mut bytes_consumed = 0;
            while bytes_consumed < input.len() {
                let input_len: usize = cmp::min(rng.gen_range(0, 10), input.len() - bytes_consumed);

                // write a little bit of the data
                stream_encoder
                    .write_all(&input[bytes_consumed..bytes_consumed + input_len])
                    .unwrap();

                bytes_consumed += input_len;
            }
            loop {
                let res = stream_encoder.finish();
                match res {
                    Ok(_) => break,
                    Err(e) => match e.kind() {
                        io::ErrorKind::Interrupted => continue,
                        _ => Err(e).unwrap(), // bail
                    },
                }
            }

            assert_eq!(input.len(), bytes_consumed);
        }
        assert_eq!(normal_output.as_bytes(), stream_output.as_slice())
    }
    let property: fn((Vec<u8>, Config)) = property;
    QuickCheck::with_gen(StdThreadGen::new(10))
        .tests(1000)
        .quickcheck(property);
}

/// A `Write` implementation that returns Interrupted some fraction of the time, randomly.
struct InterruptingWriter<'a, W: 'a + Write, R: 'a + Rng> {
    w: &'a mut W,
    rng: &'a mut R,
    /// In [0, 1]. If a random number in [0, 1] is  `<= threshold`, `Write` methods will return
    /// an `Interrupted` error
    fraction: f64,
}

impl<'a, W: Write, R: Rng> Write for InterruptingWriter<'a, W, R> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.rng.gen_range(0.0, 1.0) <= self.fraction {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
        }

        self.w.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.rng.gen_range(0.0, 1.0) <= self.fraction {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
        }

        self.w.flush()
    }
}
