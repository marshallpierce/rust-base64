use {tables, Config, STANDARD};
use byteorder::{BigEndian, ByteOrder};

use std::{error, fmt, str};

/// Errors that can occur while decoding.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// An invalid byte was found in the input. The offset and offending byte are provided.
    InvalidByte(usize, u8),
    /// The length of the input is invalid.
    InvalidLength,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecodeError::InvalidByte(index, byte) => {
                write!(f, "Invalid byte {}, offset {}.", byte, index)
            }
            DecodeError::InvalidLength => write!(f, "Encoded text cannot have a 6-bit remainder."),
        }
    }
}

impl error::Error for DecodeError {
    fn description(&self) -> &str {
        match *self {
            DecodeError::InvalidByte(_, _) => "invalid byte",
            DecodeError::InvalidLength => "invalid length",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

///Decode from string reference as octets.
///Returns a Result containing a Vec<u8>.
///Convenience `decode_config(input, base64::STANDARD);`.
///
///# Example
///
///```rust
///extern crate base64;
///
///fn main() {
///    let bytes = base64::decode("aGVsbG8gd29ybGQ=").unwrap();
///    println!("{:?}", bytes);
///}
///```
pub fn decode<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<Vec<u8>, DecodeError> {
    decode_config(input, STANDARD)
}

///Decode from string reference as octets.
///Returns a Result containing a Vec<u8>.
///
///# Example
///
///```rust
///extern crate base64;
///
///fn main() {
///    let bytes = base64::decode_config("aGVsbG8gd29ybGR+Cg==", base64::STANDARD).unwrap();
///    println!("{:?}", bytes);
///
///    let bytes_url = base64::decode_config("aGVsbG8gaW50ZXJuZXR-Cg==", base64::URL_SAFE).unwrap();
///    println!("{:?}", bytes_url);
///}
///```
pub fn decode_config<T: ?Sized + AsRef<[u8]>>(
    input: &T,
    config: Config,
) -> Result<Vec<u8>, DecodeError> {
    let mut buffer = Vec::<u8>::with_capacity(input.as_ref().len() * 4 / 3);

    decode_config_buf(input, config, &mut buffer).map(|_| buffer)
}

///Decode from string reference as octets.
///Writes into the supplied buffer to avoid allocation.
///Returns a Result containing an empty tuple, aka ().
///
///# Example
///
///```rust
///extern crate base64;
///
///fn main() {
///    let mut buffer = Vec::<u8>::new();
///    base64::decode_config_buf("aGVsbG8gd29ybGR+Cg==", base64::STANDARD, &mut buffer).unwrap();
///    println!("{:?}", buffer);
///
///    buffer.clear();
///
///    base64::decode_config_buf("aGVsbG8gaW50ZXJuZXR-Cg==", base64::URL_SAFE, &mut buffer)
///        .unwrap();
///    println!("{:?}", buffer);
///}
///```
pub fn decode_config_buf<T: ?Sized + AsRef<[u8]>>(
    input: &T,
    config: Config,
    buffer: &mut Vec<u8>,
) -> Result<(), DecodeError> {
    let mut input_copy;
    let input_bytes = if config.strip_whitespace {
        input_copy = Vec::<u8>::with_capacity(input.as_ref().len());
        input_copy.extend(
            input
                .as_ref()
                .iter()
                .filter(|b| !b" \n\t\r\x0b\x0c".contains(b)),
        );

        input_copy.as_ref()
    } else {
        input.as_ref()
    };

    let decode_table = &config.char_set.decode_table();

    // decode logic operates on chunks of 8 input bytes without padding
    const INPUT_CHUNK_LEN: usize = 8;
    const DECODED_CHUNK_LEN: usize = 6;
    // we read a u64 and write a u64, but a u64 of input only yields 6 bytes of output, so the last
    // 2 bytes of any output u64 should not be counted as written to (but must be available in a
    // slice).
    const DECODED_CHUNK_SUFFIX: usize = 2;

    let remainder_len = input_bytes.len() % INPUT_CHUNK_LEN;

    // Because the fast decode loop writes in groups of 8 bytes (unrolled to
    // CHUNKS_PER_FAST_LOOP_BLOCK times 8 bytes, where possible) and outputs 8 bytes at a time (of
    // which only 6 are valid data), we need to be sure that we stop using the fast decode loop
    // soon enough that there will always be 2 more bytes of valid data written after that loop.
    let trailing_bytes_to_skip = match remainder_len {
        // if input is a multiple of the chunk size, ignore the last chunk as it may have padding,
        // and the fast decode logic cannot handle padding
        0 => INPUT_CHUNK_LEN,
        // 1 and 5 trailing bytes are illegal: can't decode 6 bits of input into a byte
        1 | 5 => return Err(DecodeError::InvalidLength),
        // This will decode to one output byte, which isn't enough to overwrite the 2 extra bytes
        // written by the fast decode loop. So, we have to ignore both these 2 bytes and the
        // previous chunk.
        2 => INPUT_CHUNK_LEN + 2,
        // Everything else is a legal decode len (given that we don't require padding), and will
        // decode to at least 2 bytes of output.
        _ => remainder_len,
    };

    let mut input_index = 0;

    {
        let length_of_fast_decode_chunks = input_bytes.len().saturating_sub(trailing_bytes_to_skip);
        let starting_output_len = buffer.len();
        // Resize to hold decoded output from fast loop. Need the extra two bytes because
        // we write a full 8 bytes for the last 6-byte decoded chunk and then truncate off the last
        // two.
        let fast_decode_len_with_suffix = starting_output_len
            .checked_add(length_of_fast_decode_chunks / INPUT_CHUNK_LEN * DECODED_CHUNK_LEN)
            .and_then(|l| l.checked_add(DECODED_CHUNK_SUFFIX))
            .expect("Overflow when calculating output buffer length");
        buffer.resize(fast_decode_len_with_suffix, 0);

        let mut output_index = 0;
        let buffer_slice = &mut buffer.as_mut_slice()[starting_output_len..];

        // how many u64's of input to handle at a time
        const CHUNKS_PER_FAST_LOOP_BLOCK: usize = 4;
        const INPUT_BLOCK_LEN: usize = CHUNKS_PER_FAST_LOOP_BLOCK * INPUT_CHUNK_LEN;
        // includes the trailing 2 bytes for the final u64 write
        const DECODED_BLOCK_LEN: usize =
            CHUNKS_PER_FAST_LOOP_BLOCK * DECODED_CHUNK_LEN + DECODED_CHUNK_SUFFIX;
        // the start index of the last block of data that is big enough to use the unrolled loop
        let last_block_start_index = length_of_fast_decode_chunks.saturating_sub(INPUT_BLOCK_LEN);

        // Fast loop, stage 1
        // manual unroll to CHUNKS_PER_FAST_LOOP_BLOCK of u64s to amortize slice bounds checks
        if last_block_start_index > 0 {
            while input_index <= last_block_start_index {
                let input_slice = &input_bytes[input_index..(input_index + INPUT_BLOCK_LEN)];
                let output_slice =
                    &mut buffer_slice[output_index..(output_index + DECODED_BLOCK_LEN)];

                decode_chunk(
                    &input_slice[0..],
                    input_index,
                    decode_table,
                    &mut output_slice[0..],
                )?;
                decode_chunk(
                    &input_slice[8..],
                    input_index + 8,
                    decode_table,
                    &mut output_slice[6..],
                )?;
                decode_chunk(
                    &input_slice[16..],
                    input_index + 16,
                    decode_table,
                    &mut output_slice[12..],
                )?;
                decode_chunk(
                    &input_slice[24..],
                    input_index + 24,
                    decode_table,
                    &mut output_slice[18..],
                )?;

                input_index += INPUT_BLOCK_LEN;
                output_index += DECODED_BLOCK_LEN - DECODED_CHUNK_SUFFIX;
            }
        }

        // Fast loop, stage 2 (aka still pretty fast loop)
        // 8 bytes at a time for whatever we didn't do in stage 1.
        while input_index < length_of_fast_decode_chunks {
            decode_chunk(
                &input_bytes[input_index..(input_index + INPUT_CHUNK_LEN)],
                input_index,
                decode_table,
                &mut buffer_slice
                    [output_index..(output_index + DECODED_CHUNK_LEN + DECODED_CHUNK_SUFFIX)],
            )?;

            output_index += DECODED_CHUNK_LEN;
            input_index += INPUT_CHUNK_LEN;
        }
    }

    // Truncate off the last two bytes from writing the last u64.
    // Unconditional because we added on the extra 2 bytes in the resize before the loop,
    // so it will never underflow.
    let len_without_decode_suffix = buffer.len() - DECODED_CHUNK_SUFFIX;
    buffer.truncate(len_without_decode_suffix);

    {
        // Stage 3
        // If input length was such that a chunk had to be deferred until after the fast loop
        // because decoding it would have produced 2 trailing bytes that wouldn't then be
        // overwritten, we decode that chunk here. This way is slower but doesn't write the 2
        // trailing bytes.
        // However, we still need to avoid the last chunk (partial or complete) because it could
        // have padding, so we round up to the next largest chunk, then subtract 1. Subtraction
        // will not underflow because input_index is at most the length of input_bytes.
        let remaining_chunks =
            (input_bytes.len() - input_index + (INPUT_CHUNK_LEN - 1)) / INPUT_CHUNK_LEN;
        let precise_decode_chunks = remaining_chunks.saturating_sub(1);
        for _ in 0..precise_decode_chunks {
            let mut buf = [0_u8; DECODED_CHUNK_LEN];
            decode_chunk_precise(
                &input_bytes[input_index..],
                input_index,
                decode_table,
                &mut buf[..],
            )?;

            buffer.extend_from_slice(&buf);
            input_index += INPUT_CHUNK_LEN;
        }
    }

    // Stage 4
    // Finally, decode any leftovers that aren't a complete input block of 8 bytes.
    // Use a u64 as a stack-resident 8 byte buffer.
    let mut leftover_bits: u64 = 0;
    let mut morsels_in_leftover = 0;
    let mut padding_bytes = 0;
    let mut first_padding_index: usize = 0;
    let start_of_leftovers = input_index;
    for (i, b) in input_bytes[start_of_leftovers..].iter().enumerate() {
        // '=' padding
        if *b == 0x3D {
            // There can be bad padding in a few ways:
            // 1 - Padding with non-padding characters after it
            // 2 - Padding after zero or one non-padding characters before it
            //     in the current quad.
            // 3 - More than two characters of padding. If 3 or 4 padding chars
            //     are in the same quad, that implies it will be caught by #2.
            //     If it spreads from one quad to another, it will be caught by
            //     #2 in the second quad.

            if i % 4 < 2 {
                // Check for case #2.
                let bad_padding_index = start_of_leftovers + if padding_bytes > 0 {
                    // If we've already seen padding, report the first padding index.
                    // This is to be consistent with the faster logic above: it will report an error
                    // on the first padding character (since it doesn't expect to see anything but
                    // actual encoded data).
                    first_padding_index
                } else {
                    // haven't seen padding before, just use where we are now
                    i
                };
                return Err(DecodeError::InvalidByte(bad_padding_index, *b));
            }

            if padding_bytes == 0 {
                first_padding_index = i;
            }

            padding_bytes += 1;
            continue;
        }

        // Check for case #1.
        // To make '=' handling consistent with the main loop, don't allow
        // non-suffix '=' in trailing chunk either. Report error as first
        // erroneous padding.
        if padding_bytes > 0 {
            return Err(DecodeError::InvalidByte(
                start_of_leftovers + first_padding_index,
                0x3D,
            ));
        }

        // can use up to 8 * 6 = 48 bits of the u64, if last chunk has no padding.
        // To minimize shifts, pack the leftovers from left to right.
        let shift = 64 - (morsels_in_leftover + 1) * 6;
        // tables are all 256 elements, lookup with a u8 index always succeeds
        let morsel = decode_table[*b as usize];
        if morsel == tables::INVALID_VALUE {
            return Err(DecodeError::InvalidByte(start_of_leftovers + i, *b));
        };

        leftover_bits |= (morsel as u64) << shift;
        morsels_in_leftover += 1;
    }

    let leftover_bits_ready_to_append = match morsels_in_leftover {
        0 => 0,
        2 => 8,
        3 => 16,
        4 => 24,
        6 => 32,
        7 => 40,
        8 => 48,
        _ => panic!(
            "Impossible: must only have 0 to 8 input bytes in last chunk, with no invalid lengths"
        ),
    };

    let mut leftover_bits_appended_to_buf = 0;
    while leftover_bits_appended_to_buf < leftover_bits_ready_to_append {
        // `as` simply truncates the higher bits, which is what we want here
        let selected_bits = (leftover_bits >> (56 - leftover_bits_appended_to_buf)) as u8;
        buffer.push(selected_bits);

        leftover_bits_appended_to_buf += 8;
    }

    Ok(())
}

/// Decode 8 bytes of input into 6 bytes of output. 8 bytes of output will be written, but only the
/// first 6 of those contain meaningful data.
///
/// `input` is the bytes to decode, of which the first 8 bytes will be processed.
/// `index_at_start_of_input` is the offset in the overall input (used for reporting errors
/// accurately)
/// `decode_table` is the lookup table for the particular base64 alphabet.
/// `output` will have its first 8 bytes overwritten, of which only the first 6 are valid decoded
/// data.
// yes, really inline (worth 30-50% speedup)
#[inline(always)]
fn decode_chunk(
    input: &[u8],
    index_at_start_of_input: usize,
    decode_table: &[u8; 256],
    output: &mut [u8],
) -> Result<(), DecodeError> {
    let mut accum: u64;

    let morsel = decode_table[input[0] as usize];
    if morsel == tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(index_at_start_of_input, input[0]));
    }
    accum = (morsel as u64) << 58;

    let morsel = decode_table[input[1] as usize];
    if morsel == tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(
            index_at_start_of_input + 1,
            input[1],
        ));
    }
    accum |= (morsel as u64) << 52;

    let morsel = decode_table[input[2] as usize];
    if morsel == tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(
            index_at_start_of_input + 2,
            input[2],
        ));
    }
    accum |= (morsel as u64) << 46;

    let morsel = decode_table[input[3] as usize];
    if morsel == tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(
            index_at_start_of_input + 3,
            input[3],
        ));
    }
    accum |= (morsel as u64) << 40;

    let morsel = decode_table[input[4] as usize];
    if morsel == tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(
            index_at_start_of_input + 4,
            input[4],
        ));
    }
    accum |= (morsel as u64) << 34;

    let morsel = decode_table[input[5] as usize];
    if morsel == tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(
            index_at_start_of_input + 5,
            input[5],
        ));
    }
    accum |= (morsel as u64) << 28;

    let morsel = decode_table[input[6] as usize];
    if morsel == tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(
            index_at_start_of_input + 6,
            input[6],
        ));
    }
    accum |= (morsel as u64) << 22;

    let morsel = decode_table[input[7] as usize];
    if morsel == tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(
            index_at_start_of_input + 7,
            input[7],
        ));
    }
    accum |= (morsel as u64) << 16;

    BigEndian::write_u64(output, accum);

    Ok(())
}

/// Decode an 8-byte chunk, but only write the 6 bytes actually decoded instead of including 2
/// trailing garbage bytes.
#[inline]
fn decode_chunk_precise(
    input: &[u8],
    index_at_start_of_input: usize,
    decode_table: &[u8; 256],
    output: &mut [u8],
) -> Result<(), DecodeError> {
    let mut tmp_buf = [0_u8; 8];

    decode_chunk(
        input,
        index_at_start_of_input,
        decode_table,
        &mut tmp_buf[..],
    )?;

    output[0..6].copy_from_slice(&tmp_buf[0..6]);

    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate rand;

    use tests::{assert_encode_sanity, random_config};
    use encode::encode_config_buf;
    use super::*;

    use self::rand::Rng;
    use self::rand::distributions::{IndependentSample, Range};

    #[test]
    fn decode_chunk_precise_writes_only_6_bytes() {
        let input = b"Zm9vYmFy"; // "foobar"
        let mut output = [0_u8, 1, 2, 3, 4, 5, 6, 7];
        decode_chunk_precise(&input[..], 0, tables::STANDARD_DECODE, &mut output).unwrap();
        assert_eq!(&vec![b'f', b'o', b'o', b'b', b'a', b'r', 6, 7], &output);
    }

    #[test]
    fn decode_chunk_writes_8_bytes() {
        let input = b"Zm9vYmFy"; // "foobar"
        let mut output = [0_u8, 1, 2, 3, 4, 5, 6, 7];
        decode_chunk(&input[..], 0, tables::STANDARD_DECODE, &mut output).unwrap();
        assert_eq!(&vec![b'f', b'o', b'o', b'b', b'a', b'r', 0, 0], &output);
    }

    #[test]
    fn decode_into_nonempty_buffer_doesnt_clobber_existing_prefix() {
        let mut orig_data = Vec::new();
        let mut encoded_data = String::new();
        let mut decoded_with_prefix = Vec::new();
        let mut decoded_without_prefix = Vec::new();
        let mut prefix = Vec::new();

        let prefix_len_range = Range::new(0, 1000);
        let input_len_range = Range::new(0, 1000);
        let line_len_range = Range::new(1, 1000);

        let mut rng = rand::weak_rng();

        for _ in 0..10_000 {
            orig_data.clear();
            encoded_data.clear();
            decoded_with_prefix.clear();
            decoded_without_prefix.clear();
            prefix.clear();

            let input_len = input_len_range.ind_sample(&mut rng);

            for _ in 0..input_len {
                orig_data.push(rng.gen());
            }

            let config = random_config(&mut rng, &line_len_range);
            encode_config_buf(&orig_data, config, &mut encoded_data);
            assert_encode_sanity(&encoded_data, &config, input_len);

            let prefix_len = prefix_len_range.ind_sample(&mut rng);

            // fill the buf with a prefix
            for _ in 0..prefix_len {
                prefix.push(rng.gen());
            }

            decoded_with_prefix.resize(prefix_len, 0);
            decoded_with_prefix.copy_from_slice(&prefix);

            // remove line wrapping
            let encoded_no_line_endings: String = encoded_data
                .chars()
                .filter(|&c| c != '\r' && c != '\n')
                .collect();

            // decode into the non-empty buf
            decode_config_buf(&encoded_no_line_endings, config, &mut decoded_with_prefix).unwrap();
            // also decode into the empty buf
            decode_config_buf(
                &encoded_no_line_endings,
                config,
                &mut decoded_without_prefix,
            ).unwrap();

            assert_eq!(
                prefix_len + decoded_without_prefix.len(),
                decoded_with_prefix.len()
            );
            assert_eq!(orig_data, decoded_without_prefix);

            // append plain decode onto prefix
            prefix.append(&mut decoded_without_prefix);

            assert_eq!(prefix, decoded_with_prefix);
        }
    }
}
