use byteorder::{BigEndian, ByteOrder};
use {CryptAlphabet, CustomConfig, Padding, StdAlphabet, UrlSafeAlphabet, STANDARD};

use std::{error, fmt, str};

// decode logic operates on chunks of 8 input bytes without padding
const INPUT_CHUNK_LEN: usize = 8;
const DECODED_CHUNK_LEN: usize = 6;
// we read a u64 and write a u64, but a u64 of input only yields 6 bytes of output, so the last
// 2 bytes of any output u64 should not be counted as written to (but must be available in a
// slice).
const DECODED_CHUNK_SUFFIX: usize = 2;

// how many u64's of input to handle at a time
const CHUNKS_PER_FAST_LOOP_BLOCK: usize = 4;
const INPUT_BLOCK_LEN: usize = CHUNKS_PER_FAST_LOOP_BLOCK * INPUT_CHUNK_LEN;
// includes the trailing 2 bytes for the final u64 write
const DECODED_BLOCK_LEN: usize =
    CHUNKS_PER_FAST_LOOP_BLOCK * DECODED_CHUNK_LEN + DECODED_CHUNK_SUFFIX;

/// Errors that can occur while decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// An invalid byte was found in the input. The offset and offending byte are provided.
    InvalidByte(usize, u8),
    /// The length of the input is invalid.
    InvalidLength,
    /// The last non-padding input symbol's encoded 6 bits have nonzero bits that will be discarded.
    /// This is indicative of corrupted or truncated Base64.
    /// Unlike InvalidByte, which reports symbols that aren't in the alphabet, this error is for
    /// symbols that are in the alphabet but represent nonsensical encodings.
    InvalidLastSymbol(usize, u8),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecodeError::InvalidByte(index, byte) => {
                write!(f, "Invalid byte {}, offset {}.", byte, index)
            }
            DecodeError::InvalidLength => write!(f, "Encoded text cannot have a 6-bit remainder."),
            DecodeError::InvalidLastSymbol(index, byte) => {
                write!(f, "Invalid last symbol {}, offset {}.", byte, index)
            }
        }
    }
}

impl error::Error for DecodeError {
    fn description(&self) -> &str {
        match *self {
            DecodeError::InvalidByte(_, _) => "invalid byte",
            DecodeError::InvalidLength => "invalid length",
            DecodeError::InvalidLastSymbol(_, _) => "invalid last symbol",
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
pub fn decode_config<T, C>(input: &T, config: C) -> Result<Vec<u8>, DecodeError>
where
    T: ?Sized + AsRef<[u8]>,
    C: Decoding + Padding,
{
    let mut buffer = Vec::<u8>::new();

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
pub fn decode_config_buf<T, C>(
    input: &T,
    config: C,
    buffer: &mut Vec<u8>,
) -> Result<(), DecodeError>
where
    T: ?Sized + AsRef<[u8]>,
    C: Decoding + Padding,
{
    let input_bytes = input.as_ref();

    let starting_output_len = buffer.len();

    let num_chunks = num_chunks(input_bytes);
    let decoded_len_estimate = num_chunks
        .checked_mul(DECODED_CHUNK_LEN)
        .and_then(|p| p.checked_add(starting_output_len))
        .expect("Overflow when calculating output buffer length");
    buffer.resize(decoded_len_estimate, 0);

    let bytes_written;
    {
        let buffer_slice = &mut buffer.as_mut_slice()[starting_output_len..];
        bytes_written = decode_helper(input_bytes, num_chunks, config, buffer_slice)?;
    }

    buffer.truncate(starting_output_len + bytes_written);

    Ok(())
}

/// Decode the input into the provided output slice.
///
/// This will not write any bytes past exactly what is decoded (no stray garbage bytes at the end).
///
/// If you don't know ahead of time what the decoded length should be, size your buffer with a
/// conservative estimate for the decoded length of an input: 3 bytes of output for every 4 bytes of
/// input, rounded up, or in other words `(input_len + 3) / 4 * 3`.
///
/// If the slice is not large enough, this will panic.
pub fn decode_config_slice<T, C>(
    input: &T,
    config: C,
    output: &mut [u8],
) -> Result<usize, DecodeError>
where
    T: ?Sized + AsRef<[u8]>,
    C: Decoding + Padding,
{
    let input_bytes = input.as_ref();

    decode_helper(input_bytes, num_chunks(input_bytes), config, output)
}

/// Return the number of input chunks (including a possibly partial final chunk) in the input
fn num_chunks(input: &[u8]) -> usize {
    input
        .len()
        .checked_add(INPUT_CHUNK_LEN - 1)
        .expect("Overflow when calculating number of chunks in input")
        / INPUT_CHUNK_LEN
}

/// Helper to avoid duplicating num_chunks calculation, which is costly on short inputs.
/// Returns the number of bytes written, or an error.
// We're on the fragile edge of compiler heuristics here. If this is not inlined, slow. If this is
// inlined(always), a different slow. plain ol' inline makes the benchmarks happiest at the moment,
// but this is fragile and the best setting changes with only minor code modifications.
#[inline]
fn decode_helper<C>(
    input: &[u8],
    num_chunks: usize,
    config: C,
    output: &mut [u8],
) -> Result<usize, DecodeError>
where
    C: Decoding + Padding,
{
    let remainder_len = input.len() % INPUT_CHUNK_LEN;

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
        // If this is 3 unpadded chars, then it would actually decode to 2 bytes. However, if this
        // is an erroneous 2 chars + 1 pad char that would decode to 1 byte, then it should fail
        // with an error, not panic from going past the bounds of the output slice, so we let it
        // use stage 3 + 4.
        3 => INPUT_CHUNK_LEN + 3,
        // This can also decode to one output byte because it may be 2 input chars + 2 padding
        // chars, which would decode to 1 byte.
        4 => INPUT_CHUNK_LEN + 4,
        // Everything else is a legal decode len (given that we don't require padding), and will
        // decode to at least 2 bytes of output.
        _ => remainder_len,
    };

    // rounded up to include partial chunks
    let mut remaining_chunks = num_chunks;

    let mut input_index = 0;
    let mut output_index = 0;

    {
        let length_of_fast_decode_chunks = input.len().saturating_sub(trailing_bytes_to_skip);

        // Fast loop, stage 1
        // manual unroll to CHUNKS_PER_FAST_LOOP_BLOCK of u64s to amortize slice bounds checks
        if let Some(max_start_index) = length_of_fast_decode_chunks.checked_sub(INPUT_BLOCK_LEN) {
            while input_index <= max_start_index {
                let input_slice = &input[input_index..(input_index + INPUT_BLOCK_LEN)];
                let output_slice = &mut output[output_index..(output_index + DECODED_BLOCK_LEN)];

                decode_chunk(
                    &input_slice[0..],
                    input_index,
                    config,
                    &mut output_slice[0..],
                )?;
                decode_chunk(
                    &input_slice[8..],
                    input_index + 8,
                    config,
                    &mut output_slice[6..],
                )?;
                decode_chunk(
                    &input_slice[16..],
                    input_index + 16,
                    config,
                    &mut output_slice[12..],
                )?;
                decode_chunk(
                    &input_slice[24..],
                    input_index + 24,
                    config,
                    &mut output_slice[18..],
                )?;

                input_index += INPUT_BLOCK_LEN;
                output_index += DECODED_BLOCK_LEN - DECODED_CHUNK_SUFFIX;
                remaining_chunks -= CHUNKS_PER_FAST_LOOP_BLOCK;
            }
        }

        // Fast loop, stage 2 (aka still pretty fast loop)
        // 8 bytes at a time for whatever we didn't do in stage 1.
        if let Some(max_start_index) = length_of_fast_decode_chunks.checked_sub(INPUT_CHUNK_LEN) {
            while input_index < max_start_index {
                decode_chunk(
                    &input[input_index..(input_index + INPUT_CHUNK_LEN)],
                    input_index,
                    config,
                    &mut output
                        [output_index..(output_index + DECODED_CHUNK_LEN + DECODED_CHUNK_SUFFIX)],
                )?;

                output_index += DECODED_CHUNK_LEN;
                input_index += INPUT_CHUNK_LEN;
                remaining_chunks -= 1;
            }
        }
    }

    // Stage 3
    // If input length was such that a chunk had to be deferred until after the fast loop
    // because decoding it would have produced 2 trailing bytes that wouldn't then be
    // overwritten, we decode that chunk here. This way is slower but doesn't write the 2
    // trailing bytes.
    // However, we still need to avoid the last chunk (partial or complete) because it could
    // have padding, so we always do 1 fewer to avoid the last chunk.
    for _ in 1..remaining_chunks {
        decode_chunk_precise(
            &input[input_index..],
            input_index,
            config,
            &mut output[output_index..(output_index + DECODED_CHUNK_LEN)],
        )?;

        input_index += INPUT_CHUNK_LEN;
        output_index += DECODED_CHUNK_LEN;
    }

    // always have one more (possibly partial) block of 8 input
    debug_assert!(input.len() - input_index > 1 || input.is_empty());
    debug_assert!(input.len() - input_index <= 8);

    // Stage 4
    // Finally, decode any leftovers that aren't a complete input block of 8 bytes.
    // Use a u64 as a stack-resident 8 byte buffer.
    let mut leftover_bits: u64 = 0;
    let mut morsels_in_leftover = 0;
    let mut padding_bytes = 0;
    let mut first_padding_index: usize = 0;
    let mut last_symbol = 0_u8;
    let start_of_leftovers = input_index;
    for (i, b) in input[start_of_leftovers..].iter().enumerate() {
        // '=' padding
        if Some(*b) == config.padding_byte() {
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
                let bad_padding_index = start_of_leftovers
                    + if padding_bytes > 0 {
                        // If we've already seen padding, report the first padding index.
                        // This is to be consistent with the faster logic above: it will report an
                        // error on the first padding character (since it doesn't expect to see
                        // anything but actual encoded data).
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
                config.padding_byte().unwrap(),
            ));
        }
        last_symbol = *b;

        // can use up to 8 * 6 = 48 bits of the u64, if last chunk has no padding.
        // To minimize shifts, pack the leftovers from left to right.
        let shift = 64 - (morsels_in_leftover + 1) * 6;
        // tables are all 256 elements, lookup with a u8 index always succeeds
        let morsel = config.decode_u8(*b);
        if morsel == ::tables::INVALID_VALUE {
            return Err(DecodeError::InvalidByte(start_of_leftovers + i, *b));
        }

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
        _ => unreachable!(
            "Impossible: must only have 0 to 8 input bytes in last chunk, with no invalid lengths"
        ),
    };

    // if there are bits set outside the bits we care about, last symbol encodes trailing bits that
    // will not be included in the output
    let mask = !0 >> leftover_bits_ready_to_append;
    if (leftover_bits & mask) != 0 {
        // last morsel is at `morsels_in_leftover` - 1
        return Err(DecodeError::InvalidLastSymbol(
            start_of_leftovers + morsels_in_leftover - 1,
            last_symbol,
        ));
    }

    let mut leftover_bits_appended_to_buf = 0;
    while leftover_bits_appended_to_buf < leftover_bits_ready_to_append {
        // `as` simply truncates the higher bits, which is what we want here
        let selected_bits = (leftover_bits >> (56 - leftover_bits_appended_to_buf)) as u8;
        output[output_index] = selected_bits;
        output_index += 1;

        leftover_bits_appended_to_buf += 8;
    }

    Ok(output_index)
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
fn decode_chunk<D: Decoding>(
    input: &[u8],
    index_at_start_of_input: usize,
    decoding: D,
    output: &mut [u8],
) -> Result<(), DecodeError> {
    let mut accum: u64;

    let morsel = decoding.decode_u8(input[0]);
    if morsel == ::tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(index_at_start_of_input, input[0]));
    }
    accum = (morsel as u64) << 58;

    let morsel = decoding.decode_u8(input[1]);
    if morsel == ::tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(
            index_at_start_of_input + 1,
            input[1],
        ));
    }
    accum |= (morsel as u64) << 52;

    let morsel = decoding.decode_u8(input[2]);
    if morsel == ::tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(
            index_at_start_of_input + 2,
            input[2],
        ));
    }
    accum |= (morsel as u64) << 46;

    let morsel = decoding.decode_u8(input[3]);
    if morsel == ::tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(
            index_at_start_of_input + 3,
            input[3],
        ));
    }
    accum |= (morsel as u64) << 40;

    let morsel = decoding.decode_u8(input[4]);
    if morsel == ::tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(
            index_at_start_of_input + 4,
            input[4],
        ));
    }
    accum |= (morsel as u64) << 34;

    let morsel = decoding.decode_u8(input[5]);
    if morsel == ::tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(
            index_at_start_of_input + 5,
            input[5],
        ));
    }
    accum |= (morsel as u64) << 28;

    let morsel = decoding.decode_u8(input[6]);
    if morsel == ::tables::INVALID_VALUE {
        return Err(DecodeError::InvalidByte(
            index_at_start_of_input + 6,
            input[6],
        ));
    }
    accum |= (morsel as u64) << 22;

    let morsel = decoding.decode_u8(input[7]);
    if morsel == ::tables::INVALID_VALUE {
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
fn decode_chunk_precise<D: Decoding>(
    input: &[u8],
    index_at_start_of_input: usize,
    decoding: D,
    output: &mut [u8],
) -> Result<(), DecodeError> {
    let mut tmp_buf = [0_u8; 8];

    decode_chunk(input, index_at_start_of_input, decoding, &mut tmp_buf[..])?;

    output[0..6].copy_from_slice(&tmp_buf[0..6]);

    Ok(())
}

#[inline]
fn decode_by_table(input: u8, decode_table: &[u8; 256]) -> u8 {
    decode_table[input as usize]
}

/// Trait to decode base64 data.
pub trait Decoding: ::private::Sealed + Copy {
    /// Decode the input byte. If the input byte is not a valid character for the
    /// provided configuration, ::tables::INVALID_VALUE must be returned. Note:
    /// If this trait is ever made publicly implementable, then INVALID_VALUE
    /// will need to be exposed as well.
    fn decode_u8(self, input: u8) -> u8;

    /// Decode input into bytes. Equivalent to decode_config.
    #[inline]
    fn decode<T>(self, input: &T) -> Result<Vec<u8>, DecodeError>
    where
        Self: Padding,
        T: ?Sized + AsRef<[u8]>,
    {
        decode_config(input, self)
    }

    /// Decode input into bytes. Equivalent to decode_config_buf.
    #[inline]
    fn decode_buf<T>(self, input: &T, buffer: &mut Vec<u8>) -> Result<(), DecodeError>
    where
        Self: Padding,
        T: ?Sized + AsRef<[u8]>,
    {
        decode_config_buf(input, self, buffer)
    }

    /// Decode input into bytes. Equivalent to decode_config_buf.
    #[inline]
    fn decode_slice<T>(self, input: &T, output: &mut [u8]) -> Result<usize, DecodeError>
    where
        Self: Padding,
        T: ?Sized + AsRef<[u8]>,
    {
        decode_config_slice(input, self, output)
    }
}

impl Decoding for StdAlphabet {
    #[inline]
    fn decode_u8(self, input: u8) -> u8 {
        decode_by_table(input, ::tables::STANDARD_DECODE)
    }
}

impl Decoding for UrlSafeAlphabet {
    #[inline]
    fn decode_u8(self, input: u8) -> u8 {
        decode_by_table(input, ::tables::URL_SAFE_DECODE)
    }
}

impl Decoding for CryptAlphabet {
    #[inline]
    fn decode_u8(self, input: u8) -> u8 {
        decode_by_table(input, ::tables::CRYPT_DECODE)
    }
}

impl Decoding for &CustomConfig {
    #[inline]
    fn decode_u8(self, input: u8) -> u8 {
        decode_by_table(input, &self.decode_table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_chunk_precise_writes_only_6_bytes() {
        let input = b"Zm9vYmFy"; // "foobar"
        let mut output = [0_u8, 1, 2, 3, 4, 5, 6, 7];
        decode_chunk_precise(&input[..], 0, StdAlphabet, &mut output).unwrap();
        assert_eq!(&vec![b'f', b'o', b'o', b'b', b'a', b'r', 6, 7], &output);
    }

    #[test]
    fn decode_chunk_writes_8_bytes() {
        let input = b"Zm9vYmFy"; // "foobar"
        let mut output = [0_u8, 1, 2, 3, 4, 5, 6, 7];
        decode_chunk(&input[..], 0, StdAlphabet, &mut output).unwrap();
        assert_eq!(&vec![b'f', b'o', b'o', b'b', b'a', b'r', 0, 0], &output);
    }

    #[test]
    fn detect_invalid_last_symbol_two_bytes() {
        // example from https://github.com/alicemaz/rust-base64/issues/75
        assert!(decode("iYU=").is_ok());
        // trailing 01
        assert_eq!(Err(DecodeError::InvalidLastSymbol(2, b'V')), decode("iYV="));
        // trailing 10
        assert_eq!(Err(DecodeError::InvalidLastSymbol(2, b'W')), decode("iYW="));
        // trailing 11
        assert_eq!(Err(DecodeError::InvalidLastSymbol(2, b'X')), decode("iYX="));

        // also works when there are 2 quads in the last block
        assert_eq!(
            Err(DecodeError::InvalidLastSymbol(6, b'X')),
            decode("AAAAiYX=")
        );
    }

    #[test]
    fn detect_invalid_last_symbol_one_byte() {
        // 0xFF -> "/w==", so all letters > w, 0-9, and '+', '/' should get InvalidLastSymbol

        assert!(decode("/w==").is_ok());
        // trailing 01
        assert_eq!(Err(DecodeError::InvalidLastSymbol(1, b'x')), decode("/x=="));
        assert_eq!(Err(DecodeError::InvalidLastSymbol(1, b'z')), decode("/z=="));
        assert_eq!(Err(DecodeError::InvalidLastSymbol(1, b'0')), decode("/0=="));
        assert_eq!(Err(DecodeError::InvalidLastSymbol(1, b'9')), decode("/9=="));
        assert_eq!(Err(DecodeError::InvalidLastSymbol(1, b'+')), decode("/+=="));
        assert_eq!(Err(DecodeError::InvalidLastSymbol(1, b'/')), decode("//=="));

        // also works when there are 2 quads in the last block
        assert_eq!(
            Err(DecodeError::InvalidLastSymbol(5, b'x')),
            decode("AAAA/x==")
        );
    }

    #[test]
    fn detect_invalid_last_symbol_every_possible_three_symbols() {
        let mut base64_to_bytes = ::std::collections::HashMap::new();

        let mut bytes = [0_u8; 2];
        for b1 in 0_u16..256 {
            bytes[0] = b1 as u8;
            for b2 in 0_u16..256 {
                bytes[1] = b2 as u8;
                let mut b64 = vec![0_u8; 4];
                assert_eq!(4, ::encode_config_slice(&bytes, STANDARD, &mut b64[..]));
                let mut v = ::std::vec::Vec::with_capacity(2);
                v.extend_from_slice(&bytes[..]);

                assert!(base64_to_bytes.insert(b64, v).is_none());
            }
        }

        // every possible combination of symbols must either decode to 2 bytes or get InvalidLastSymbol

        let mut symbols = [0_u8; 4];
        for &s1 in ::tables::STANDARD_ENCODE.iter() {
            symbols[0] = s1;
            for &s2 in ::tables::STANDARD_ENCODE.iter() {
                symbols[1] = s2;
                for &s3 in ::tables::STANDARD_ENCODE.iter() {
                    symbols[2] = s3;
                    symbols[3] = b'=';

                    match base64_to_bytes.get(&symbols[..]) {
                        Some(bytes) => {
                            assert_eq!(Ok(bytes.to_vec()), decode_config(&symbols, STANDARD))
                        }
                        None => assert_eq!(
                            Err(DecodeError::InvalidLastSymbol(2, s3)),
                            decode_config(&symbols[..], STANDARD)
                        ),
                    }
                }
            }
        }
    }

    #[test]
    fn detect_invalid_last_symbol_every_possible_two_symbols() {
        let mut base64_to_bytes = ::std::collections::HashMap::new();

        for b in 0_u16..256 {
            let mut b64 = vec![0_u8; 4];
            assert_eq!(4, ::encode_config_slice(&[b as u8], STANDARD, &mut b64[..]));
            let mut v = ::std::vec::Vec::with_capacity(1);
            v.push(b as u8);

            assert!(base64_to_bytes.insert(b64, v).is_none());
        }

        // every possible combination of symbols must either decode to 1 byte or get InvalidLastSymbol

        let mut symbols = [0_u8; 4];
        for &s1 in ::tables::STANDARD_ENCODE.iter() {
            symbols[0] = s1;
            for &s2 in ::tables::STANDARD_ENCODE.iter() {
                symbols[1] = s2;
                symbols[2] = b'=';
                symbols[3] = b'=';

                match base64_to_bytes.get(&symbols[..]) {
                    Some(bytes) => {
                        assert_eq!(Ok(bytes.to_vec()), decode_config(&symbols, STANDARD))
                    }
                    None => assert_eq!(
                        Err(DecodeError::InvalidLastSymbol(1, s2)),
                        decode_config(&symbols[..], STANDARD)
                    ),
                }
            }
        }
    }
}
