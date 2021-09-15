//! Provides the [AVX2] engine and associated config types.
use crate::engine::Config;
use crate::engine::DecodeEstimate;
use crate::{DecodeError, PAD_BYTE};

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

const INVALID_VALUE: u8 = 255;

const BLOCKS_PER_AVX: usize = 4;
const AVX_PER_LOOP: usize = 1;
const BLOCKS_PER_FAST_LOOP: usize = AVX_PER_LOOP * BLOCKS_PER_AVX;

const INPUT_CHUNK_LEN: usize = 32;
const DECODED_CHUNK_LEN: usize = 24;

/// A vectorized base64 engine using AVX2 extensions for the STANDARD alphabet
///
/// - It uses the avx2 extensions for x86 and x86_64/AMD64 so it's highly non-portable.
/// - It is slightly fast (About 300% faster than FastPortable on my Intel Skylake)
/// - It is also not specifically constant-time
/// - It has to use unsafe code because intrinsics are always unsafe in Rust.
/// - The algorithm in use makes specific assumptions about the alphabet, so it's only implemented
/// for the STANDARD and URL_SAFE Alphabet
pub struct AVX2Encoder {
    config: AVX2Config,

    // Alphabet LUT for serial steps
    encode_table: [u8;  64],
    decode_table: [u8; 256],

    // Alphabet LUT for vectorized steps
    encode_offsets: __m256i,
    decode_offsets: __m256i,

    // The algorithm in use needs to be able to distinguish between the two singletons outside the
    // [A-Za-z] ranges. 
    // For STANDARD these are '+' and '/' and the engine matches against '/' i.e. 0x2F
    // For URL_SAFE these are '-' and '_' and the engine matches against '_' i.e. 0x5F
    singleton_mask: __m256i,
    hi_witnesses: __m256i,
    lo_witnesses: __m256i,
}

impl AVX2Encoder {
    /// Create an AVX2Encoder for the standard Alphabet from a given config.
    /// You can create one for urlsafe with the associated function [`from_urlsafe`].
    pub fn from_standard(config: AVX2Config) -> Self {
        let encode_offsets = unsafe {
            _mm256_setr_epi8(
            //  00  01  02  03  04  05  06  07  08  09  10  11  12  13  14  15
                71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4,-19,-16, 65,  0,  0,
                71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4,-19,-16, 65,  0,  0,
            )
        };

        // These decode offsets are accessed by the high nibble of the ASCII character being
        // decoded so for example 'A' (0x41) is offset -65 since it encodes 0b000000.
        // The one exception to that is the value '/' (0x2F) which has to be handled specifically.
        let decode_offsets = unsafe {
            _mm256_setr_epi8(
            //  00 01  02 03   04   05   06   07  08 09 10 11 12 13 14 15
                 0, 0, 19, 4, -65, -65, -71, -71, 16, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 19, 4, -65, -65, -71, -71, 16, 0, 0, 0, 0, 0, 0, 0
            )
        };

        let singleton_mask = unsafe { _mm256_set1_epi8(0x2F) };
        // Witnesses for the high nibbles:
        // 0x0 and 0x1 are never valid, no matter what the low nibble is.
        // 0x2 is valid for the characters '+' (0x2B), '/' (0x2F) and '-' (0x2D), depending on the
        // alphabet.
        // 0x3 contains numerals but the only valid inputs are 0x30 to 0x39, so we need to make
        // sure that everything from 0xA to 0xF is rejected.
        // 0x4 and 0x5 contain [A-Z] and also the special character '_' (0x5F) from the urlsafe
        // alphabet.
        // 0x6 and 0x7 contain [a-z].
        // 0x7 and 0x8 are never valid; 0x8 or higher especially means invalid ASCII.
        //
        // We use -0x1 as "always invalid" value so that the low witness has to only return
        // something != 0 for the invalid test to trip.
        let hi_witnesses = unsafe {
            _mm256_setr_epi8(
                // 0     1     2     3     4     5     6     7
                -0x1, -0x1, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
                // 8     9    10    11    12    13    14    15
                -0x1, -0x1, -0x1, -0x1, -0x1, -0x1, -0x1, -0x1,
                // 0     1     2     3     4     5     6     7
                -0x1, -0x1, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
                // 8     9    10    11    12    13    14    15
                -0x1, -0x1, -0x1, -0x1, -0x1, -0x1, -0x1, -0x1
            )
        };
        // Witnesses for the low nibbles.
        // ASCII has the advantage that A-Z and a-z are 0x20 away from each other so you can use
        // the same lo witnesses for both of those ranges.
        // The easiest way to create these witness tables and what is done here is to use the hi
        // witness to select a bit to probe and set the bit in the low witness for invalid nibbles
        // in that range. E.g. the hi witness sets bit 1 for high nibble 0x2, bit 2 for 0x3, and
        // bit 3 for 0x4 and 0x6. The lo witness then sets bit 2 for 0xA..0xF (since those are
        // invalids in the numeric range), bit 1 for everything invalid in the special bytes range
        // (i.e. everything but 0x2F, 0x2B etc.), bit 3 for 0x1 and bit 4 for 0xB..0xF.
        let lo_witnesses = unsafe {
            _mm256_setr_epi8(
                // 0     1     2     3     4     5     6     7
                0x75, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
                // 8     9    80    11    12    13    14    15
                0x71, 0x71, 0x73, 0x7A, 0x7B, 0x7B, 0x7B, 0x7A,
                // 0     1     2     3     4     5     6     7
                0x75, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
                // 8     9    80    11    12    13    14    15
                0x71, 0x71, 0x73, 0x7A, 0x7B, 0x7B, 0x7B, 0x7A,
            )
        };

        Self {
            config,

            encode_table: ENCODE_TABLE,
            decode_table: DECODE_TABLE,

            encode_offsets,
            decode_offsets,
            singleton_mask,
            hi_witnesses,
            lo_witnesses,
        }
    }
    /// Create an AVX2Encoder for the urlsafe alphabet with the given config.
    /// You can create one for standard with the associated function [`from_standard`].
    pub fn from_url_safe(config: AVX2Config) -> Self {
        let encode_offsets = unsafe {
            _mm256_setr_epi8(
            //  00  01  02  03  04  05  06  07  08  09  10  11  12  13  14  15
                71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4,-17, 32, 65,  0,  0,
                71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4,-17, 32, 65,  0,  0,
            )
        };

        let decode_offsets = unsafe {
            _mm256_setr_epi8(
            // 00 01  02  03   04   05   06   07  08  09  10  11  12  13  14  15
                0, 0, 17,  4, -65, -65, -71, -71,  0,  0,  0,-32,  0,  0,  0,  0,
                0, 0, 17,  4, -65, -65, -71, -71,  0,  0,  0,-32,  0,  0,  0,  0
            )
        };

        let singleton_mask = unsafe { _mm256_set1_epi8(0x5F) };
        let hi_witnesses = unsafe {
            _mm256_setr_epi8(
                // 0     1     2     3     4     5     6     7
                -0x1, -0x1, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
                // 8     9    10    11    12    13    14    15
                -0x1, -0x1, -0x1, -0x1, -0x1, -0x1, -0x1, -0x1,
                // 0     1     2     3     4     5     6     7
                -0x1, -0x1, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
                // 8     9    10    11    12    13    14    15
                -0x1, -0x1, -0x1, -0x1, -0x1, -0x1, -0x1, -0x1
            )
        };
        // Lo witnesses for url-safe are slightly different than for standard:
        // Inputs 0x5F ('_') and 0x2D are valid, inputs 0x2F ('/') and 0x2B ('+') are not.
        let lo_witnesses = unsafe {
            _mm256_setr_epi8(
                // 0     1     2     3     4     5     6     7
                0x75, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
                // 8     9     A     B     C     D     E     F
                0x71, 0x71, 0x73, 0x7B, 0x7B, 0x7A, 0x7B, 0x73,
                // 0     1     2     3     4     5     6     7
                0x75, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71, 0x71,
                // 8     9     A     B     C     D     E     F
                0x71, 0x71, 0x73, 0x7B, 0x7B, 0x7A, 0x7B, 0x73,
            )
        };

        Self {
            config,

            encode_table: URL_ENCODE_TABLE,
            decode_table: URL_DECODE_TABLE,

            encode_offsets,
            decode_offsets,
            singleton_mask,
            hi_witnesses,
            lo_witnesses,
        }
    }
}

#[doc(hidden)]
pub struct AVX2Estimate {
    /// Total number of decode chunks, including a possibly partial last chunk
    num_chunks: usize,
}

impl AVX2Estimate {
    pub(crate) fn from(input_len: usize) -> AVX2Estimate {
        let num_chunks = input_len
                .checked_add(INPUT_CHUNK_LEN - 1)
                .expect("Overflow when calculating number of chunks in input")
                / INPUT_CHUNK_LEN;

        AVX2Estimate {
            num_chunks,
        }
    }
}

impl DecodeEstimate for AVX2Estimate {
    fn decoded_length_estimate(&self) -> usize {
        self.num_chunks
            .checked_mul(DECODED_CHUNK_LEN)
            .expect("Overflow when calculating decoded length")
    }
}


#[inline(always)]
unsafe fn load_block(input: __m256i) -> __m256i {
    // TODO: Explain this load shuffle
    let i: __m256i = _mm256_shuffle_epi8(input, _mm256_set_epi8(
        10, 11,  9, 10,  7,  8,  6,  7,  4,  5,  3,  4,  1,  2,  0,  1,
        14, 15, 13, 14, 11, 12, 10, 11,  8,  9,  7,  8,  5,  6,  4,  5
    ));
    let t0: __m256i = _mm256_and_si256(i, _mm256_set1_epi32(0x0fc0fc00));
    let t1: __m256i = _mm256_mulhi_epu16(t0, _mm256_set1_epi32(0x04000040));
    let t2: __m256i = _mm256_and_si256(i, _mm256_set1_epi32(0x003f03f0));
    let t3: __m256i = _mm256_mullo_epi16(t2, _mm256_set1_epi32(0x01000010));
    return _mm256_or_si256(t1, t3);
}

#[inline(always)]
unsafe fn decode(
    invalid: &mut bool,
    lo_witness_lut: __m256i,
    hi_witness_lut: __m256i,
    offsets: __m256i,
    mask_singleton: __m256i,
    block: __m256i
) -> __m256i {
    // The most relevant information to understand this algorithm is this tidbit:
    // AVX shuffle conveniently work like table lookups; c = _mm256_shuffle_epi8(a,b) behaves* like 
    // for i in 0..16 {
    //     c[i] = a[b[i]];
    //     c[i+16] = a[b[i+16]];
    // }
    // This is the reason why lo_witness_lut, hi_witness_lut, encode_offsets and decode_offets all have the exact
    // same values set for each 16-byte half; they are used as Look-Up tables in shuffles.
    // (* it additionally sets c[i] and c[i] to 0 if b[i] >= 128 but that is not used here)
    //
    // As a first step, since the indexes available in shuffles are only 0.16 or in other words one
    // nibble's worth, split each input byte into high and low nibble.
    // The high nibbles are retrieved by shifting the input by 4 bits and then applying a mask of
    // 0b1111 to it. The low bits are retrieved by not shifting and applying the very same map.
    // The "standard" algorithm happens to look for 0x2F ('/') which *also* just happens to have the
    // lowest 4 bits set to 1, so it can use that. The urlsafe one can't.
    let mask_nib = _mm256_set1_epi8(0b00001111);
    let block_shifted = _mm256_srli_epi32(block, 4);
    let hi_nibbles = _mm256_and_si256(block_shifted, mask_nib);
    let lo_nibbles = _mm256_and_si256(block, mask_nib);

    // This algorithm uses offsets for decoding. e.g. in the standard and url-safe alphabet the
    // ASCII letter 'A' encodes 0b000000, the letter 'B' 0b000001, and so on. The ASCII value of
    // 'A' is 65. So to get from a capital letter in the input to the value it encodes you have to
    // substract 65.  Similarly, the letter 'a' encodes 0b011010, or 26 in decimal. 'b' encodes 27
    // and so on. But the ASCII value of 'a' is 97, so to get from a miniscule to it's value you
    // don't substract 65 but 71 instead.
    // The main optimization this algorithm makes and the source for it's assumptions is that it
    // relies on the fact that the alphabet used has continous ordered ranges of inputs that thus
    // share an offset, and that these ranges are distinguishable by their upper nibble.
    // In other words for [A-Z] substracting 65 gets you to the correct value and for [a-z]
    // substracting 71 does as well. While decoding we just have to figure out which range an input
    // belongs to and directly know what offset to apply.
    // However, we need to check for invalid inputs. The algorithm again optimizes that by using
    // the fact that valid input is in one of the ranges or one of two special bytes ('+' and '/'
    // or '-' and '_' specifically)
    // [A-Z] for example is the range of 0b100_0001 to 0b101_1010, so the high nibbles 0b100 (4)
    // and 0b101 (5). But not every input with these high nibbles is valid, e.g. the character '@'
    // encoded as 0b100_0000 or the character '[', i.e. 0b101_1011.  So we need to check if the low
    // nibble is valid for a given high nibble. AVX2 has an instructions for bitwise comparing two
    // vectors which is exposed as `test` instrinsics which return a different CPU flag for
    // conditionals.
    // _mm256_testz_si256 used here bitwise AND's both input vectors and returns 1 if the result is
    // zero and 0 if the result has any bit set.
    // So we need to now generate a `witness` for the high and low nibble each so that 
    // `witness_hi & witness_lo == 0` iff the input is valid.
    let witness_lo = _mm256_shuffle_epi8(lo_witness_lut, lo_nibbles);
    let witness_hi = _mm256_shuffle_epi8(hi_witness_lut, hi_nibbles);
    if _mm256_testz_si256(witness_lo, witness_hi) == 0 {
        *invalid = true;
        return _mm256_and_si256(witness_hi, witness_lo);
    }

    // Next we check for one of the singleton bytes. Since in neither standard nor url-safe
    // alphabet they both have the same offset to their encoded value and also can't be
    // distinguished from other offset values by their high nibble alone ('_' has high nibble 5
    // like a-z, '/' and '+' both have 2) we need to explicitly match against one of them.
    let eq_singleton = _mm256_cmpeq_epi8(block, mask_singleton);

    // In the last decoding step we do two things: Add 0x6 to all hi nibbles where we found our
    // singleton. This makes input 0x2F check for offset in offsets[8] and 0x5F in offsets[11].
    // Then, get the actual offset amount from `offsets` and add it to our input.
    let offsetidxs = _mm256_add_epi8(hi_nibbles, _mm256_and_si256(eq_singleton, _mm256_set1_epi8(0x6)));
    let offsetvals = _mm256_shuffle_epi8(offsets, offsetidxs);
    let shuffeled = _mm256_add_epi8(block, offsetvals);

    // This merges the 16, 6 bit wide but byte aligned, values in each half into a packed 12 byte
    // block of data each.
    let merge_ab_and_bc = _mm256_maddubs_epi16(shuffeled, 
        _mm256_set1_epi32(0x01400140));
    let madd = _mm256_madd_epi16(merge_ab_and_bc, _mm256_set1_epi32(0x00011000));
    let shuffle = _mm256_shuffle_epi8(madd, _mm256_setr_epi8(
        2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1,
        2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1
    ));

    // Compact the two 128 bit lanes filled with 12 bytes of data each down to 24
    // consecutive bytes.
    // TODO This could also be done with _mm256_storeu2_m128i.
    _mm256_permutevar8x32_epi32(shuffle, _mm256_setr_epi32(
            0, 1, 2, 4, 5, 6, -1, -1
    ))
}

#[inline(always)]
/// decode_masked is a version of decode specialized for partial input.
/// The only difference between it and the unmasked version is that the test that checks for
/// invalid bytes (which is `a AND b` over a,b := 256-bit vector) gets the same input mask applied,
/// since `0` bytes would in fact be an invalid input.
unsafe fn decode_masked(
    invalid: &mut bool,
    lo_witness_lut: __m256i,
    hi_witness_lut: __m256i,
    offsets: __m256i,
    mask_singleton: __m256i,
    mask_input: __m256i,
    block: __m256i
) -> __m256i {
    let mask_nib = _mm256_set1_epi8(0b00001111);
    let block_shifted = _mm256_srli_epi32(block, 4);
    let hi_nibbles = _mm256_and_si256(block_shifted, mask_nib);
    let lo_nibbles = _mm256_and_si256(block, mask_nib);

    let witness_lo = _mm256_shuffle_epi8(lo_witness_lut, lo_nibbles);
    let witness_hi = _mm256_shuffle_epi8(hi_witness_lut, hi_nibbles);

    let witness_hi = _mm256_and_si256(witness_hi, mask_input);
    if _mm256_testz_si256(witness_lo, witness_hi) == 0 {
        *invalid = true;
        return _mm256_and_si256(witness_hi, witness_lo);
    }

    let eq_singleton = _mm256_cmpeq_epi8(block, mask_singleton);
    let offsetidxs = _mm256_add_epi8(hi_nibbles, _mm256_and_si256(eq_singleton, _mm256_set1_epi8(0x6)));
    let offsetvals = _mm256_shuffle_epi8(offsets, offsetidxs);
    let shuffeled = _mm256_add_epi8(block, offsetvals);

    let merge_ab_and_bc = _mm256_maddubs_epi16(shuffeled, 
        _mm256_set1_epi32(0x01400140));
    let madd = _mm256_madd_epi16(merge_ab_and_bc, _mm256_set1_epi32(0x00011000));
    let shuffle = _mm256_shuffle_epi8(madd, _mm256_setr_epi8(
        2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1,
        2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1
    ));

    // Compact the two 128 bit lanes filled with 12 bytes of data each down to 24
    // consecutive bytes.
    // TODO This could also be done with _mm256_storeu2_m128i.
    _mm256_permutevar8x32_epi32(shuffle, _mm256_setr_epi32(
            0, 1, 2, 4, 5, 6, -1, -1
    ))
}


#[inline]
unsafe fn encode(offsets: __m256i, input: __m256i) -> __m256i {
    let mut result: __m256i = _mm256_subs_epu8(input, _mm256_set1_epi8(51));
    let less: __m256i = _mm256_cmpgt_epi8(_mm256_set1_epi8(26), input);
    result = _mm256_or_si256(result, _mm256_and_si256(less, _mm256_set1_epi8(13)));
    result = _mm256_shuffle_epi8(offsets, result);
    return _mm256_add_epi8(result, input);
}

const ENCODE_TABLE: [u8; 64] = 
    crate::engine::fast_portable::encode_table(&crate::alphabet::STANDARD);
const URL_ENCODE_TABLE: [u8; 64] = 
    crate::engine::fast_portable::encode_table(&crate::alphabet::URL_SAFE);
const DECODE_TABLE: [u8; 256] = 
    crate::engine::fast_portable::decode_table(&crate::alphabet::STANDARD);
const URL_DECODE_TABLE: [u8; 256] = 
    crate::engine::fast_portable::decode_table(&crate::alphabet::URL_SAFE);

const MASKLOAD: [i32; 16] = [-1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0];

impl super::Engine for AVX2Encoder {
    type Config = AVX2Config;
    type DecodeEstimate = AVX2Estimate;

    fn encode(&self, input: &[u8], output: &mut [u8]) -> usize {
        let mut input_index: usize = 0;

        // Note:
        // Very small input buffers don't profit from vector SIMD. In fact the latency cost of
        // using AVX and copying data into a form to be able to use vectored instructions at all
        // may as well make using vectored instructions *worse* here.

        // We encode 24 bytes per AVX-accelerated round into 32 output bytes.
        // Each input block of 6 bit get encoded as an output block of 8 bit.
        const BLOCKS_PER_AVX: usize = 4;
        const AVX_PER_LOOP: usize = 1;
        const BLOCKS_PER_FAST_LOOP: usize = AVX_PER_LOOP * BLOCKS_PER_AVX;

        // We load 32 byte at a time with AVX and discard the first and last 4 bytes.
        // This means that we require 4 trailing bytes to be readable for unmasked loads.
        let last_fast_index = input.len().saturating_sub(BLOCKS_PER_FAST_LOOP * 6 + 4);
        let mut output_index: usize = 0;

        if last_fast_index > 0 {
            // During the first load we have to use a masked load since we need to load 24 bytes
            // into the *middle* of our 32-byte register meaning the mem_addr we provide points
            // 4 bytes *before* &input into (potentially) unallocated space.

            let mut block: __m256i;

            // I rely on i32 being encoded as two's complement here. Given that this module is only
            // possible to run on very modern x86 and x86_64/AMD64 this is a reasonable assumption
            // to make.
            const LOAD: i32 = -1;
            const SKIP: i32 = 0;

            unsafe {
                let output_chunk = &mut output[output_index..(output_index + 32)];
                // The only reason this here is even remotely safe is due to two assumptions:
                // 1. The compiler will not store, write to or otherwise use this ptr.
                // 2. _mm256_maskload_epi32 will never attempt to read masked bytes from memory.
                let mem_addr: *const u8 = input.as_ptr().offset(-4);
                block = _mm256_maskload_epi32(mem_addr.cast(), 
                    _mm256_set_epi32(SKIP,LOAD,LOAD,LOAD,LOAD,LOAD,LOAD,SKIP));

                let expanded: __m256i = load_block(block);
                let outblock: __m256i = encode(self.encode_offsets, expanded);
                _mm256_storeu_si256(output_chunk.as_mut_ptr().cast(), outblock);

                output_index += 32;
                input_index += 24;
            }

            while input_index < last_fast_index {
                // The 4 most and least significant bytes of the input register are voided and only
                // the middle 24 bytes are kept as input. Thus we offset the input by four bytes to
                // the left and have it be 32 bytes wide. This is safe since input_index is at this
                // point always at least 24 and at most input.len()-29.
                let input_chunk = &input[(input_index-4)..(input_index + 28)];
                let output_chunk = &mut output[output_index..(output_index + 32)];

                unsafe {
                    // Load data from &input into avx register
                    block = _mm256_loadu_si256(input_chunk.as_ptr().cast());

                    // First step: Expand the 24 input bytes into 32 bytes ready for encoding.
                    let expanded: __m256i = load_block(block);
                    // Second step: Do the actual conversion
                    let outblock: __m256i = encode(self.encode_offsets, expanded);
                    // Third step: Write the data into the output
                    _mm256_storeu_si256(output_chunk.as_mut_ptr().cast(), outblock);

                }
                output_index += BLOCKS_PER_FAST_LOOP * 8;
                input_index += BLOCKS_PER_FAST_LOOP * 6;
            }

        }
        // End of fast loop.
        // TODO: In the case that we do more than one AVX2 round per fast loop we should still
        // probably use unmasked AVX2 (latency of 1 vs 8 for unmasked vs masked) here but with
        // only one round per loop.

        // We may need padding. Everything except the last three bytes is fair game, the last three
        // bytes have one of three special cases: 
        // 1) All three bytes are one group and can be encoded as is
        // 2) The first of the last three bytes is part of the group before, the other two have to
        //    be encoded in a shorter group.
        // 3) The first two of the last three bytes are part of the group before, the last one has
        //    to be encoded alone.
        // We don't want to specifically handle case 1), so we check if the index is one of the
        // last two bytes (input_index < start_of_rem).
        let start_of_rem = input.len().saturating_sub(2);

        const LOW_SIX_BITS_U8: u8 = 0b111111;

        while input_index < start_of_rem {
            let input_chunk = &input[input_index..(input_index + 3)];
            let output_chunk = &mut output[output_index..(output_index + 4)];

            output_chunk[0] = self.encode_table[(input_chunk[0] >> 2) as usize];
            output_chunk[1] = self.encode_table
                [((input_chunk[0] << 4 | input_chunk[1] >> 4) & LOW_SIX_BITS_U8) as usize];
            output_chunk[2] = self.encode_table
                [((input_chunk[1] << 2 | input_chunk[2] >> 6) & LOW_SIX_BITS_U8) as usize];
            output_chunk[3] = self.encode_table[(input_chunk[2] & LOW_SIX_BITS_U8) as usize];

            input_index += 3;
            output_index += 4;
        }

        let rem = input.len() - input_index;

        if rem == 2 {
            let final_input = input.len()-2;
            output[output_index] = self.encode_table[(input[final_input] >> 2) as usize];
            output[output_index + 1] =
                self.encode_table[((input[final_input] << 4 | input[final_input + 1] >> 4)
                    & LOW_SIX_BITS_U8) as usize];
            output[output_index + 2] =
                self.encode_table[((input[final_input + 1] << 2) & LOW_SIX_BITS_U8) as usize];
            output_index += 3;
        } else if rem == 1 {
            let final_input = input.len()-1;
            output[output_index] = self.encode_table[(input[final_input] >> 2) as usize];
            output[output_index + 1] =
                self.encode_table[((input[final_input] << 4) & LOW_SIX_BITS_U8) as usize];
            output_index += 2;
        }

        output_index
    }

    fn decoded_length_estimate(&self, input_len: usize) -> Self::DecodeEstimate {
        AVX2Estimate::from(input_len)
    }

    fn decode(
        &self,
        input: &[u8],
        output: &mut [u8],
        _estimate: Self::DecodeEstimate,
    ) -> Result<usize, DecodeError> {
        // TODO: Check if LLVM optimizes this modulo into an &
        let skip_stage_2 = match input.len() % 4 {
            1 => {
                // trailing whitespace is so common that it's worth it to check the last byte to
                // possibly return a better error message
                if let Some(b) = input.last() {
                    if *b != PAD_BYTE && self.decode_table[*b as usize] == INVALID_VALUE {
                        return Err(DecodeError::InvalidByte(input.len() - 1, *b));
                    }
                }

                return Err(DecodeError::InvalidLength);
            },
            // A multiple of 4 input bytes mean output will be undersized for whole word writes,
            // but allow whole word reads, or contain padding. In that case we skip an extra word
            // in stage 2 to not write OOB and to not hit padding.
            0 => 4,
            // In all other cases we only skip the extra bytes.
            x => x,
        };

        // If we have to skip a final 32-byte block or not is mainly dictated by our *output*
        // buffer, not our *input* buffer. We can only do 32-byte wide writes in the fast loop with
        // the final 8 bytes being garbage. Since we have to assume the output buffer is exactly
        // sized we must prevent an OOB write here.
        // Specifically an full input chunk will only generate 24 bytes of output but we write a
        // full 32 bytes into &output. If output is less than 32 bytes large this would be an OOB
        // write violating Rust safety assumptions and thus must not happen.
        // This can only happen for the last full chunk; any chunk before has at least 24
        // additional bytes of output buffer available. For the last chunk if output is large
        // enough depends on the trailing bytes *after* the last chunk.
        // If there is less than 12 bytes of trailing inputs an exactly sized output buffer may be
        // undersized; valid input with 12 bytes or less usually* decodes to less than 8 bytes of
        // valid output, for example 10 data bytes with padding decode to 7 bytes out output. Any
        // *valid* input of more than 12 byte must however decode to more than 8 bytes of output
        // data, and thus the output buffer a well behaved client passes us must be at least
        // 24*INPUT_CHUNK + 8 bytes or in other words at least 32 bytes if we run the fast loop at
        // all.
        // TODO: This assumption is violated in some very specific edgecases where a client passes
        // an undersized buffer due to some external knowledge of the data in question, e.g.
        // because it checks for trailing bits or invalid extra padding. In that case the fast loop
        // will currently panic while taking an output_chunk of 32 bytes, which still upholds the
        // safety guarantees of Rust but may be unexpected to users.

        // TODO: Check if this modulo is optimized by LLVM into an &
        // TODO: Maybe Merge with the above match should this not be optimized into one big offset
        //       table.
        let skip_final_bytes = match input.len() % 32 {
            // Manual special case of the below rule:
            // Only valid input of 11 bytes is unpadded data decoding to 8 bytes output.
            // FIXME: Prove this is correct or remove it. Doing an extra fast loop over two bytes
            // is not worth violating safety.
            // 11 => 11, 
            x if x <= 12 => (BLOCKS_PER_FAST_LOOP * 8) + x,
            x if x > 12 => x,
            _ => unreachable!("Maths, how does it work?"),
        };

        let mut input_index: usize = 0;

        // We have to always skip the last two bytes since they may be padding our fast loop can't
        // handle.
        let last_fast_index = input.len().saturating_sub(skip_final_bytes);
        let mut output_index: usize = 0;

        let mut block: __m256i;
        let mut invalid: bool = false;

        // This will only evaluate to true if we have an input of 33 bytes or more;
        // skip_final_bytes is at least input.len() otherwise.
        if last_fast_index > 0 {
            // Stage 1, fast 32-byte reads & 24-byte writes. Most importantly the output buffer has to have
            // 8 trailing bytes we can write (garbage) into. This is always given since we always
            // skip the last 32 bytes of input.
            while input_index < last_fast_index {
                let input_chunk = &input[input_index..(input_index + 32)];

                // TODO: Check output buffer length at the start of the decoding function since
                // it's rather cheap to do.
                // While we only write 24 *valid* bytes we write a full 32 bytes. This *will* panic
                // if the output buffer is undersized but the only situation where I can see this
                // happen is test code that knowingly provides both invalid data and an undersized
                // buffer assuming linear decoding that breaks off as soon as it hits this invalid
                // data.
                let output_chunk = &mut output[output_index..(output_index + 32)];


                unsafe {
                    block = _mm256_loadu_si256(input_chunk.as_ptr().cast());
                    block = decode(&mut invalid, 
                        self.lo_witnesses, 
                        self.hi_witnesses, 
                        self.decode_offsets, 
                        self.singleton_mask, 
                        block);

                    if invalid {
                        return Err(find_invalid_input(input_index, input_chunk, &self.decode_table));
                    }

                    _mm256_storeu_si256(output_chunk.as_mut_ptr().cast(), block);
                }

                output_index += BLOCKS_PER_FAST_LOOP * 6;
                input_index += BLOCKS_PER_FAST_LOOP * 8;
            }

            // The fast loop can at best give us the 32-byte block in which an invalid input
            // character was found, we need to specialize here
        }

        debug_assert!(input.len() - input_index < 48);

        // At this point we have 12..43 input bytes left if the fast loop ran once or 0..32 if it
        // did not.

        // Stage 1.5
        // If there are 33..43 input bytes left. We do two reads: One unmasked but with masked
        // write (Stage 1.5) and one masked read with masked write (Stage 2)
        // If we have 33..36 input bytes left we *only* do Stage 1.5 because Stage 2 requires that
        // there are more 5 input bytes left.
        if input.len() - input_index > 32 {
            let input_chunk = &input[input_index..(input_index + 32)];
            // We perform a masked write and really only write into the first 24 bytes.
            let output_chunk = &mut output[output_index..(output_index + 24)];

            unsafe {
                // Set the mask to only write the 24 lowest bytes into the output. 
                let mask_output = _mm256_loadu_si256(MASKLOAD[2..10].as_ptr().cast());

                block = _mm256_loadu_si256(input_chunk.as_ptr().cast());
                block = decode(&mut invalid, 
                        self.lo_witnesses, 
                        self.hi_witnesses, 
                        self.decode_offsets,
                        self.singleton_mask,
                        block);

                _mm256_maskstore_epi32(output_chunk.as_mut_ptr().cast(), mask_output, block);
            }
            if invalid {
                return Err(find_invalid_input(input_index, input_chunk, &self.decode_table));
            }

            input_index += 32;
            output_index += 24;
        }

        // There are now 0..32 input bytes left if the fast loop didn't run or 12..32 bytes left if
        // it did.

        // skip_stage_2 is in the range 1..4. input.len()%4 or 4 if input.len()%4 == 0.
        let last_slow_index = input.len().saturating_sub(4 + skip_stage_2);
        if last_slow_index > input_index {
            let stage_2_bytes = last_slow_index - input_index;

            // Input mask index is the number of words we read from the input. Since
            // stage_2_bytes is always a multiple of four this is an exact division.
            let input_mask_index = stage_2_bytes / 4;

            // How many (u32) words of output we produce. Up to three bytes of that may be garbage
            // because we did a masked load above. The exact number of valid output bytes is always
            // `input_mask_index * 3`. Buf if we produce for example 9 bytes of valid output we
            // have to write 12 bytes of output simply because we can only mask in 4-byte groups.
            // The trailing bytes coming after stage 2 always decode into enough data that output
            // will be large enough that writing the garbage is not an OOB write.
            // Thus, we do a rounding up division.
            let output_mask_index = ((input_mask_index + 1) * 3) / 4;

            // Use a const array to create the mask from. This should be close by and hopefully in
            // cache.
            let input_mask = &MASKLOAD[8-input_mask_index..];
            let output_mask = &MASKLOAD[8-output_mask_index..];


            // We take ourselves correctly sized chunks. This can panic if the output or input are
            // too small but in that case we would perform OOB operations in the next step
            let input_chunk = &input[input_index..(input_index + input_mask_index * 4)];
            let output_chunk = &mut output[output_index..(output_index + output_mask_index * 4)];

            let mut invalid = false;
            // Stage 2, still using AVX2 but with masked read and masked write
            unsafe {
                let mask_input = _mm256_loadu_si256(input_mask.as_ptr().cast());
                let mask_output = _mm256_loadu_si256(output_mask.as_ptr().cast());

                block = _mm256_maskload_epi32(input_chunk.as_ptr().cast(), mask_input);
                let outblock = decode_masked(
                        &mut invalid,
                        self.lo_witnesses, 
                        self.hi_witnesses, 
                        self.decode_offsets,
                        self.singleton_mask,
                        mask_input,
                        block
                );

                if invalid {
                    return Err(find_invalid_input(input_index, input_chunk, &self.decode_table));
                }

                _mm256_maskstore_epi32(output_chunk.as_mut_ptr().cast(), mask_output, outblock);
            }

            input_index += input_mask_index * 4;
            output_index += input_mask_index * 3;
        }


        // Now we have anything between two and four bytes of input left. Not counting padding

        let mut leftover_bits: u64 = 0;
        let mut morsels_in_leftover = 0;
        let mut padding_bytes = 0;
        let mut first_padding_index: usize = 0;
        let mut last_symbol = 0_u8;
        let start_of_leftovers = input_index;
        for (i, b) in input[start_of_leftovers..].iter().enumerate() {
            // '=' padding
            if *b == PAD_BYTE {
                // There can be bad padding in a few ways:
                // 1 - Padding with non-padding characters after it
                // 2 - Padding after zero or one non-padding characters before it
                //     in the current quad.
                // 3 - More than two characters of padding. If 3 or 4 padding chars
                //     are in the same quad, that implies it will be caught by #2.
                //     If it spreads from one quad to another, it will be an invalid byte
                //     in the first quad.

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
                    PAD_BYTE,
                ));
            }
            last_symbol = *b;

            // can use up to 8 * 6 = 48 bits of the u64, if last chunk has no padding.
            // Pack the leftovers from left to right.
            let shift = 64 - (morsels_in_leftover + 1) * 6;
            let morsel = self.decode_table[*b as usize];
            if morsel == INVALID_VALUE {
                return Err(DecodeError::InvalidByte(start_of_leftovers + i, *b));
            }

            leftover_bits |= (morsel as u64) << shift;
            morsels_in_leftover += 1;
        }

        // If we had 4 data bytes in the input left we have 24 bits of valid data to append.
        // In all other cases there are zero valid data bits but maybe some invalid ones.
        let leftover_bits_ready_to_append = match morsels_in_leftover {
            0 => 0,
            2 => 8,
            3 => 16,
            4 => 24,
            6 => 32,
            7 => 40,
            8 => 48,
            _ => unreachable!("Stage 2 should never return with more than 8 bytes left"),
        };

        // if there are bits set outside the bits we care about, last symbol encodes trailing bits that
        // will not be included in the output
        let mask = !0 >> leftover_bits_ready_to_append;
        if !self.config.decode_allow_trailing_bits && (leftover_bits & mask) != 0 {
            // last morsel is at `morsels_in_leftover` - 1
            return Err(DecodeError::InvalidLastSymbol(
                start_of_leftovers + morsels_in_leftover - 1,
                last_symbol,
            ));
        }

        // TODO benchmark simply converting to big endian bytes
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

    fn config(&self) -> &Self::Config {
        &self.config
    }
}

fn find_invalid_input(input_index: usize, input: &[u8], decode_table: &[u8; 256]) -> DecodeError {
    // Figure out which byte was invalid exactly.
    for i in 0..input.len() {
        let byte = input[i];
        if decode_table[byte as usize] == INVALID_VALUE {
            return DecodeError::InvalidByte(input_index + i, byte);
        }
    }

    unreachable!("find_invalid_input was given valid input {:?}, global index {}", input, input_index);
}


#[derive(Clone, Copy, Debug)]
/// Config for the AVX2 Encoder
pub struct AVX2Config {
    encode_padding: bool,
    decode_allow_trailing_bits: bool,
}

impl AVX2Config {
    /// Create a new config with `padding` = `true` and `decode_allow_trailing_bits` = `false`.
    ///
    /// This probably matches most people's expectations, but consider disabling padding to save
    /// a few bytes unless you specifically need it for compatibility with some legacy system.
    pub const fn new() -> Self {
        Self {
            // RFC states that padding must be applied by default
            encode_padding: true,
            decode_allow_trailing_bits: false,
        }
    }

    /// Create a new config based on `self` with an updated `padding` parameter.
    ///
    /// If `true`, encoding will append either 1 or 2 `=` padding characters to produce an
    /// output whose length is a multiple of 4.
    ///
    /// Padding is not needed for correct decoding and only serves to waste bytes, but it's in the
    /// [spec](https://datatracker.ietf.org/doc/html/rfc4648#section-3.2).
    ///
    /// For new applications, consider not using padding if the decoders you're using don't require
    /// padding to be present.
    pub const fn with_encode_padding(self, padding: bool) -> Self {
        Self {
            encode_padding: padding,
            ..self
        }
    }

    /// Create a new config based on `self` with an updated `decode_allow_trailing_bits` parameter.
    ///
    /// Most users will not need to configure this. It's useful if you need to decode base64
    /// produced by a buggy encoder that has bits set in the unused space on the last base64
    /// character as per [forgiving-base64 decode](https://infra.spec.whatwg.org/#forgiving-base64-decode).
    /// If invalid trailing bits are present and this is `true`, those bits will
    /// be silently ignored, else `DecodeError::InvalidLastSymbol` will be emitted.
    pub const fn with_decode_allow_trailing_bits(self, allow: bool) -> Self {
        Self {
            decode_allow_trailing_bits: allow,
            ..self
        }
    }
}

impl Default for AVX2Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config for AVX2Config {
    fn encode_padding(&self) -> bool {
        self.encode_padding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::decode_engine;

    #[test]
    fn maskload_array_is_sane() {
        assert_eq!(&MASKLOAD[0..8],  &[-1,-1,-1,-1,-1,-1,-1,-1]);
        assert_eq!(&MASKLOAD[1..9],  &[-1,-1,-1,-1,-1,-1,-1, 0]);
        assert_eq!(&MASKLOAD[2..10], &[-1,-1,-1,-1,-1,-1, 0, 0]);
        assert_eq!(&MASKLOAD[3..11], &[-1,-1,-1,-1,-1, 0, 0, 0]);
        assert_eq!(&MASKLOAD[4..12], &[-1,-1,-1,-1, 0, 0, 0, 0]);
        assert_eq!(&MASKLOAD[5..13], &[-1,-1,-1, 0, 0, 0, 0, 0]);
        assert_eq!(&MASKLOAD[6..14], &[-1,-1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&MASKLOAD[7..15], &[-1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&MASKLOAD[8..16], &[ 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_every_len() {
        let engine = AVX2Encoder::from_standard(AVX2Config::new());
        let mut v = Vec::with_capacity(8192);
        for i in 1..8192 {
            v.push('A' as u8);
            let r = decode_engine(&v, &engine);
            match i % 4 {
                1 => assert_eq!(r, Err(DecodeError::InvalidLength)),
                x => {
                    assert_eq!(r.unwrap().len(), i*3/4, "Failed on len {}", x);
                },
            }
        }
    }
}
