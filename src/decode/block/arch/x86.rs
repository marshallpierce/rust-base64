//! This module is only included on x86 and x86_64.

use decode::block::ScalarBlockDecoding;
use {CryptAlphabet, DecodeError, Decoding, IntoBlockDecoding, StdAlphabet, UrlSafeAlphabet};

#[derive(Debug, Default, Clone, Copy)]
pub struct BlockDecoding<D>(D);

impl<D> ::BlockDecoding for BlockDecoding<D>
where
    D: Decoding + avx2::Translate256i,
{
    #[inline]
    fn decode_blocks(self, input: &[u8], output: &mut [u8]) -> Result<(usize, usize), DecodeError> {
        if let Ok(decoding) = avx2::BlockDecoding::new(self.0) {
            decoding.decode_blocks(input, output)
        } else {
            ScalarBlockDecoding(self.0).decode_blocks(input, output)
        }
    }
}

impl<D> ::private::Sealed for BlockDecoding<D> {}

impl IntoBlockDecoding for StdAlphabet {
    type BlockDecoding = BlockDecoding<Self>;

    #[inline]
    fn into_block_decoding(self) -> Self::BlockDecoding {
        BlockDecoding(self)
    }
}

impl IntoBlockDecoding for UrlSafeAlphabet {
    type BlockDecoding = BlockDecoding<Self>;

    #[inline]
    fn into_block_decoding(self) -> Self::BlockDecoding {
        BlockDecoding(self)
    }
}

impl IntoBlockDecoding for CryptAlphabet {
    type BlockDecoding = BlockDecoding<Self>;

    #[inline]
    fn into_block_decoding(self) -> Self::BlockDecoding {
        BlockDecoding(self)
    }
}

/// AVX2 implementation of b64 decoding.
mod avx2 {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    use decode::block::input_limit;
    use {DecodeError, StdAlphabet, CryptAlphabet, UrlSafeAlphabet};

    #[derive(Debug, Default, Clone, Copy)]
    pub(super) struct BlockDecoding<D>(D);
    impl<D> BlockDecoding<D> {
        const INPUT_CHUNK_BYTES_READ: usize = 32;
        const OUTPUT_CHUNK_BYTES_DECODED: usize = 24;
        const OUTPUT_CHUNK_BYTES_WRITTEN: usize = 26;

        #[inline]
        pub(super) fn new(decoding: D) -> Result<BlockDecoding<D>, ()> {
            if is_x86_feature_detected!("avx2") {
                Ok(BlockDecoding(decoding))
            } else {
                Err(())
            }
        }

        #[inline]
        pub(super) fn decode_blocks(
            self,
            input: &[u8],
            output: &mut [u8],
        ) -> Result<(usize, usize), DecodeError>
        where
            D: Translate256i,
        {
            Ok(unsafe { self._decode_blocks(input, output) })
        }

        #[inline]
        #[target_feature(enable = "avx2")]
        unsafe fn _decode_blocks(self, input: &[u8], output: &mut [u8]) -> (usize, usize)
        where
            D: Translate256i,
        {
            // AVX2 adaptation of the algorithm outlined here:
            // http://0x80.pl/notesen/2016-01-17-sse-base64-decoding.html#vector-lookup-pshufb-with-bitmask-new
            let input_limit = input_limit(
                input,
                output,
                Self::INPUT_CHUNK_BYTES_READ,
                Self::OUTPUT_CHUNK_BYTES_WRITTEN,
                Self::OUTPUT_CHUNK_BYTES_DECODED,
            );
            let mut input_index = 0;
            let mut output_index = 0;
            while input_index < input_limit {
                #[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
                let mut data =
                    _mm256_loadu_si256(input.as_ptr().add(input_index) as *const __m256i);

                data = match D::translate_m256i(data) {
                    Ok(data) => data,
                    Err(_) => {
                        // There was an error decoding this chunk. Return that we
                        // were only able to decode up to the beginning of the
                        // current range. The non-avx fallback will find and report
                        // the error.
                        return (input_index, output_index);
                    }
                };

                data = _mm256_maddubs_epi16(data, _mm256_set1_epi32(0x0140_0140));
                data = _mm256_madd_epi16(data, _mm256_set1_epi32(0x0001_1000));
                data = _mm256_shuffle_epi8(
                    data,
                    #[cfg_attr(rustfmt, rustfmt_skip)]
                    _mm256_setr_epi8(
                        2, 1, 0,
                        6, 5, 4,
                        10, 9, 8,
                        14, 13, 12,
                        -1, -1, -1, -1,

                        2, 1, 0,
                        6, 5, 4,
                        10, 9, 8,
                        14, 13, 12,
                        -1, -1, -1, -1,
                    ),
                );
                data =
                    _mm256_permutevar8x32_epi32(data, _mm256_setr_epi32(0, 1, 2, 4, 5, 6, -1, -1));
                #[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
                _mm256_storeu_si256(output.as_mut_ptr().add(output_index) as *mut __m256i, data);
                input_index += Self::INPUT_CHUNK_BYTES_READ;
                output_index += Self::OUTPUT_CHUNK_BYTES_DECODED;
            }
            (input_index, output_index)
        }
    }

    pub trait Translate256i {
        unsafe fn translate_m256i(input: __m256i) -> Result<__m256i, ()>;
        unsafe fn is_valid(hi_nibbles: __m256i, low_nibbles: __m256i) -> bool;
    }

    impl Translate256i for StdAlphabet {
        #[inline]
        #[target_feature(enable = "avx2")]
        unsafe fn translate_m256i(input: __m256i) -> Result<__m256i, ()> {
            let hi_nibbles = _mm256_and_si256(_mm256_srli_epi32(input, 4), _mm256_set1_epi8(0x0f));
            let low_nibbles = _mm256_and_si256(input, _mm256_set1_epi8(0x0f));
            if !Self::is_valid(hi_nibbles, low_nibbles) {
                return Err(());
            }
            #[cfg_attr(rustfmt, rustfmt_skip)]
            let shift_lut = _mm256_setr_epi8(
                0,   0,  19,   4, -65, -65, -71, -71,
                0,   0,   0,   0,   0,   0,   0,   0,
                0,   0,  19,   4, -65, -65, -71, -71,
                0,   0,   0,   0,   0,   0,   0,   0,
            );

            let sh = _mm256_shuffle_epi8(shift_lut, hi_nibbles);
            let eq_slash = _mm256_cmpeq_epi8(input, _mm256_set1_epi8(b'/' as i8));
            let shift = _mm256_blendv_epi8(sh, _mm256_set1_epi8(16), eq_slash);
            Ok(_mm256_add_epi8(input, shift))
        }

        #[inline]
        #[target_feature(enable = "avx2")]
        #[allow(overflowing_literals)]
        unsafe fn is_valid(hi_nibbles: __m256i, low_nibbles: __m256i) -> bool {
            #[cfg_attr(rustfmt, rustfmt_skip)]
            let mask_lut = _mm256_setr_epi8(
                0b1010_1000,                            // 0
                0b1111_1000, 0b1111_1000, 0b1111_1000,  // 1 .. 9
                0b1111_1000, 0b1111_1000, 0b1111_1000,
                0b1111_1000, 0b1111_1000, 0b1111_1000,
                0b1111_0000,                            // 10
                0b0101_0100,                            // 11
                0b0101_0000, 0b0101_0000, 0b0101_0000,  // 12 .. 14
                0b0101_0100,                            // 15

                0b1010_1000,                            // 0
                0b1111_1000, 0b1111_1000, 0b1111_1000,  // 1 .. 9
                0b1111_1000, 0b1111_1000, 0b1111_1000,
                0b1111_1000, 0b1111_1000, 0b1111_1000,
                0b1111_0000,                            // 10
                0b0101_0100,                            // 11
                0b0101_0000, 0b0101_0000, 0b0101_0000,  // 12 .. 14
                0b0101_0100,                            // 15
            );

            #[cfg_attr(rustfmt, rustfmt_skip)]
            let bit_pos_lut = _mm256_setr_epi8(
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            );

            let m = _mm256_shuffle_epi8(mask_lut, low_nibbles);
            let bit = _mm256_shuffle_epi8(bit_pos_lut, hi_nibbles);
            let non_match = _mm256_cmpeq_epi8(_mm256_and_si256(m, bit), _mm256_setzero_si256());
            _mm256_movemask_epi8(non_match) == 0
        }
    }

    impl Translate256i for UrlSafeAlphabet {
        #[inline]
        #[target_feature(enable = "avx2")]
        unsafe fn translate_m256i(input: __m256i) -> Result<__m256i, ()> {
            let hi_nibbles = _mm256_and_si256(_mm256_srli_epi32(input, 4), _mm256_set1_epi8(0x0f));
            let low_nibbles = _mm256_and_si256(input, _mm256_set1_epi8(0x0f));
            if !Self::is_valid(hi_nibbles, low_nibbles) {
                return Err(());
            }

            #[cfg_attr(rustfmt, rustfmt_skip)]
            let shift_lut = _mm256_setr_epi8(
                0,   0,  17,   4, -65, -65, -71, -71,
                0,   0,   0,   0,   0,   0,   0,   0,
                0,   0,  17,   4, -65, -65, -71, -71,
                0,   0,   0,   0,   0,   0,   0,   0,
            );

            let sh = _mm256_shuffle_epi8(shift_lut, hi_nibbles);
            let eq_underscore = _mm256_cmpeq_epi8(input, _mm256_set1_epi8(b'_' as i8));
            let shift = _mm256_blendv_epi8(sh, _mm256_set1_epi8(-32), eq_underscore);
            Ok(_mm256_add_epi8(input, shift))
        }

        #[inline]
        #[target_feature(enable = "avx2")]
        #[allow(overflowing_literals)]
        unsafe fn is_valid(hi_nibbles: __m256i, low_nibbles: __m256i) -> bool {
            #[cfg_attr(rustfmt, rustfmt_skip)]
            let mask_lut = _mm256_setr_epi8(
                0b1010_1000,                            // 0
                0b1111_1000, 0b1111_1000, 0b1111_1000,  // 1 .. 9
                0b1111_1000, 0b1111_1000, 0b1111_1000,
                0b1111_1000, 0b1111_1000, 0b1111_1000,
                0b1111_0000,                            // 10
                0b0101_0000, 0b0101_0000,               // 11 .. 12
                0b0101_0100,                            // 13
                0b0101_0000,                            // 14
                0b0111_0000,                            // 15

                0b1010_1000,                            // 0
                0b1111_1000, 0b1111_1000, 0b1111_1000,  // 1 .. 9
                0b1111_1000, 0b1111_1000, 0b1111_1000,
                0b1111_1000, 0b1111_1000, 0b1111_1000,
                0b1111_0000,                            // 10
                0b0101_0000, 0b0101_0000,               // 11 .. 12
                0b0101_0100,                            // 13
                0b0101_0000,                            // 14
                0b0111_0000,                            // 15
            );

            #[cfg_attr(rustfmt, rustfmt_skip)]
            let bit_pos_lut = _mm256_setr_epi8(
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            );

            let m = _mm256_shuffle_epi8(mask_lut, low_nibbles);
            let bit = _mm256_shuffle_epi8(bit_pos_lut, hi_nibbles);
            let non_match = _mm256_cmpeq_epi8(_mm256_and_si256(m, bit), _mm256_setzero_si256());
            _mm256_movemask_epi8(non_match) == 0
        }
    }

    impl Translate256i for CryptAlphabet {
        #[inline]
        #[target_feature(enable = "avx2")]
        unsafe fn translate_m256i(input: __m256i) -> Result<__m256i, ()> {
            let hi_nibbles = _mm256_and_si256(_mm256_srli_epi32(input, 4), _mm256_set1_epi8(0x0f));
            let low_nibbles = _mm256_and_si256(input, _mm256_set1_epi8(0x0f));
            if !Self::is_valid(hi_nibbles, low_nibbles) {
                return Err(());
            }

            #[cfg_attr(rustfmt, rustfmt_skip)]
            let shift_lut = _mm256_setr_epi8(
                0,   0, -46, -46, -53, -53, -59, -59,
                0,   0,   0,   0,   0,   0,   0,   0,
                0,   0, -46, -46, -53, -53, -59, -59,
                0,   0,   0,   0,   0,   0,   0,   0,
            );
            let sh = _mm256_shuffle_epi8(shift_lut, hi_nibbles);
            Ok(_mm256_add_epi8(input, sh))
        }

        #[inline]
        #[target_feature(enable = "avx2")]
        #[allow(overflowing_literals)]
        unsafe fn is_valid(hi_nibbles: __m256i, low_nibbles: __m256i) -> bool {
            #[cfg_attr(rustfmt, rustfmt_skip)]
            let mask_lut = _mm256_setr_epi8(
                0b1010_1000,                            // 0
                0b1111_1000, 0b1111_1000, 0b1111_1000,  // 1 .. 9 
                0b1111_1000, 0b1111_1000, 0b1111_1000,
                0b1111_1000, 0b1111_1000, 0b1111_1000,
                0b1111_0000,                            // 10
                0b0101_0000, 0b0101_0000, 0b0101_0000,  // 11 .. 13
                0b0101_0100, 0b0101_0100,               // 14 .. 15

                0b1010_1000,                            // 0
                0b1111_1000, 0b1111_1000, 0b1111_1000,  // 1 .. 9 
                0b1111_1000, 0b1111_1000, 0b1111_1000,
                0b1111_1000, 0b1111_1000, 0b1111_1000,
                0b1111_0000,                            // 10
                0b0101_0000, 0b0101_0000, 0b0101_0000,  // 11 .. 13
                0b0101_0100, 0b0101_0100,               // 14 .. 15
            );

            #[cfg_attr(rustfmt, rustfmt_skip)]
            let bit_pos_lut = _mm256_setr_epi8(
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            );

            let m = _mm256_shuffle_epi8(mask_lut, low_nibbles);
            let bit = _mm256_shuffle_epi8(bit_pos_lut, hi_nibbles);
            let non_match = _mm256_cmpeq_epi8(_mm256_and_si256(m, bit), _mm256_setzero_si256());
            _mm256_movemask_epi8(non_match) == 0
        }
    }
}
