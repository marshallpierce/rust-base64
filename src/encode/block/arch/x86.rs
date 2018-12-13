//! This module is only included on x86 and x86_64.

use ::{CryptAlphabet, Encoding, IntoBlockEncoding, StdAlphabet, UrlSafeAlphabet};
use ::encode::block::ScalarBlockEncoding;

#[derive(Debug, Default, Clone, Copy)]
pub struct BlockEncoding<E>(E);

impl<E> ::BlockEncoding for BlockEncoding<E> where E: Encoding + sse::Translate128i + avx2::Translate256i {
    #[inline]
    fn encode_blocks(self, input: &[u8], output: &mut [u8]) -> (usize, usize) {
        if let Ok(encoding) = avx2::BlockEncoding::new(self.0) {
            encoding.encode_blocks(input, output)
        } else if let Ok(encoding) = sse::BlockEncoding::new(self.0) {
            encoding.encode_blocks(input, output)
        } else {
            ScalarBlockEncoding(self.0).encode_blocks(input, output)
        }
    }
}
impl<E> ::private::Sealed for BlockEncoding<E> {}

impl IntoBlockEncoding for StdAlphabet {
    type BlockEncoding = BlockEncoding<Self>;

    #[inline]
    fn into_block_encoding(self) -> Self::BlockEncoding {
        BlockEncoding(self)
    }
}

impl IntoBlockEncoding for UrlSafeAlphabet {
    type BlockEncoding = BlockEncoding<Self>;

    #[inline]
    fn into_block_encoding(self) -> Self::BlockEncoding {
        BlockEncoding(self)
    }
}

impl IntoBlockEncoding for CryptAlphabet {
    type BlockEncoding = BlockEncoding<Self>;

    #[inline]
    fn into_block_encoding(self) -> Self::BlockEncoding {
        BlockEncoding(self)
    }
}

/// SSE implemenation of B64 encoding.
mod sse {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;
    use ::{CryptAlphabet, StdAlphabet, UrlSafeAlphabet};

    #[derive(Debug, Default, Clone, Copy)]
    pub(super) struct BlockEncoding<E>(E);
    impl<E> BlockEncoding<E> {
        const INPUT_CHUNK_BYTES_READ: usize = 16;
        const INPUT_CHUNK_BYTES_ENCODED: usize = 12;
        const OUTPUT_CHUNK_BYTES_WRITTEN: usize = 16;

        #[inline]
        pub(super) fn new(encoding: E) -> Result<BlockEncoding<E>, ()> {
            if is_x86_feature_detected!("sse") {
                Ok(BlockEncoding(encoding))
            } else {
                Err(())
            }
        }

        #[inline]
        pub(super) fn encode_blocks(self, input: &[u8], output: &mut [u8]) -> (usize, usize)
        where
            E: Translate128i,
        {
            unsafe { self._encode_blocks(input, output) }
        }

        #[inline]
        #[target_feature(enable = "sse")]
        unsafe fn _encode_blocks(self, input: &[u8], output: &mut [u8]) -> (usize, usize)
        where
            E: Translate128i,
        {
            let mut input_index = 0;
            let mut output_index: usize = 0;
            let last_index = input.len() as isize - Self::INPUT_CHUNK_BYTES_READ as isize;
            while input_index as isize <= last_index {
                // SSE implementation description has been detailed here: http://www.alfredklomp.com/programming/sse-base64/
                // Very briefly this loads 16 byte chunks, arranges the first 12
                // bytes into 4 separate lanes of 3 bytes each. Each 3 byte lane is
                // then encoded into the 4 bytes of it's base64 encoding.
                #[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
                let mut data = _mm_loadu_si128(input.as_ptr().add(input_index) as *const __m128i);
                data = _mm_shuffle_epi8(
                    data,
                    _mm_setr_epi8(2, 2, 1, 0, 5, 5, 4, 3, 8, 8, 7, 6, 11, 11, 10, 9),
                );
                let mut mask = _mm_set1_epi32(0x3F00_0000);
                let mut res = _mm_and_si128(_mm_srli_epi32(data, 2), mask);
                mask = _mm_srli_epi32(mask, 8);
                res = _mm_or_si128(res, _mm_and_si128(_mm_srli_epi32(data, 4), mask));
                mask = _mm_srli_epi32(mask, 8);
                res = _mm_or_si128(res, _mm_and_si128(_mm_srli_epi32(data, 6), mask));
                mask = _mm_srli_epi32(mask, 8);
                res = _mm_or_si128(res, _mm_and_si128(data, mask));

                res = _mm_shuffle_epi8(
                    res,
                    _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12),
                );
                res = E::translate_m128i(res);
                #[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
                _mm_storeu_si128(output.as_mut_ptr().add(output_index) as *mut __m128i, res);
                input_index += Self::INPUT_CHUNK_BYTES_ENCODED;
                output_index += Self::OUTPUT_CHUNK_BYTES_WRITTEN;
            }
            (input_index, output_index)
        }
    }

    pub trait Translate128i {
        unsafe fn translate_m128i(input: __m128i) -> __m128i;
    }


    impl Translate128i for StdAlphabet {
        #[inline]
        #[target_feature(enable = "sse")]
        unsafe fn translate_m128i(input: __m128i) -> __m128i {
            let s1mask = _mm_cmplt_epi8(input, _mm_set1_epi8(26));
            let mut blockmask = s1mask;
            let s2mask = _mm_andnot_si128(blockmask, _mm_cmplt_epi8(input, _mm_set1_epi8(52)));
            blockmask = _mm_or_si128(blockmask, s2mask);
            let s3mask = _mm_andnot_si128(blockmask, _mm_cmplt_epi8(input, _mm_set1_epi8(62)));
            blockmask = _mm_or_si128(blockmask, s3mask);
            let s4mask = _mm_andnot_si128(blockmask, _mm_cmplt_epi8(input, _mm_set1_epi8(63)));
            blockmask = _mm_or_si128(blockmask, s4mask);
            let s1 = _mm_and_si128(s1mask, _mm_add_epi8(input, _mm_set1_epi8(b'A' as i8)));
            let s2 = _mm_and_si128(s2mask, _mm_add_epi8(input, _mm_set1_epi8(b'a' as i8 - 26)));
            let s3 = _mm_and_si128(s3mask, _mm_add_epi8(input, _mm_set1_epi8(b'0' as i8 - 52)));
            let s4 = _mm_and_si128(s4mask, _mm_set1_epi8(b'+' as i8));
            let s5 = _mm_andnot_si128(blockmask, _mm_set1_epi8(b'/' as i8));
            _mm_or_si128(s1, _mm_or_si128(s2, _mm_or_si128(s3, _mm_or_si128(s4, s5))))
        }
    }

    impl Translate128i for UrlSafeAlphabet {
        #[inline]
        #[target_feature(enable = "sse")]
        unsafe fn translate_m128i(input: __m128i) -> __m128i {
            let s1mask = _mm_cmplt_epi8(input, _mm_set1_epi8(26));
            let mut blockmask = s1mask;
            let s2mask = _mm_andnot_si128(blockmask, _mm_cmplt_epi8(input, _mm_set1_epi8(52)));
            blockmask = _mm_or_si128(blockmask, s2mask);
            let s3mask = _mm_andnot_si128(blockmask, _mm_cmplt_epi8(input, _mm_set1_epi8(62)));
            blockmask = _mm_or_si128(blockmask, s3mask);
            let s4mask = _mm_andnot_si128(blockmask, _mm_cmplt_epi8(input, _mm_set1_epi8(63)));
            blockmask = _mm_or_si128(blockmask, s4mask);
            let s1 = _mm_and_si128(s1mask, _mm_add_epi8(input, _mm_set1_epi8(b'A' as i8)));
            let s2 = _mm_and_si128(s2mask, _mm_add_epi8(input, _mm_set1_epi8(b'a' as i8 - 26)));
            let s3 = _mm_and_si128(s3mask, _mm_add_epi8(input, _mm_set1_epi8(b'0' as i8 - 52)));
            let s4 = _mm_and_si128(s4mask, _mm_set1_epi8(b'-' as i8));
            let s5 = _mm_andnot_si128(blockmask, _mm_set1_epi8(b'_' as i8));
            _mm_or_si128(s1, _mm_or_si128(s2, _mm_or_si128(s3, _mm_or_si128(s4, s5))))
        }
    }

    impl Translate128i for CryptAlphabet {
        #[inline]
        #[target_feature(enable = "sse")]
        unsafe fn translate_m128i(input: __m128i) -> __m128i {
            let s1mask = _mm_cmplt_epi8(input, _mm_set1_epi8(12));
            let mut blockmask = s1mask;
            let s2mask = _mm_andnot_si128(blockmask, _mm_cmplt_epi8(input, _mm_set1_epi8(38)));
            blockmask = _mm_or_si128(blockmask, s2mask);
            let s1 = _mm_and_si128(s1mask, _mm_add_epi8(input, _mm_set1_epi8(b'.' as i8)));
            let s2 = _mm_and_si128(s2mask, _mm_add_epi8(input, _mm_set1_epi8(b'A' as i8 - 12)));
            let s3 = _mm_andnot_si128(
                blockmask,
                _mm_add_epi8(input, _mm_set1_epi8(b'a' as i8 - 38)),
            );
            _mm_or_si128(s1, _mm_or_si128(s2, s3))
        }
    }
}

/// AVX2 implementation of B64 encoding.
mod avx2 {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;
    use ::{CryptAlphabet, StdAlphabet, UrlSafeAlphabet};

    #[derive(Debug, Default, Clone, Copy)]
    pub(super) struct BlockEncoding<E>(E);
    impl<E> BlockEncoding<E> {
        const INPUT_CHUNK_BYTES_READ: usize = 28;
        const INPUT_CHUNK_BYTES_ENCODED: usize = 24;
        const OUTPUT_CHUNK_BYTES_WRITTEN: usize = 32;

        #[inline]
        pub(super) fn new(encoding: E) -> Result<BlockEncoding<E>, ()> {
            if is_x86_feature_detected!("avx2") {
                Ok(BlockEncoding(encoding))
            } else {
                Err(())
            }
        }

        #[inline]
        pub(super) fn encode_blocks(self, input: &[u8], output: &mut [u8]) -> (usize, usize)
        where
            E: Translate256i,
        {
            unsafe { self._encode_blocks(input, output) }
        }

        #[inline]
        #[target_feature(enable = "avx2")]
        unsafe fn _encode_blocks(self, input: &[u8], output: &mut [u8]) -> (usize, usize)
        where
            E: Translate256i,
        {
            let mut output_index: usize = 0;
            let last_index = input.len() as isize - Self::INPUT_CHUNK_BYTES_READ as isize;
            let mut input_index = 0;
            while input_index as isize <= last_index {
                // This is a straightforward adaptation of the SSE implemenation
                // above, just extended for 256 bit registers.
                let input_ptr = input.as_ptr().add(input_index);
                #[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
                let lo_data = _mm_loadu_si128(input_ptr as *const __m128i);
                #[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
                let hi_data = _mm_loadu_si128(input_ptr.add(12) as *const __m128i);
                let mut data = _mm256_set_m128i(hi_data, lo_data);
                data = _mm256_shuffle_epi8(
                    data,
                    _mm256_setr_epi8(
                        2, 2, 1, 0, 5, 5, 4, 3, 8, 8, 7, 6, 11, 11, 10, 9, 2, 2, 1, 0, 5, 5, 4, 3, 8,
                        8, 7, 6, 11, 11, 10, 9,
                    ),
                );
                let mut mask = _mm256_set1_epi32(0x3F00_0000);
                let mut res = _mm256_and_si256(_mm256_srli_epi32(data, 2), mask);
                mask = _mm256_srli_epi32(mask, 8);
                res = _mm256_or_si256(res, _mm256_and_si256(_mm256_srli_epi32(data, 4), mask));
                mask = _mm256_srli_epi32(mask, 8);
                res = _mm256_or_si256(res, _mm256_and_si256(_mm256_srli_epi32(data, 6), mask));
                mask = _mm256_srli_epi32(mask, 8);
                res = _mm256_or_si256(res, _mm256_and_si256(data, mask));

                res = _mm256_shuffle_epi8(
                    res,
                    _mm256_setr_epi8(
                        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 19, 18, 17, 16, 23, 22,
                        21, 20, 27, 26, 25, 24, 31, 30, 29, 28,
                    ),
                );
                res = E::translate_m256i(res);

                #[cfg_attr(feature = "cargo-clippy", allow(cast_ptr_alignment))]
                _mm256_storeu_si256(output.as_mut_ptr().add(output_index) as *mut __m256i, res);
                input_index += Self::INPUT_CHUNK_BYTES_ENCODED;
                output_index += Self::OUTPUT_CHUNK_BYTES_WRITTEN;
            }
            (input_index, output_index)
        }
    }

    pub trait Translate256i {
        unsafe fn translate_m256i(input: __m256i) -> __m256i;
    }

    impl Translate256i for StdAlphabet {
        #[inline]
        #[target_feature(enable = "avx2")]
        unsafe fn translate_m256i(input: __m256i) -> __m256i {
            let s1mask = _mm256_cmpgt_epi8(_mm256_set1_epi8(26), input);
            let mut blockmask = s1mask;
            let s2mask = _mm256_andnot_si256(blockmask, _mm256_cmpgt_epi8(_mm256_set1_epi8(52), input));
            blockmask = _mm256_or_si256(blockmask, s2mask);
            let s3mask = _mm256_andnot_si256(blockmask, _mm256_cmpgt_epi8(_mm256_set1_epi8(62), input));
            blockmask = _mm256_or_si256(blockmask, s3mask);
            let s4mask = _mm256_andnot_si256(blockmask, _mm256_cmpgt_epi8(_mm256_set1_epi8(63), input));
            blockmask = _mm256_or_si256(blockmask, s4mask);
            let s1 = _mm256_and_si256(s1mask, _mm256_add_epi8(input, _mm256_set1_epi8(b'A' as i8)));
            let s2 = _mm256_and_si256(
                s2mask,
                _mm256_add_epi8(input, _mm256_set1_epi8(b'a' as i8 - 26)),
            );
            let s3 = _mm256_and_si256(
                s3mask,
                _mm256_add_epi8(input, _mm256_set1_epi8(b'0' as i8 - 52)),
            );
            let s4 = _mm256_and_si256(s4mask, _mm256_set1_epi8(b'+' as i8));
            let s5 = _mm256_andnot_si256(blockmask, _mm256_set1_epi8(b'/' as i8));
            _mm256_or_si256(
                s1,
                _mm256_or_si256(s2, _mm256_or_si256(s3, _mm256_or_si256(s4, s5))),
            )
        }
    }

    impl Translate256i for UrlSafeAlphabet {
        #[inline]
        #[target_feature(enable = "avx2")]
        unsafe fn translate_m256i(input: __m256i) -> __m256i {
            let s1mask = _mm256_cmpgt_epi8(_mm256_set1_epi8(26), input);
            let mut blockmask = s1mask;
            let s2mask = _mm256_andnot_si256(blockmask, _mm256_cmpgt_epi8(_mm256_set1_epi8(52), input));
            blockmask = _mm256_or_si256(blockmask, s2mask);
            let s3mask = _mm256_andnot_si256(blockmask, _mm256_cmpgt_epi8(_mm256_set1_epi8(62), input));
            blockmask = _mm256_or_si256(blockmask, s3mask);
            let s4mask = _mm256_andnot_si256(blockmask, _mm256_cmpgt_epi8(_mm256_set1_epi8(63), input));
            blockmask = _mm256_or_si256(blockmask, s4mask);
            let s1 = _mm256_and_si256(s1mask, _mm256_add_epi8(input, _mm256_set1_epi8(b'A' as i8)));
            let s2 = _mm256_and_si256(
                s2mask,
                _mm256_add_epi8(input, _mm256_set1_epi8(b'a' as i8 - 26)),
            );
            let s3 = _mm256_and_si256(
                s3mask,
                _mm256_add_epi8(input, _mm256_set1_epi8(b'0' as i8 - 52)),
            );
            let s4 = _mm256_and_si256(s4mask, _mm256_set1_epi8(b'-' as i8));
            let s5 = _mm256_andnot_si256(blockmask, _mm256_set1_epi8(b'_' as i8));
            _mm256_or_si256(
                s1,
                _mm256_or_si256(s2, _mm256_or_si256(s3, _mm256_or_si256(s4, s5))),
            )
        }
    }

    impl Translate256i for CryptAlphabet {
        #[inline]
        #[target_feature(enable = "avx2")]
        unsafe fn translate_m256i(input: __m256i) -> __m256i {
            let s1mask = _mm256_cmpgt_epi8(_mm256_set1_epi8(12), input);
            let mut blockmask = s1mask;
            let s2mask = _mm256_andnot_si256(blockmask, _mm256_cmpgt_epi8(_mm256_set1_epi8(38), input));
            blockmask = _mm256_or_si256(blockmask, s2mask);
            let s1 = _mm256_and_si256(s1mask, _mm256_add_epi8(input, _mm256_set1_epi8(b'.' as i8)));
            let s2 = _mm256_and_si256(
                s2mask,
                _mm256_add_epi8(input, _mm256_set1_epi8(b'A' as i8 - 12)),
            );
            let s3 = _mm256_andnot_si256(
                blockmask,
                _mm256_add_epi8(input, _mm256_set1_epi8(b'a' as i8 - 38)),
            );
            _mm256_or_si256(s1, _mm256_or_si256(s2, s3))
        }
    }
}