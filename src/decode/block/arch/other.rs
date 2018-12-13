//! This module is included whenever running on an architecture that doesn't
//! have a specialized module.

use ::{CryptAlphabet, IntoBlockDecoding, StdAlphabet, UrlSafeAlphabet};
use ::decode::block::ScalarBlockDecoding;

impl IntoBlockDecoding for StdAlphabet {
    type BlockDecoding = ScalarBlockDecoding<Self>;

    #[inline]
    fn into_block_decoding(self) -> Self::BlockDecoding {
        ScalarBlockDecoding(self)
    }
}

impl IntoBlockDecoding for UrlSafeAlphabet {
    type BlockDecoding = ScalarBlockDecoding<Self>;

    #[inline]
    fn into_block_decoding(self) -> Self::BlockDecoding {
        ScalarBlockDecoding(self)
    }
}

impl IntoBlockDecoding for CryptAlphabet {
    type BlockDecoding = ScalarBlockDecoding<Self>;

    #[inline]
    fn into_block_decoding(self) -> Self::BlockDecoding {
        ScalarBlockDecoding(self)
    }
}