//! This module is included whenever running on an architecture that doesn't
//! have a specialized module.

use ::{CryptAlphabet, IntoBlockEncoding, StdAlphabet, UrlSafeAlphabet};
use ::encode::block::ScalarBlockEncoding;

impl IntoBlockEncoding for StdAlphabet {
    type BlockEncoding = ScalarBlockEncoding<Self>;

    #[inline]
    fn into_block_encoding(self) -> Self::BlockEncoding {
        ScalarBlockEncoding(self)
    }
}

impl IntoBlockEncoding for UrlSafeAlphabet {
    type BlockEncoding = ScalarBlockEncoding<Self>;

    #[inline]
    fn into_block_encoding(self) -> Self::BlockEncoding {
        ScalarBlockEncoding(self)
    }
}

impl IntoBlockEncoding for CryptAlphabet {
    type BlockEncoding = ScalarBlockEncoding<Self>;

    #[inline]
    fn into_block_encoding(self) -> Self::BlockEncoding {
        ScalarBlockEncoding(self)
    }
}