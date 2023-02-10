use crate::{
    alphabet::Alphabet,
    engine::{
        general_purpose::{self, decode_table, encode_table},
        Config, DecodePaddingMode, Engine,
    },
    DecodeError, PAD_BYTE,
};
use alloc::ops::BitOr;
use std::ops::{BitAnd, Shl, Shr};

/// Comparatively simple implementation that can be used as something to compare against in tests
pub struct Naive {
    encode_table: [u8; 64],
    decode_table: [u8; 256],
    config: NaiveConfig,
}

impl Naive {
    const ENCODE_INPUT_CHUNK_SIZE: usize = 3;
    const DECODE_INPUT_CHUNK_SIZE: usize = 4;

    pub const fn new(alphabet: &Alphabet, config: NaiveConfig) -> Self {
        Self {
            encode_table: encode_table(alphabet),
            decode_table: decode_table(alphabet),
            config,
        }
    }

    fn decode_byte_into_u32(&self, offset: usize, byte: u8) -> Result<u32, DecodeError> {
        let decoded = self.decode_table[byte as usize];

        if decoded == general_purpose::INVALID_VALUE {
            return Err(DecodeError::InvalidByte(offset, byte));
        }

        Ok(decoded as u32)
    }
}

impl Engine for Naive {
    type Config = NaiveConfig;

    fn internal_encode(&self, input: &[u8], output: &mut [u8]) -> usize {
        // complete chunks first

        const LOW_SIX_BITS: u32 = 0x3F;

        let rem = input.len() % Self::ENCODE_INPUT_CHUNK_SIZE;
        // will never underflow
        let complete_chunk_len = input.len() - rem;

        let mut input_index = 0_usize;
        let mut output_index = 0_usize;
        if let Some(last_complete_chunk_index) =
            complete_chunk_len.checked_sub(Self::ENCODE_INPUT_CHUNK_SIZE)
        {
            while input_index <= last_complete_chunk_index {
                let chunk = &input[input_index..input_index + Self::ENCODE_INPUT_CHUNK_SIZE];

                // populate low 24 bits from 3 bytes
                let chunk_int: u32 =
                    (chunk[0] as u32).shl(16) | (chunk[1] as u32).shl(8) | (chunk[2] as u32);
                // encode 4x 6-bit output bytes
                output[output_index] = self.encode_table[chunk_int.shr(18) as usize];
                output[output_index + 1] =
                    self.encode_table[chunk_int.shr(12_u8).bitand(LOW_SIX_BITS) as usize];
                output[output_index + 2] =
                    self.encode_table[chunk_int.shr(6_u8).bitand(LOW_SIX_BITS) as usize];
                output[output_index + 3] =
                    self.encode_table[chunk_int.bitand(LOW_SIX_BITS) as usize];

                input_index += Self::ENCODE_INPUT_CHUNK_SIZE;
                output_index += 4;
            }
        }

        // then leftovers
        if rem == 2 {
            let chunk = &input[input_index..input_index + 2];

            // high six bits of chunk[0]
            output[output_index] = self.encode_table[chunk[0].shr(2) as usize];
            // bottom 2 bits of [0], high 4 bits of [1]
            output[output_index + 1] =
                self.encode_table[(chunk[0].shl(4_u8).bitor(chunk[1].shr(4_u8)) as u32)
                    .bitand(LOW_SIX_BITS) as usize];
            // bottom 4 bits of [1], with the 2 bottom bits as zero
            output[output_index + 2] =
                self.encode_table[(chunk[1].shl(2_u8) as u32).bitand(LOW_SIX_BITS) as usize];

            output_index += 3;
        } else if rem == 1 {
            let byte = input[input_index];
            output[output_index] = self.encode_table[byte.shr(2) as usize];
            output[output_index + 1] =
                self.encode_table[(byte.shl(4_u8) as u32).bitand(LOW_SIX_BITS) as usize];
            output_index += 2;
        }

        output_index
    }

    fn internal_decode(&self, input: &[u8], output: &mut [u8]) -> Result<(), DecodeError> {
        let full_chunks = match input.len() % 4 {
            0 => {
                if input.is_empty() {
                    debug_assert!(output.is_empty());
                    return Ok(());
                } else {
                    input.len() / Self::DECODE_INPUT_CHUNK_SIZE - 1
                }
            }
            1 => {
                // Trailing whitespace is so common that it's worth it to check
                // the last byte to possibly return a better error message
                let last = input[input.len() - 1];
                let value = self.decode_table[last as usize];
                if last != PAD_BYTE && value == general_purpose::INVALID_VALUE {
                    return Err(DecodeError::InvalidByte(input.len() - 1, last));
                } else {
                    return Err(DecodeError::InvalidLength);
                }
            }
            _ => input.len() / Self::DECODE_INPUT_CHUNK_SIZE,
        };
        let full_bytes = full_chunks * Self::DECODE_INPUT_CHUNK_SIZE;
        let mut output_index = 0_usize;
        const BOTTOM_BYTE: u32 = 0xFF;

        for input_index in (0..full_bytes).step_by(Self::DECODE_INPUT_CHUNK_SIZE) {
            let chunk = &input[input_index..input_index + Self::DECODE_INPUT_CHUNK_SIZE];
            let decoded_int: u32 = self.decode_byte_into_u32(input_index, chunk[0])?.shl(18)
                | self
                    .decode_byte_into_u32(input_index + 1, chunk[1])?
                    .shl(12)
                | self.decode_byte_into_u32(input_index + 2, chunk[2])?.shl(6)
                | self.decode_byte_into_u32(input_index + 3, chunk[3])?;

            output[output_index] = decoded_int.shr(16_u8).bitand(BOTTOM_BYTE) as u8;
            output[output_index + 1] = decoded_int.shr(8_u8).bitand(BOTTOM_BYTE) as u8;
            output[output_index + 2] = decoded_int.bitand(BOTTOM_BYTE) as u8;
            output_index += 3;
        }

        general_purpose::decode_suffix::decode_suffix(
            input,
            full_bytes,
            output,
            output_index,
            &self.decode_table,
            self.config.decode_allow_trailing_bits,
            self.config.decode_padding_mode,
        )
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NaiveConfig {
    pub encode_padding: bool,
    pub decode_allow_trailing_bits: bool,
    pub decode_padding_mode: DecodePaddingMode,
}

impl Config for NaiveConfig {
    fn encode_padding(&self) -> bool {
        self.encode_padding
    }
}
