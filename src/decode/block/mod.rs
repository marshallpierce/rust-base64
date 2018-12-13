use super::{decode_chunk, DecodeError, Decoding};

mod arch;

/// Create and return a type that impelements BlockDecoding.
pub trait IntoBlockDecoding: ::private::Sealed + Copy {
    /// The BlockDecoding type returned.
    type BlockDecoding: BlockDecoding;

    /// Create and return the BlockDecoding type to use.
    fn into_block_decoding(self) -> Self::BlockDecoding;
}

/// Decode input bytes in blocks for performance. Different configurations and
/// machines will use different types that all implement BlockDecoding. See
/// IntoBlockDecoding implementations to see which type is used.
pub trait BlockDecoding: ::private::Sealed {
    /// Decode input.
    fn decode_blocks(self, input: &[u8], output: &mut [u8]) -> Result<(usize, usize), DecodeError>;
}

#[derive(Debug, Default, Copy, Clone)]
pub struct ScalarBlockDecoding<D>(D);
impl<D> ScalarBlockDecoding<D>
where
    D: Decoding,
{
    const INPUT_CHUNK_BYTES_READ: usize = 32;
    const OUTPUT_CHUNK_BYTES_DECODED: usize = 24;
    const OUTPUT_CHUNK_BYTES_WRITTEN: usize = 26;

    pub(crate) fn new(decoding: D) -> Self {
        ScalarBlockDecoding(decoding)
    }
}

impl<D> BlockDecoding for ScalarBlockDecoding<D>
where
    D: Decoding,
{
    #[inline]
    fn decode_blocks(self, input: &[u8], output: &mut [u8]) -> Result<(usize, usize), DecodeError> {
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
            let input_slice = &input[input_index..(input_index + Self::INPUT_CHUNK_BYTES_READ)];
            let output_slice =
                &mut output[output_index..(output_index + Self::OUTPUT_CHUNK_BYTES_WRITTEN)];
            decode_chunk(
                &input_slice[0..],
                input_index,
                self.0,
                &mut output_slice[0..],
            )?;
            decode_chunk(
                &input_slice[8..],
                input_index + 8,
                self.0,
                &mut output_slice[6..],
            )?;
            decode_chunk(
                &input_slice[16..],
                input_index + 16,
                self.0,
                &mut output_slice[12..],
            )?;
            decode_chunk(
                &input_slice[24..],
                input_index + 24,
                self.0,
                &mut output_slice[18..],
            )?;
            input_index += Self::INPUT_CHUNK_BYTES_READ;
            output_index += Self::OUTPUT_CHUNK_BYTES_DECODED;
        }
        Ok((input_index, output_index))
    }
}

impl<D> ::private::Sealed for ScalarBlockDecoding<D> {}

impl IntoBlockDecoding for &::CustomConfig {
    type BlockDecoding = ScalarBlockDecoding<Self>;

    #[inline]
    fn into_block_decoding(self) -> ScalarBlockDecoding<Self> {
        ScalarBlockDecoding::new(self)
    }
}

/// Given and input and output slice, along with the size of input chunks read
/// and output chunks written, determine the input offset limit such that it's
/// safe to process a chunk so long as the beginning of the chunk is less than
/// the returned offset.
#[inline]
pub(super) fn input_limit(
    input: &[u8],
    output: &mut [u8],
    input_chunk_bytes: usize,
    output_chunk_bytes_written: usize,
    output_chunk_bytes_decoded: usize,
) -> usize {
    let max_input_chunks = input.len() / input_chunk_bytes;
    let max_output_chunks = if output.len() < output_chunk_bytes_written {
        0
    } else {
        let size_before_final_chunk = output.len() - output_chunk_bytes_written;
        1 + size_before_final_chunk / output_chunk_bytes_decoded
    };
    let max_chunks_allowed = std::cmp::min(max_input_chunks, max_output_chunks);
    (max_chunks_allowed * input_chunk_bytes).saturating_sub(input_chunk_bytes.saturating_sub(1))
}
