use base64::{
    alphabet,
    engine::{
        general_purpose::{self, GeneralPurpose},
        Engine,
    },
    write,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::{rngs, RngExt, SeedableRng};
use std::hint::black_box;
use std::io::Write;

const SMALL_RAW_BYTE_SIZES: &[usize] = &[
    0, 1, 2, 3, 4, 8, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024,
];
const LARGE_RAW_BYTE_SIZES: &[usize] = &[4096, 16_384, 65_536, 1_048_576];
const VERY_LARGE_RAW_BYTE_SIZES: &[usize] = &[3 * 1024 * 1024, 10 * 1024 * 1024, 30 * 1024 * 1024];

fn input(size: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size);
    let mut rng = rngs::SmallRng::seed_from_u64(size as u64);
    while bytes.len() < size {
        bytes.push(rng.random());
    }
    bytes
}

fn encode_benchmarks<E: Engine>(
    c: &mut Criterion,
    size_class: &str,
    config: &str,
    engine_name: &str,
    engine: &E,
    sizes: &[usize],
) {
    let mut group = c.benchmark_group(format!("encode/{size_class}/{config}/{engine_name}"));
    group
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(3));
    if size_class == "very_large" {
        group.sample_size(10);
    }

    for &size in sizes {
        let input = input(size);
        let output_len = engine.encode(&input).len();
        if size > 0 {
            group.throughput(Throughput::Bytes(size as u64));
        }

        group.bench_with_input(
            BenchmarkId::new("allocate_raw_bytes", size),
            &input,
            |b, input| b.iter(|| black_box(engine.encode(black_box(input)))),
        );

        let mut slice_output = vec![0; output_len];
        group.bench_with_input(
            BenchmarkId::new("slice_raw_bytes", size),
            &input,
            |b, input| {
                b.iter(|| {
                    black_box(
                        engine
                            .encode_slice(black_box(input), black_box(&mut slice_output))
                            .unwrap(),
                    )
                })
            },
        );

        let mut reused_output = String::with_capacity(output_len);
        group.bench_with_input(
            BenchmarkId::new("reuse_string_raw_bytes", size),
            &input,
            |b, input| {
                b.iter(|| {
                    reused_output.clear();
                    engine.encode_string(black_box(input), black_box(&mut reused_output));
                    black_box(&reused_output);
                })
            },
        );

        let mut writer_output = Vec::with_capacity(output_len);
        group.bench_with_input(
            BenchmarkId::new("append_writer_vec_raw_bytes", size),
            &input,
            |b, input| {
                b.iter(|| {
                    writer_output.clear();
                    {
                        let mut writer = write::EncoderWriter::new(&mut writer_output, engine);
                        writer.write_all(black_box(input)).unwrap();
                        let _ = writer.finish().unwrap();
                    }
                    black_box(&writer_output);
                })
            },
        );
    }

    group.finish();
}

fn decode_benchmarks<E: Engine>(
    c: &mut Criterion,
    size_class: &str,
    config: &str,
    engine_name: &str,
    engine: &E,
    sizes: &[usize],
) {
    let mut group = c.benchmark_group(format!("decode/{size_class}/{config}/{engine_name}"));
    group
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(3));
    if size_class == "very_large" {
        group.sample_size(10);
    }

    for &size in sizes {
        let raw_input = input(size);
        let encoded = engine.encode(&raw_input);
        let size_label = format!("raw_bytes_{size}_encoded_bytes_{}", encoded.len());
        if !encoded.is_empty() {
            group.throughput(Throughput::Bytes(encoded.len() as u64));
        }

        group.bench_with_input(
            BenchmarkId::new("allocate", &size_label),
            &encoded,
            |b, encoded| b.iter(|| black_box(engine.decode(black_box(encoded)).unwrap())),
        );

        let mut slice_output = vec![0; size];
        group.bench_with_input(
            BenchmarkId::new("slice", &size_label),
            &encoded,
            |b, encoded| {
                b.iter(|| {
                    black_box(
                        engine
                            .decode_slice(black_box(encoded), black_box(&mut slice_output))
                            .unwrap(),
                    )
                })
            },
        );

        let mut reused_output = Vec::with_capacity(size);
        group.bench_with_input(
            BenchmarkId::new("reuse_vec", &size_label),
            &encoded,
            |b, encoded| {
                b.iter(|| {
                    reused_output.clear();
                    engine
                        .decode_vec(black_box(encoded), black_box(&mut reused_output))
                        .unwrap();
                    black_box(&reused_output);
                })
            },
        );
    }

    group.finish();
}

#[derive(Clone, Copy)]
enum InvalidCase {
    Beginning,
    Middle,
    End,
    TrailingBits,
    Padding,
    ScalarTail,
}

impl InvalidCase {
    const ALL: [Self; 6] = [
        Self::Beginning,
        Self::Middle,
        Self::End,
        Self::TrailingBits,
        Self::Padding,
        Self::ScalarTail,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Beginning => "invalid_beginning",
            Self::Middle => "invalid_middle",
            Self::End => "invalid_end",
            Self::TrailingBits => "invalid_trailing_bits",
            Self::Padding => "invalid_padding",
            Self::ScalarTail => "simd_prefix_invalid_scalar_tail",
        }
    }
}

fn invalid_input(size: usize, invalid_case: InvalidCase) -> Option<Vec<u8>> {
    let raw_input = input(size);
    let mut encoded = general_purpose::STANDARD.encode(raw_input).into_bytes();

    match invalid_case {
        InvalidCase::Beginning if !encoded.is_empty() => encoded[0] = b'$',
        InvalidCase::Middle if !encoded.is_empty() => {
            let middle = encoded.len() / 2;
            encoded[middle] = b'$';
        }
        InvalidCase::End if !encoded.is_empty() => {
            let end = encoded.len() - 1;
            encoded[end] = b'$';
        }
        InvalidCase::TrailingBits => {
            encoded = general_purpose::STANDARD
                .encode(input(size - (size % 3)))
                .into_bytes();
            encoded.extend_from_slice(b"AB==");
        }
        InvalidCase::Padding => {
            encoded = general_purpose::STANDARD
                .encode(input(size - (size % 3)))
                .into_bytes();
            encoded.push(b'=');
        }
        InvalidCase::ScalarTail if encoded.len() >= 64 => {
            let end = encoded.len() - 1;
            encoded[end] = b'$';
        }
        _ => return None,
    }

    Some(encoded)
}

fn decode_error_benchmarks<E: Engine>(c: &mut Criterion, engine_name: &str, engine: &E) {
    let mut group = c.benchmark_group(format!("decode/errors/standard_padded/{engine_name}"));
    group
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(3));

    for &size in SMALL_RAW_BYTE_SIZES.iter().chain(LARGE_RAW_BYTE_SIZES) {
        for invalid_case in InvalidCase::ALL {
            let Some(encoded) = invalid_input(size, invalid_case) else {
                continue;
            };
            let mut output = vec![0; size + 3];
            assert!(engine.decode_slice(&encoded, &mut output).is_err());
            group.throughput(Throughput::Bytes(encoded.len() as u64));
            group.bench_with_input(
                BenchmarkId::new(
                    invalid_case.name(),
                    format!("raw_bytes_{size}_encoded_bytes_{}", encoded.len()),
                ),
                &encoded,
                |b, encoded| {
                    b.iter(|| {
                        black_box(engine.decode_slice(black_box(encoded), black_box(&mut output)))
                    })
                },
            );
        }
    }

    group.finish();
}

fn benchmark_engine<E: Engine>(
    c: &mut Criterion,
    config_name: &str,
    engine_name: &str,
    engine: &E,
) {
    encode_benchmarks(
        c,
        "latency",
        config_name,
        engine_name,
        engine,
        SMALL_RAW_BYTE_SIZES,
    );
    encode_benchmarks(
        c,
        "throughput",
        config_name,
        engine_name,
        engine,
        LARGE_RAW_BYTE_SIZES,
    );
    decode_benchmarks(
        c,
        "latency",
        config_name,
        engine_name,
        engine,
        SMALL_RAW_BYTE_SIZES,
    );
    decode_benchmarks(
        c,
        "throughput",
        config_name,
        engine_name,
        engine,
        LARGE_RAW_BYTE_SIZES,
    );
}

fn benchmark_config(
    c: &mut Criterion,
    config_name: &str,
    alphabet: &alphabet::Alphabet,
    _url_safe: bool,
    config: general_purpose::GeneralPurposeConfig,
) {
    let scalar = GeneralPurpose::new(alphabet, config);
    benchmark_engine(c, config_name, "general_purpose", &scalar);

    #[cfg(all(
        feature = "simd-unsafe",
        feature = "std",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let runtime = if _url_safe {
            base64::engine::Simd::url_safe(config)
        } else {
            base64::engine::Simd::standard(config)
        };
        benchmark_engine(c, config_name, "simd", &runtime);
    }

    #[cfg(all(feature = "simd-unsafe", target_arch = "x86_64"))]
    {
        let explicit = if _url_safe {
            base64::engine::Avx2::url_safe(config)
        } else {
            base64::engine::Avx2::standard(config)
        };
        if let Some(explicit) = explicit {
            benchmark_engine(c, config_name, "avx2", &explicit);
        }
    }

    #[cfg(all(feature = "simd-unsafe", target_arch = "aarch64"))]
    {
        let explicit = if _url_safe {
            base64::engine::Neon::url_safe(config)
        } else {
            base64::engine::Neon::standard(config)
        };
        benchmark_engine(c, config_name, "neon", &explicit);
    }
}

fn valid_benchmarks(c: &mut Criterion) {
    benchmark_config(
        c,
        "standard_padded",
        &alphabet::STANDARD,
        false,
        general_purpose::PAD,
    );
    benchmark_config(
        c,
        "standard_unpadded",
        &alphabet::STANDARD,
        false,
        general_purpose::NO_PAD,
    );
    benchmark_config(
        c,
        "url_safe_padded",
        &alphabet::URL_SAFE,
        true,
        general_purpose::PAD,
    );
    benchmark_config(
        c,
        "url_safe_unpadded",
        &alphabet::URL_SAFE,
        true,
        general_purpose::NO_PAD,
    );
}

fn invalid_benchmarks(c: &mut Criterion) {
    decode_error_benchmarks(c, "general_purpose", &general_purpose::STANDARD);

    #[cfg(all(
        feature = "simd-unsafe",
        feature = "std",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    decode_error_benchmarks(
        c,
        "simd",
        &base64::engine::Simd::standard(general_purpose::PAD),
    );

    #[cfg(all(feature = "simd-unsafe", target_arch = "x86_64"))]
    if let Some(avx2) = base64::engine::Avx2::standard(general_purpose::PAD) {
        decode_error_benchmarks(c, "avx2", &avx2);
    }

    #[cfg(all(feature = "simd-unsafe", target_arch = "aarch64"))]
    decode_error_benchmarks(
        c,
        "neon",
        &base64::engine::Neon::standard(general_purpose::PAD),
    );
}

fn very_large_benchmarks(c: &mut Criterion) {
    encode_benchmarks(
        c,
        "very_large",
        "standard_padded",
        "general_purpose",
        &general_purpose::STANDARD,
        VERY_LARGE_RAW_BYTE_SIZES,
    );
    decode_benchmarks(
        c,
        "very_large",
        "standard_padded",
        "general_purpose",
        &general_purpose::STANDARD,
        VERY_LARGE_RAW_BYTE_SIZES,
    );

    #[cfg(all(
        feature = "simd-unsafe",
        feature = "std",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let simd = base64::engine::Simd::standard(general_purpose::PAD);
        encode_benchmarks(
            c,
            "very_large",
            "standard_padded",
            "simd",
            &simd,
            VERY_LARGE_RAW_BYTE_SIZES,
        );
        decode_benchmarks(
            c,
            "very_large",
            "standard_padded",
            "simd",
            &simd,
            VERY_LARGE_RAW_BYTE_SIZES,
        );
    }
}

criterion_group!(
    benches,
    valid_benchmarks,
    invalid_benchmarks,
    very_large_benchmarks
);
criterion_main!(benches);
