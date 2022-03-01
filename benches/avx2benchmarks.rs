extern crate base64;
#[macro_use]
extern crate criterion;
extern crate rand;

#[macro_use]
extern crate lazy_static;

use std::ops::Deref;

use base64::display;
use base64::{
    decode_engine, decode_engine_slice, decode_engine_vec, encode_engine, encode_engine_slice,
    encode_engine_string, engine::DEFAULT_ENGINE, write,
};

use base64::engine::avx2::{AVX2Config, AVX2Encoder};
use criterion::{black_box, Bencher, BenchmarkId, Criterion, Throughput};
use rand::{FromEntropy, Rng};
use std::io::{self, Read, Write};

lazy_static! {
    static ref AVX2_ENGINE: AVX2Encoder = AVX2Encoder::from_standard(AVX2Config::new());
}

fn do_decode_bench(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size * 3 / 4);
    fill(&mut v);
    let encoded = encode_engine(&v, &DEFAULT_ENGINE);

    b.iter(|| {
        let orig = decode_engine(&encoded, &DEFAULT_ENGINE);
        black_box(&orig);
    });
}
fn do_decode_bench_avx(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size * 3 / 4);
    fill(&mut v);
    let encoded = encode_engine(&v, AVX2_ENGINE.deref());

    b.iter(|| {
        let orig = decode_engine(&encoded, AVX2_ENGINE.deref());
        black_box(&orig);
    });
}

fn do_decode_bench_reuse_buf(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size * 3 / 4);
    fill(&mut v);
    let encoded = encode_engine(&v, &DEFAULT_ENGINE);

    let mut buf = Vec::new();
    b.iter(|| {
        decode_engine_vec(&encoded, &mut buf, &DEFAULT_ENGINE).unwrap();
        black_box(&buf);
        buf.clear();
    });
}

fn do_decode_bench_reuse_buf_avx(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size * 3 / 4);
    fill(&mut v);
    let encoded = encode_engine(&v, AVX2_ENGINE.deref());

    let mut buf = Vec::new();
    b.iter(|| {
        decode_engine_vec(&encoded, &mut buf, AVX2_ENGINE.deref()).unwrap();
        black_box(&buf);
        buf.clear();
    });
}

fn do_decode_bench_slice(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size * 3 / 4);
    fill(&mut v);
    let encoded = encode_engine(&v, &DEFAULT_ENGINE);

    let mut buf = Vec::new();
    buf.resize(size, 0);
    b.iter(|| {
        decode_engine_slice(&encoded, &mut buf, &DEFAULT_ENGINE).unwrap();
        black_box(&buf);
    });
}

fn do_decode_bench_slice_avx(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size * 3 / 4);
    fill(&mut v);
    let encoded = encode_engine(&v, AVX2_ENGINE.deref());

    let mut buf = Vec::new();
    buf.resize(size, 0);
    b.iter(|| {
        decode_engine_slice(&encoded, &mut buf, AVX2_ENGINE.deref()).unwrap();
        black_box(&buf);
    });
}

fn do_decode_bench_stream(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size * 3 / 4);
    fill(&mut v);
    let encoded = encode_engine(&v, &DEFAULT_ENGINE);

    let mut buf = Vec::new();
    buf.resize(size, 0);
    buf.truncate(0);

    b.iter(|| {
        let mut cursor = io::Cursor::new(&encoded[..]);
        let mut decoder = base64::read::DecoderReader::from(&mut cursor, &DEFAULT_ENGINE);
        decoder.read_to_end(&mut buf).unwrap();
        buf.clear();
        black_box(&buf);
    });
}

fn do_decode_bench_stream_avx(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size * 3 / 4);
    fill(&mut v);
    let encoded = encode_engine(&v, AVX2_ENGINE.deref());

    let mut buf = Vec::new();
    buf.resize(size, 0);
    buf.truncate(0);

    b.iter(|| {
        let mut cursor = io::Cursor::new(&encoded[..]);
        let mut decoder = base64::read::DecoderReader::from(&mut cursor, AVX2_ENGINE.deref());
        decoder.read_to_end(&mut buf).unwrap();
        buf.clear();
        black_box(&buf);
    });
}

fn do_encode_bench(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);
    b.iter(|| {
        let e = encode_engine(&v, &DEFAULT_ENGINE);
        black_box(&e);
    });
}

fn do_encode_bench_avx(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);
    b.iter(|| {
        let e = encode_engine(&v, AVX2_ENGINE.deref());
        black_box(&e);
    });
}

fn do_encode_bench_display(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);
    b.iter(|| {
        let e = format!("{}", display::Base64Display::from(&v, &DEFAULT_ENGINE));
        black_box(&e);
    });
}

fn do_encode_bench_display_avx(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);
    b.iter(|| {
        let e = format!("{}", display::Base64Display::from(&v, AVX2_ENGINE.deref()));
        black_box(&e);
    });
}

fn do_encode_bench_reuse_buf(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);
    let mut buf = String::new();
    b.iter(|| {
        encode_engine_string(&v, &mut buf, &DEFAULT_ENGINE);
        buf.clear();
    });
}

fn do_encode_bench_reuse_buf_avx(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);
    let mut buf = String::new();
    b.iter(|| {
        encode_engine_string(&v, &mut buf, AVX2_ENGINE.deref());
        buf.clear();
    });
}

fn do_encode_bench_slice(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);
    let mut buf = Vec::new();
    // conservative estimate of encoded size
    buf.resize(v.len() * 2, 0);
    b.iter(|| {
        encode_engine_slice(&v, &mut buf, &DEFAULT_ENGINE);
    });
}

fn do_encode_bench_slice_avx(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);
    let mut buf = Vec::new();
    // conservative estimate of encoded size
    buf.resize(v.len() * 2, 0);
    b.iter(|| {
        encode_engine_slice(&v, &mut buf, AVX2_ENGINE.deref());
    });
}

fn do_encode_bench_stream(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);
    let mut buf = Vec::new();

    buf.reserve(size * 2);
    b.iter(|| {
        buf.clear();
        let mut stream_enc = write::EncoderWriter::from(&mut buf, &DEFAULT_ENGINE);
        stream_enc.write_all(&v).unwrap();
        stream_enc.flush().unwrap();
    });
}

fn do_encode_bench_stream_avx(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);
    let mut buf = Vec::new();

    buf.reserve(size * 2);
    b.iter(|| {
        buf.clear();
        let mut stream_enc = write::EncoderWriter::from(&mut buf, AVX2_ENGINE.deref());
        stream_enc.write_all(&v).unwrap();
        stream_enc.flush().unwrap();
    });
}

fn do_encode_bench_string_stream(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);

    b.iter(|| {
        let mut stream_enc = write::EncoderStringWriter::from(&DEFAULT_ENGINE);
        stream_enc.write_all(&v).unwrap();
        stream_enc.flush().unwrap();
        let _ = stream_enc.into_inner();
    });
}

fn do_encode_bench_string_stream_avx(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);

    b.iter(|| {
        let mut stream_enc = write::EncoderStringWriter::from(AVX2_ENGINE.deref());
        stream_enc.write_all(&v).unwrap();
        stream_enc.flush().unwrap();
        let _ = stream_enc.into_inner();
    });
}

fn do_encode_bench_string_reuse_buf_stream(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);

    let mut buf = String::new();
    b.iter(|| {
        buf.clear();
        let mut stream_enc = write::EncoderStringWriter::from_consumer(&mut buf, &DEFAULT_ENGINE);
        stream_enc.write_all(&v).unwrap();
        stream_enc.flush().unwrap();
        let _ = stream_enc.into_inner();
    });
}

fn do_encode_bench_string_reuse_buf_stream_avx(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size);
    fill(&mut v);

    let mut buf = String::new();
    b.iter(|| {
        buf.clear();
        let mut stream_enc =
            write::EncoderStringWriter::from_consumer(&mut buf, AVX2_ENGINE.deref());
        stream_enc.write_all(&v).unwrap();
        stream_enc.flush().unwrap();
        let _ = stream_enc.into_inner();
    });
}

fn fill(v: &mut Vec<u8>) {
    let cap = v.capacity();
    // weak randomness is plenty; we just want to not be completely friendly to the branch predictor
    let mut r = rand::rngs::SmallRng::from_entropy();
    while v.len() < cap {
        v.push(r.gen::<u8>());
    }
}

const BYTE_SIZES: [usize; 5] = [3, 50, 100, 500, 3 * 1024];

// Benchmarks over these byte sizes take longer so we will run fewer samples to
// keep the benchmark runtime reasonable.
const LARGE_BYTE_SIZES: [usize; 3] = [3 * 1024 * 1024, 10 * 1024 * 1024, 30 * 1024 * 1024];

fn encode_benchmarks(c: &mut Criterion, label: &str, byte_sizes: &[usize]) {
    {
        let mut group_dec = c.benchmark_group(label);
        group_dec
            .warm_up_time(std::time::Duration::from_millis(500))
            .measurement_time(std::time::Duration::from_secs(3));
        for size in byte_sizes {
            group_dec
                .throughput(Throughput::Bytes(*size as u64))
                .bench_with_input(BenchmarkId::new("encode", size), size, do_encode_bench)
                .bench_with_input(
                    BenchmarkId::new("encode_avx", size),
                    size,
                    do_encode_bench_avx,
                );
        }
        group_dec.finish();
    }

    {
        let mut dis = String::from(label);
        dis.push_str("_display");
        let mut group_dis = c.benchmark_group(dis);
        group_dis
            .warm_up_time(std::time::Duration::from_millis(500))
            .measurement_time(std::time::Duration::from_secs(3));
        for size in byte_sizes {
            group_dis
                .throughput(Throughput::Bytes(*size as u64))
                .bench_with_input(
                    BenchmarkId::new("encode_display", size),
                    size,
                    do_encode_bench_display,
                )
                .bench_with_input(
                    BenchmarkId::new("encode_display_avx", size),
                    size,
                    do_encode_bench_display_avx,
                );
        }
        group_dis.finish();
    }

    {
        let mut reu = String::from(label);
        reu.push_str("_reuse");
        let mut group_reu = c.benchmark_group(reu);
        group_reu
            .warm_up_time(std::time::Duration::from_millis(500))
            .measurement_time(std::time::Duration::from_secs(3));
        for size in byte_sizes {
            group_reu
                .throughput(Throughput::Bytes(*size as u64))
                .bench_with_input(
                    BenchmarkId::new("encode_reuse_buf", size),
                    size,
                    do_encode_bench_reuse_buf,
                )
                .bench_with_input(
                    BenchmarkId::new("encode_reuse_buf_avx", size),
                    size,
                    do_encode_bench_reuse_buf_avx,
                );
        }
        group_reu.finish();
    }

    {
        let mut sli = String::from(label);
        sli.push_str("_slice");
        let mut group_sli = c.benchmark_group(sli);
        group_sli
            .warm_up_time(std::time::Duration::from_millis(500))
            .measurement_time(std::time::Duration::from_secs(3));
        for size in byte_sizes {
            group_sli
                .throughput(Throughput::Bytes(*size as u64))
                .bench_with_input(
                    BenchmarkId::new("encode_slice", size),
                    size,
                    do_encode_bench_slice,
                )
                .bench_with_input(
                    BenchmarkId::new("encode_slice_avx", size),
                    size,
                    do_encode_bench_slice_avx,
                );
        }
        group_sli.finish();
    }

    {
        let mut str_ = String::from(label);
        str_.push_str("_stream");
        let mut group_str = c.benchmark_group(str_);
        group_str
            .warm_up_time(std::time::Duration::from_millis(500))
            .measurement_time(std::time::Duration::from_secs(3));
        for size in byte_sizes {
            group_str
                .throughput(Throughput::Bytes(*size as u64))
                .bench_with_input(
                    BenchmarkId::new("encode_string_stream", size),
                    size,
                    do_encode_bench_string_stream,
                )
                .bench_with_input(
                    BenchmarkId::new("encode_string_stream_avx", size),
                    size,
                    do_encode_bench_string_stream_avx,
                );
        }
        group_str.finish();
    }

    {
        let mut buf = String::from(label);
        buf.push_str("_buf");
        let mut group_buf = c.benchmark_group(buf);
        group_buf
            .warm_up_time(std::time::Duration::from_millis(500))
            .measurement_time(std::time::Duration::from_secs(3));
        for size in byte_sizes {
            group_buf
                .bench_with_input(
                    BenchmarkId::new("encode_reuse_buf_stream", size),
                    size,
                    do_encode_bench_stream,
                )
                .bench_with_input(
                    BenchmarkId::new("encode_reuse_buf_stream_avx", size),
                    size,
                    do_encode_bench_stream_avx,
                );
        }
        group_buf.finish();
    }

    let mut bufstr = String::from(label);
    bufstr.push_str("_bufstream");
    let mut group_bufstr = c.benchmark_group(bufstr);
    group_bufstr
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(3));
    for size in byte_sizes {
        group_bufstr
            .throughput(Throughput::Bytes(*size as u64))
            .bench_with_input(
                BenchmarkId::new("encode_string_reuse_buf_stream", size),
                size,
                do_encode_bench_string_reuse_buf_stream,
            )
            .bench_with_input(
                BenchmarkId::new("encode_string_reuse_buf_stream_avx", size),
                size,
                do_encode_bench_string_reuse_buf_stream_avx,
            );
    }
    group_bufstr.finish();
}

fn decode_benchmarks(c: &mut Criterion, label: &str, byte_sizes: &[usize]) {
    {
        let mut group_dec = c.benchmark_group(label);
        for size in byte_sizes {
            group_dec
                .warm_up_time(std::time::Duration::from_millis(500))
                .measurement_time(std::time::Duration::from_secs(3))
                .throughput(Throughput::Bytes(*size as u64))
                .bench_with_input(BenchmarkId::new("decode", size), size, do_decode_bench)
                .bench_with_input(
                    BenchmarkId::new("decode_avx", size),
                    size,
                    do_decode_bench_avx,
                );
        }
        group_dec.finish();
    }
    {
        let mut reu = String::from(label);
        reu.push_str("_reuse");
        let mut group_reu = c.benchmark_group(reu);

        for size in byte_sizes {
            group_reu
                .warm_up_time(std::time::Duration::from_millis(500))
                .measurement_time(std::time::Duration::from_secs(3))
                .throughput(Throughput::Bytes(*size as u64))
                .bench_with_input(
                    BenchmarkId::new("decode_reuse_buf", size),
                    size,
                    do_decode_bench_reuse_buf,
                )
                .bench_with_input(
                    BenchmarkId::new("decode_reuse_buf_avx", size),
                    size,
                    do_decode_bench_reuse_buf_avx,
                );
        }

        group_reu.finish()
    }
    {
        let mut sli = String::from(label);
        sli.push_str("_slice");
        let mut group_sli = c.benchmark_group(sli);
        for size in byte_sizes {
            group_sli
                .warm_up_time(std::time::Duration::from_millis(500))
                .measurement_time(std::time::Duration::from_secs(3))
                .throughput(Throughput::Bytes(*size as u64))
                .bench_with_input(
                    BenchmarkId::new("decode_slice", size),
                    size,
                    do_decode_bench_slice,
                )
                .bench_with_input(
                    BenchmarkId::new("decode_slice_avx", size),
                    size,
                    do_decode_bench_slice_avx,
                );
        }
        group_sli.finish();
    }

    let mut str_ = String::from(label);
    str_.push_str("_stream");
    let mut group_str = c.benchmark_group(str_);
    for size in byte_sizes {
        group_str
            .warm_up_time(std::time::Duration::from_millis(500))
            .measurement_time(std::time::Duration::from_secs(3))
            .throughput(Throughput::Bytes(*size as u64))
            .bench_with_input(
                BenchmarkId::new("decode_stream", size),
                size,
                do_decode_bench_stream,
            )
            .bench_with_input(
                BenchmarkId::new("decode_stream_avx", size),
                size,
                do_decode_bench_stream_avx,
            );
    }
    group_str.finish();
}

fn do_align_bench(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size * 3 / 4 + 32);
    fill(&mut v);

    let (pre, aligned_u32, post) = unsafe { v.align_to_mut::<u32>() };
    let aligned: &[u8] = unsafe { core::mem::transmute(aligned_u32) };
    assert!(pre.len() == 0);
    assert!(post.len() == 0);

    let encoded = encode_engine(&v, AVX2_ENGINE.deref());

    let mut buf = Vec::new();
    buf.resize(size, 0);
    b.iter(|| {
        decode_engine_slice(&encoded, &mut buf, AVX2_ENGINE.deref()).unwrap();
        black_box(&buf);
    });
}
fn do_unalign_bench(b: &mut Bencher, &size: &usize) {
    let mut v: Vec<u8> = Vec::with_capacity(size * 3 / 4 + 32);
    fill(&mut v);

    let encoded = encode_engine(&v[5..], AVX2_ENGINE.deref());

    let mut buf = Vec::new();
    buf.resize(size, 0);
    b.iter(|| {
        decode_engine_slice(&encoded, &mut buf, AVX2_ENGINE.deref()).unwrap();
        black_box(&buf);
    });
}

fn align_benchmarks(c: &mut Criterion, label: &str, byte_sizes: &[usize]) {
    let mut group = c.benchmark_group(label);
    for size in byte_sizes {
        group
            .warm_up_time(std::time::Duration::from_millis(500))
            .measurement_time(std::time::Duration::from_secs(3))
            .throughput(Throughput::Bytes(*size as u64))
            .bench_with_input(BenchmarkId::new("aligned", size), size, do_align_bench)
            .bench_with_input(BenchmarkId::new("unaligned", size), size, do_unalign_bench);
    }
    group.finish();
}

fn bench(c: &mut Criterion) {
    encode_benchmarks(c, "encode_small_input", &BYTE_SIZES[..]);
    encode_benchmarks(c, "encode_large_input", &LARGE_BYTE_SIZES[..]);
    decode_benchmarks(c, "decode_small_input", &BYTE_SIZES[..]);
    decode_benchmarks(c, "decode_large_input", &LARGE_BYTE_SIZES[..]);

    align_benchmarks(c, "align_benchmark", &LARGE_BYTE_SIZES[..]);
}

criterion_group!(benches, bench);
criterion_main!(benches);
