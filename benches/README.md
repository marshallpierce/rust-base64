# Benchmarks

The Criterion benchmarks separate latency-oriented inputs through 1024 raw
bytes from throughput-oriented inputs between 4 KiB and 1 MiB. A separate
`very_large` group retains the 3 MiB, 10 MiB, and 30 MiB cases.

The main size matrix, in raw bytes before encoding, is:

```text
0, 1, 2, 3, 4, 8, 16, 24, 32, 48, 64, 96,
128, 192, 256, 384, 512, 768, 1024,
4096, 16384, 65536, 1048576
```

Encode benchmark throughput is reported in raw input bytes. Decode benchmark
names include both raw and encoded byte counts, and their throughput is
reported in encoded input bytes.

The benchmark path is organized as:

```text
<operation>/<size class>/<configuration>/<engine>/<API>/<size>
```

This makes substring filters useful for running one operation, configuration,
engine, API, or size. For example:

```bash
cargo bench --bench benchmarks -- \
  "encode/latency/standard_padded/general_purpose/slice_raw_bytes/64" --exact
cargo bench --bench benchmarks -- \
  "decode/throughput/url_safe_unpadded/simd/slice"
cargo bench --bench benchmarks -- \
  "decode/errors/standard_padded/avx2/invalid_end"
```

`general_purpose` is always available. The runtime `simd` engine and explicit
`avx2` or `neon` engines are registered only when their feature, architecture,
and runtime support requirements are satisfied.

## Comparing changes

The options below are supported by the Criterion 0.7 benchmark binary. Use
`cargo bench --bench benchmarks -- --help` to verify them when Criterion is
updated.

On the parent commit, save a named baseline for a focused family:

```bash
cargo bench --bench benchmarks -- \
  "encode/latency/standard_padded/general_purpose/slice_raw_bytes" \
  --save-baseline parent
```

After switching to the candidate commit, compare the same family:

```bash
cargo bench --bench benchmarks -- \
  "encode/latency/standard_padded/general_purpose/slice_raw_bytes" \
  --baseline parent
```

Use `--baseline-lenient` only when the candidate intentionally adds benchmark
cases. `--profile-time <seconds>` runs a focused benchmark without statistical
analysis or stored results, which is useful when collecting a profile.

Run parent and candidate on the same machine, power configuration, target,
features, environment, and pinned Rust toolchain. Alternate or randomize their
order. Performance claims should use at least 15 repetitions and report the
median alongside absolute time or throughput; changes around 2% should be
treated as noise unless repeated runs and confidence intervals establish
otherwise.