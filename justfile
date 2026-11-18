# Test unsafe paths with miri
miri-test:
  # Test unsafe simd with miri x64 with stacked borrows
  # Disable optimizations to muffle a miri warning about ignoring optimizations
  RUSTFLAGS="-C target-feature=+avx2 -C opt-level=0" \
    cargo +nightly miri test --target x86_64-unknown-linux-gnu miri
  # Test unsafe simd with miri aarch64 with stacked borrows
  RUSTFLAGS="-C target-feature=+neon -C opt-level=0" \
    cargo +nightly miri test --target aarch64-unknown-linux-gnu miri
  # Test with miri ppc64 to ensure non-simd architectures build
  RUSTFLAGS="-C opt-level=0" \
    cargo +nightly miri test --target powerpc64-unknown-linux-gnu miri
  # Test with miri big-endian aarch64 to ensure the little-endian neon logic isn't used
  RUSTFLAGS="-C target-feature=+neon -C opt-level=0" \
      cargo +nightly miri test --target aarch64_be-unknown-linux-gnu miri
  # Test unsafe simd with miri x64 with tree borrows
  MIRIFLAGS="-Zmiri-tree-borrows" RUSTFLAGS="-C target-feature=+avx2 -C opt-level=0" \
    cargo +nightly miri test --target x86_64-unknown-linux-gnu miri
  # Test unsafe simd with miri aarch64 with tree borrows
  MIRIFLAGS="-Zmiri-tree-borrows" RUSTFLAGS="-C target-feature=+neon -C opt-level=0" \
    cargo +nightly miri test --target aarch64-unknown-linux-gnu miri
  # Test unsafe simd with miri x64 with strict provenance
  MIRIFLAGS="-Zmiri-strict-provenance" RUSTFLAGS="-C target-feature=+avx2 -C opt-level=0" \
    cargo +nightly miri test --target x86_64-unknown-linux-gnu miri
  # Test unsafe simd with miri aarch64 with strict provenance
  MIRIFLAGS="-Zmiri-strict-provenance" RUSTFLAGS="-C target-feature=+neon -C opt-level=0" \
    cargo +nightly miri test --target aarch64-unknown-linux-gnu miri
  # Test unsafe simd with miri x64 with many seeds
  MIRIFLAGS="-Zmiri-many-seeds=0..4" RUSTFLAGS="-C target-feature=+avx2 -C opt-level=0" \
    cargo +nightly miri test --target x86_64-unknown-linux-gnu miri
  # Test unsafe simd with miri aarch64 with many seeds
  MIRIFLAGS="-Zmiri-many-seeds=0..4" RUSTFLAGS="-C target-feature=+neon -C opt-level=0" \
    cargo +nightly miri test --target aarch64-unknown-linux-gnu miri