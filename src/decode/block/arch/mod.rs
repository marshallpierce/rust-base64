//! Conditionally compile one (and only one) of the files from within the arch
//! directory.

cfg_if! {
    if #[cfg(feature = "simd")] {
        cfg_if! {
            if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                pub mod x86;
            } else {
                pub mod other;
            }
        }
    } else {
        pub mod other;
    }
}
