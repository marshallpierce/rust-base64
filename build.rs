fn main() {
    autocfg::rerun_path("build.rs");
    let ac = autocfg::new();
    // `rustc-check-cfg` is understood since Cargo 1.80; older versions warn about it.
    if ac.probe_rustc_version(1, 80) {
        autocfg::emit_possibility("base64_core_error");
    }

    // `core::error::Error` is stable since Rust 1.81, but the MSRV is lower, so probe for it.
    // (probe_trait, not probe_path: probes compile as edition 2015, where `use core::..` fails.)
    if ac.probe_trait("core::error::Error") {
        autocfg::emit("base64_core_error");
    }
}
