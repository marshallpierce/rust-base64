rust-base64
===

It's base64. What more could anyone want?

Example
---

In Cargo.toml: `base64 = "~0.2.0"`

```rust
    extern crate base64;

    use base64::{encode, decode};

    fn main() {
        let a = b"hello world";
        let b = "aGVsbG8gd29ybGQ=";

        assert_eq!(encode(a), b);
        assert_eq!(a, &decode(b).unwrap()[..]);
    }
```

API
---

NOTE: return types have changed from 0.1.x. `decode_ws` is deprecated, functionally equivalent to not-yet-implemented MIME mode which will replace it (or perhaps an alternate way of passing options if there is a usecase for whitespace-ignoring UrlSafe).

rust-base64 exposes five functions:

```rust
    encode(&[u8]) -> String
    decode(&str) -> Result<Vec<u8>, Base64Error>
    encode_mode(&[u8], Base64Mode) -> String
    decode_mode(&str, Base64Mode) -> Result<Vec<u8>, Base64Error>
    decode_ws(&str) -> Result<Vec<u8>, Base64Error>
```

Valid modes are `Base64Mode::Standard` and `Base64Mode::UrlSafe`, which aim to be fully compliant with [RFC 4648](https://tools.ietf.org/html/rfc4648). MIME mode ([RFC 2045](https://www.ietf.org/rfc/rfc2045.txt)) is forthcoming. `encode` and `decode` are convenience wrappers for the `_mode` functions called with `Base64Mode::Standard`. `decode_ws` does the same as `decode` after first stripping whitespace ("whitespace" according to the rules of Javascript's `btoa()`, meaning \n \r \f \t and space). In all cases when decoding, extraneous = characters are ignored.

Goals
---

It would be nice to give the user the choice to allocate their own memory. It is unlikely I will add much, if anything, to the feature set beyond that. I'd like to improve on the test cases, confirm full compliance with the standard, and then focus on making it smaller and more performant.

I have a fondness for small dependency footprints, ecosystems where you can pick and choose what functionality you need, and no more. Unix philosophy sort of thing I guess, many tiny utilities interoperating across a common interface. One time making a Twitter bot, I ran into the need to correctly pluralize arbitrary words. I found on npm a module that did nothing but pluralize words. Nothing else, just a couple of functions. I'd like for this to be that "just a couple of functions."

Anyway. It's base64.

[https://crates.io/crates/base64](https://crates.io/crates/base64)
