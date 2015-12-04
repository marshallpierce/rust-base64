rust-base64
===

It's base64. What more could anyone want?

Example
---

In Cargo.toml: `base64 = "~0.1.0"`

```rust
    extern crate base64;

    use base64::{encode, decode};

    fn main() {
        let a = "hello world";
        let b = "aGVsbG8gd29ybGQ=";

        assert_eq!(encode(a).unwrap(), b);
        assert_eq!(a, decode(b).unwrap());
    }
```

API
---

rust-base64 exposes five functions:

```rust
    encode(&str) -> Result<String, Base64Error>
    decode(&str) -> Result<String, Base64Error>
    u8en(&[u8]) -> Result<Vec<u8>, Base64Error>
    u8de(&[u8]) -> Result<Vec<u8>, Base64Error>
    decode_ws(&str) -> Result<String, Base64Error>
```

But really, two functions and three convenience wrappers. `u8en()` and `u8de()` transform arbitrary octets and aim to be fully compliant with [RFC 4648](https://tools.ietf.org/html/rfc4648). `encode()` and `decode()` call the appropriate u8 function and return utf8. `decode_ws()` does the same as `decode()` after first stripping whitespace ("whitespace" according to the rules of Javascript's `btoa()`, meaning \n \r \f \t and space). In all cases when decoding, extraneous = characters are ignored.

Goals
---

It would be nice to give the user the choice to allocate their own memory. It is unlikely I will add much, if anything, to the feature set beyond that. I'd like to improve on the test cases, confirm full compliance with the standard, and then focus on making it smaller and more performant.

I have a fondness for small dependency footprints, ecosystems where you can pick and choose what functionality you need, and no more. Unix philosophy sort of thing I guess, many tiny utilities interoperating across a common interface. One time making a Twitter bot, I ran into the need to correctly pluralize arbitrary words. I found on npm a module that did nothing but pluralize words. Nothing else, just a couple of functions. I'd like for this to be that "just a couple of functions."

Anyway. It's base64.

[https://crates.io/crates/base64](https://crates.io/crates/base64)
