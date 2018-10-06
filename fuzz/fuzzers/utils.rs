extern crate base64;
extern crate rand;
extern crate ring;

use self::base64::*;
use self::rand::{Rng, SeedableRng};
use self::rand::prng::XorShiftRng;
use self::rand::distributions::{Distribution, Range};
use self::ring::digest;

pub fn random_config(data: &[u8]) -> Config {
    // use sha256 of data as rng seed so it's repeatable
    let sha = digest::digest(&digest::SHA256, data);

    let mut seed: [u8; 16] = [0; 16];
    seed.copy_from_slice(&sha.as_ref()[0..16]);

    let mut rng = XorShiftRng::from_seed(seed);
    let line_len_range = Range::new(10, 100);

    let (line_wrap, strip_whitespace) = if rng.gen() {
        (LineWrap::NoWrap, rng.gen())
    } else {
        let line_len = line_len_range.sample(&mut rng);

        let line_ending = if rng.gen() {
            LineEnding::LF
        } else {
            LineEnding::CRLF
        };

        // always strip whttespace if we're wrapping
        (LineWrap::Wrap(line_len, line_ending), true)
    };

    let charset = if rng.gen() {
        CharacterSet::UrlSafe
    } else {
        CharacterSet::Standard
    };

    Config::new(charset, rng.gen(), strip_whitespace, line_wrap)
}
