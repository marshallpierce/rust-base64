extern crate base64;
extern crate rand;
extern crate ring;

use self::base64::*;
use self::rand::{Rng, SeedableRng};
use self::rand::prng::XorShiftRng;
use self::ring::digest;

pub fn random_config(data: &[u8]) -> Config {
    // use sha256 of data as rng seed so it's repeatable
    let sha = digest::digest(&digest::SHA256, data);

    let mut seed: [u8; 16] = [0; 16];
    seed.copy_from_slice(&sha.as_ref()[0..16]);

    let mut rng = XorShiftRng::from_seed(seed);

    let strip_whitespace = rng.gen();

    let charset = if rng.gen() {
        CharacterSet::UrlSafe
    } else {
        CharacterSet::Standard
    };

    Config::new(charset, rng.gen(), strip_whitespace)
}
