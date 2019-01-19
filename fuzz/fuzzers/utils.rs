extern crate base64;
extern crate rand;
extern crate rand_pcg;
extern crate sha2;

use self::base64::*;
use self::rand::{Rng, SeedableRng};
use self::rand_pcg::Pcg32;
use self::sha2::{Sha256, Digest};

pub fn random_config(data: &[u8]) -> Config {
    // use sha256 of data as rng seed so it's repeatable
    let sha = Sha256::digest(data);

    let mut seed: [u8; 16] = [0; 16];
    seed.copy_from_slice(&sha[..16]);

    let mut rng = Pcg32::from_seed(&sha);

    let charset = if rng.gen() {
        CharacterSet::UrlSafe
    } else {
        CharacterSet::Standard
    };

    Config::new(charset, rng.gen())
}
