mod common;

#[path = "../src/rng/shake256.rs"]
pub mod shake256_impl;

mod rng {
    pub use crate::shake256_impl as shake256;
}

#[path = "../src/rng/prng.rs"]
mod prng;

use prng::{Prng, PRNG_CHACHA20};
use shake256_impl::{ShakeContext, SHAKE256_CAPACITY};

fn shake256_digest(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    ShakeContext::digest(SHAKE256_CAPACITY, input, &mut out);
    out
}

#[test]
fn prng_chacha20_matches_reference_c_stutter_test() {
    let mut shake = ShakeContext::new(SHAKE256_CAPACITY);
    shake.flip();
    let mut prng = Prng::new(&mut shake, PRNG_CHACHA20).expect("portable PRNG available");

    let mut seen = Vec::<[u8; 32]>::new();
    for _ in 0..100 {
        let hv = shake256_digest(&prng.buf);
        assert!(seen.iter().all(|prev| prev != &hv), "ChaCha20 stutter");
        seen.push(hv);
        prng.refill();
    }
}

#[test]
fn prng_first_block_matches_reference_c_vector() {
    let seed = [
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let expected = [
        205u8, 37, 60, 153, 35, 243, 201, 47, 54, 220, 160, 235, 118, 51, 153, 211, 247, 170, 11,
        191, 116, 196, 132, 100, 80, 175, 93, 116, 236, 45, 234, 95, 103, 221, 198, 134, 141, 67,
        228, 183, 188, 145, 123, 77, 111, 101, 72, 242, 123, 181, 197, 39, 46, 228, 191, 247, 4,
        67, 99, 171, 109, 83, 171, 80,
    ];

    let mut shake = ShakeContext::shake256();
    shake.inject(&seed);
    shake.flip();
    let mut prng = Prng::new(&mut shake, PRNG_CHACHA20).expect("portable PRNG available");

    let mut got = [0u8; 64];
    prng.get_bytes(&mut got);
    assert_eq!(got, expected);
}
