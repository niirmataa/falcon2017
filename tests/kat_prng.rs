use falcon2017::rng::prng::{Prng, PRNG_CHACHA20};
use falcon2017::rng::shake256::{ShakeContext, SHAKE256_CAPACITY};

fn shake256_digest(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    ShakeContext::digest(SHAKE256_CAPACITY, input, &mut out);
    out
}

#[test]
fn prng_chacha20_matches_reference_stutter_test() {
    let mut shake = ShakeContext::new(SHAKE256_CAPACITY);
    shake.flip();
    let mut prng = Prng::new(&mut shake, PRNG_CHACHA20).expect("portable PRNG available");

    let mut seen = Vec::<[u8; 32]>::new();
    for _ in 0..100 {
        let mut snapshot = prng.clone();
        let mut block = [0u8; 4096];
        snapshot.get_bytes(&mut block);
        let hv = shake256_digest(&block);
        assert!(
            seen.iter().all(|prev| prev != &hv),
            "ChaCha20 output repeated"
        );
        seen.push(hv);
        prng.refill();
    }
}

#[test]
fn prng_get_bytes_can_be_split_without_changing_stream() {
    let seed = b"Falcon deterministic PRNG split test";
    let mut shake = ShakeContext::shake256();
    shake.inject(seed);
    shake.flip();
    let mut one_shot = Prng::new(&mut shake, PRNG_CHACHA20).expect("portable PRNG available");

    let mut shake = ShakeContext::shake256();
    shake.inject(seed);
    shake.flip();
    let mut split = Prng::new(&mut shake, PRNG_CHACHA20).expect("portable PRNG available");

    let mut one_shot_bytes = [0u8; 5000];
    let mut split_bytes = [0u8; 5000];
    one_shot.get_bytes(&mut one_shot_bytes);
    split.get_bytes(&mut split_bytes[..3]);
    split.get_bytes(&mut split_bytes[3..4095]);
    split.get_bytes(&mut split_bytes[4095..4099]);
    split.get_bytes(&mut split_bytes[4099..]);
    assert_eq!(split_bytes, one_shot_bytes);
}

#[test]
fn prng_get_u64_matches_little_endian_stream_bytes() {
    let seed = b"Falcon deterministic PRNG u64 test";
    let mut shake = ShakeContext::shake256();
    shake.inject(seed);
    shake.flip();
    let mut byte_prng = Prng::new(&mut shake, PRNG_CHACHA20).expect("portable PRNG available");

    let mut shake = ShakeContext::shake256();
    shake.inject(seed);
    shake.flip();
    let mut word_prng = Prng::new(&mut shake, PRNG_CHACHA20).expect("portable PRNG available");

    let mut bytes = [0u8; 8];
    byte_prng.get_bytes(&mut bytes);
    assert_eq!(word_prng.get_u64(), u64::from_le_bytes(bytes));
}

#[test]
fn prng_get_u8_matches_byte_stream() {
    let seed = b"Falcon deterministic PRNG u8 test";
    let mut shake = ShakeContext::shake256();
    shake.inject(seed);
    shake.flip();
    let mut byte_prng = Prng::new(&mut shake, PRNG_CHACHA20).expect("portable PRNG available");

    let mut shake = ShakeContext::shake256();
    shake.inject(seed);
    shake.flip();
    let mut u8_prng = Prng::new(&mut shake, PRNG_CHACHA20).expect("portable PRNG available");

    let mut bytes = [0u8; 257];
    byte_prng.get_bytes(&mut bytes);
    for expected in bytes {
        assert_eq!(u8_prng.get_u8(), expected);
    }
}

#[test]
fn prng_get_u64_refills_early_when_nine_bytes_remain() {
    let seed = b"Falcon deterministic PRNG refill threshold drop";
    let mut shake = ShakeContext::shake256();
    shake.inject(seed);
    shake.flip();
    let mut stream_prng = Prng::new(&mut shake, PRNG_CHACHA20).expect("portable PRNG available");

    let mut shake = ShakeContext::shake256();
    shake.inject(seed);
    shake.flip();
    let mut mixed_prng = Prng::new(&mut shake, PRNG_CHACHA20).expect("portable PRNG available");

    let mut stream = [0u8; 4208];
    stream_prng.get_bytes(&mut stream);
    for expected in &stream[..4087] {
        assert_eq!(mixed_prng.get_u8(), *expected);
    }
    assert_eq!(
        mixed_prng.get_u64(),
        u64::from_le_bytes(stream[4096..4104].try_into().expect("8 bytes"))
    );
    assert_eq!(mixed_prng.get_u8(), stream[4104]);
}
