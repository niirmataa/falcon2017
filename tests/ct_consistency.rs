mod common;

use common::FixedSeedRng;
use falcon2017::{Error, Falcon1024, Falcon512, SecretKey};

const REF_SECRET_KEY_NONE: [u8; 129] = [
    4, 0, 10, 0, 11, 255, 245, 0, 24, 255, 237, 255, 252, 255, 235, 0, 27, 255, 230, 0, 6, 255,
    239, 255, 255, 0, 39, 0, 5, 0, 18, 255, 244, 0, 24, 0, 25, 255, 252, 255, 241, 0, 6, 0, 14,
    0, 28, 255, 253, 0, 20, 0, 27, 0, 53, 0, 17, 0, 1, 255, 215, 255, 218, 0, 31, 255, 242, 0,
    51, 255, 225, 255, 195, 0, 13, 0, 26, 0, 55, 0, 43, 255, 232, 255, 248, 255, 255, 0, 33, 0,
    3, 0, 34, 255, 232, 0, 51, 0, 55, 0, 20, 255, 231, 0, 61, 0, 52, 255, 255, 255, 214, 255,
    255, 0, 49, 255, 242, 0, 36, 255, 229, 0, 10, 0, 5, 0, 3, 255, 192,
];

#[test]
fn expand_ct_strict_accepts_public_parameter_sets() {
    let mut rng512 = FixedSeedRng::new(*b"falcon2017-step24-expand512-seed");
    let keypair512 = Falcon512::keygen(&mut rng512).expect("keygen 512");
    keypair512
        .secret
        .expand_ct_strict()
        .expect("expand ct strict 512");

    let mut rng1024 = FixedSeedRng::new(*b"falcon2017-step24-expand1024seed");
    let keypair1024 = Falcon1024::keygen(&mut rng1024).expect("keygen 1024");
    keypair1024
        .secret
        .expand_ct_strict()
        .expect("expand ct strict 1024");
}

#[test]
fn expand_ct_strict_rejects_non_public_logn() {
    let secret = SecretKey::<4>::from_bytes(&REF_SECRET_KEY_NONE).expect("secret key");
    match secret.expand_ct_strict() {
        Ok(_) => panic!("non-public logn must be rejected"),
        Err(err) => assert_eq!(err, Error::InvalidParameter),
    }
}
