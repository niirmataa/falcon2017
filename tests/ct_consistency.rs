mod common;

use common::{FixedRng, FixedSeedRng};
use falcon2017::{Compression, Error, Falcon1024, Falcon512, Nonce, SecretKey};

const REF_SECRET_KEY_NONE: [u8; 129] = [
    4, 0, 10, 0, 11, 255, 245, 0, 24, 255, 237, 255, 252, 255, 235, 0, 27, 255, 230, 0, 6, 255,
    239, 255, 255, 0, 39, 0, 5, 0, 18, 255, 244, 0, 24, 0, 25, 255, 252, 255, 241, 0, 6, 0, 14, 0,
    28, 255, 253, 0, 20, 0, 27, 0, 53, 0, 17, 0, 1, 255, 215, 255, 218, 0, 31, 255, 242, 0, 51,
    255, 225, 255, 195, 0, 13, 0, 26, 0, 55, 0, 43, 255, 232, 255, 248, 255, 255, 0, 33, 0, 3, 0,
    34, 255, 232, 0, 51, 0, 55, 0, 20, 255, 231, 0, 61, 0, 52, 255, 255, 255, 214, 255, 255, 0, 49,
    255, 242, 0, 36, 255, 229, 0, 10, 0, 5, 0, 3, 255, 192,
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

#[test]
fn sign_ct_strict_roundtrips_for_public_parameter_sets() {
    let mut keygen_rng512 = FixedSeedRng::new(*b"falcon2017-step25-keygen-seed-51");
    let keypair512 = Falcon512::keygen(&mut keygen_rng512).expect("keygen 512");
    let expanded512 = keypair512
        .secret
        .expand_ct_strict()
        .expect("expand ct strict 512");
    let mut sign_rng512 = FixedRng::new(b"falcon2017-step25-sign-ct-512");
    let sig512 = expanded512
        .sign_ct_strict(
            b"step25-roundtrip-ct-512",
            Compression::Static,
            &mut sign_rng512,
        )
        .expect("signature 512");
    keypair512
        .public
        .verify_detached(b"step25-roundtrip-ct-512", &sig512)
        .expect("verify 512");

    let mut keygen_rng1024 = FixedSeedRng::new(*b"falcon2017-step25-keygen-seed-10");
    let keypair1024 = Falcon1024::keygen(&mut keygen_rng1024).expect("keygen 1024");
    let expanded1024 = keypair1024
        .secret
        .expand_ct_strict()
        .expect("expand ct strict 1024");
    let mut sign_rng1024 = FixedRng::new(b"falcon2017-step25-sign-ct-1024");
    let sig1024 = expanded1024
        .sign_ct_strict(
            b"step25-roundtrip-ct-1024",
            Compression::Static,
            &mut sign_rng1024,
        )
        .expect("signature 1024");
    keypair1024
        .public
        .verify_detached(b"step25-roundtrip-ct-1024", &sig1024)
        .expect("verify 1024");
}

#[test]
fn sign_ct_strict_matches_sign_ref_for_same_seed_and_nonce() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-step25-ct-equal-keygn");
    let keypair = Falcon512::keygen(&mut keygen_rng).expect("keygen");
    let expanded = keypair.secret.expand_ct_strict().expect("expanded key");

    let msg = b"step25 sign parity";
    let mut sign_rng_ref = FixedRng::new(b"falcon2017-step25-equal-sign-seed");
    let mut sign_rng_ct = FixedRng::new(b"falcon2017-step25-equal-sign-seed");

    let sig_ref = keypair
        .secret
        .sign_ref(msg, Compression::Static, &mut sign_rng_ref)
        .expect("reference signature");
    let sig_ct = expanded
        .sign_ct_strict(msg, Compression::Static, &mut sign_rng_ct)
        .expect("ct signature");

    assert_eq!(sig_ct, sig_ref);

    let nonce = Nonce::from_bytes(b"step25-external-ct-nonce");
    let mut sign_rng_ref = FixedRng::new(b"falcon2017-step25-equal-ext-seed");
    let mut sign_rng_ct = FixedRng::new(b"falcon2017-step25-equal-ext-seed");

    let sig_ref = keypair
        .secret
        .sign_ref_with_external_nonce(msg, nonce.clone(), Compression::None, &mut sign_rng_ref)
        .expect("reference external nonce signature");
    let sig_ct = expanded
        .sign_ct_strict_with_external_nonce(msg, nonce, Compression::None, &mut sign_rng_ct)
        .expect("ct external nonce signature");

    assert_eq!(sig_ct, sig_ref);
}
