#![cfg(feature = "deterministic-tests")]

mod common;

use common::c_reference;
use falcon2017::{PublicKey, SecretKey};

#[test]
fn derive_public_matches_reference_c_for_falcon512() {
    let seed = b"falcon2017-step20-derive-seed-512";
    let c_ref = c_reference::keygen(9, seed, 0);

    let secret = SecretKey::<9>::from_bytes(&c_ref.sk).expect("decode C secret key");
    let derived = secret.derive_public().expect("derive public key");

    assert_eq!(derived.to_bytes(), c_ref.pk.as_slice());

    let decoded = PublicKey::<9>::from_bytes(&c_ref.pk).expect("decode C public key");
    assert_eq!(decoded.to_bytes(), derived.to_bytes());
}

#[test]
fn derive_public_matches_reference_c_for_falcon1024() {
    let seed = b"falcon2017-step20-derive-seed-1024";
    let c_ref = c_reference::keygen(10, seed, 0);

    let secret = SecretKey::<10>::from_bytes(&c_ref.sk).expect("decode C secret key");
    let derived = secret.derive_public().expect("derive public key");

    assert_eq!(derived.to_bytes(), c_ref.pk.as_slice());

    let decoded = PublicKey::<10>::from_bytes(&c_ref.pk).expect("decode C public key");
    assert_eq!(decoded.to_bytes(), derived.to_bytes());
}
