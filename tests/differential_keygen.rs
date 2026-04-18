#![cfg(feature = "deterministic-tests")]

mod common;

use common::c_reference;
use falcon2017::{Compression, Falcon1024, Falcon512, PublicKey, SecretKey};

#[test]
fn falcon512_keygen_matches_reference_c_with_same_seed() {
    let seed = *b"falcon2017-step20-keygen-seed-51";
    let c_ref = c_reference::keygen(9, &seed, 0);

    let rust = Falcon512::keygen_from_seed(&seed).expect("Rust keygen");

    assert_eq!(rust.public.to_bytes(), c_ref.pk.as_slice());
    assert_eq!(
        &*rust.secret.to_bytes(Compression::None),
        c_ref.sk.as_slice()
    );
    assert_eq!(
        rust.secret
            .derive_public()
            .expect("derive public key")
            .to_bytes(),
        c_ref.pk.as_slice()
    );

    let decoded_pk = PublicKey::<9>::from_bytes(&c_ref.pk).expect("decode C public key");
    assert_eq!(decoded_pk.to_bytes(), c_ref.pk.as_slice());

    let decoded_sk = SecretKey::<9>::from_bytes(&c_ref.sk).expect("decode C secret key");
    assert_eq!(
        &*decoded_sk.to_bytes(Compression::None),
        c_ref.sk.as_slice()
    );
    assert_eq!(
        decoded_sk
            .derive_public()
            .expect("derive public key")
            .to_bytes(),
        c_ref.pk.as_slice()
    );
}

#[test]
fn falcon1024_keygen_matches_reference_c_with_same_seed() {
    let seed = *b"falcon2017-step20-keygen-seed-10";
    let c_ref = c_reference::keygen(10, &seed, 0);

    let rust = Falcon1024::keygen_from_seed(&seed).expect("Rust keygen");

    assert_eq!(rust.public.to_bytes(), c_ref.pk.as_slice());
    assert_eq!(
        &*rust.secret.to_bytes(Compression::None),
        c_ref.sk.as_slice()
    );
    assert_eq!(
        rust.secret
            .derive_public()
            .expect("derive public key")
            .to_bytes(),
        c_ref.pk.as_slice()
    );

    let decoded_pk = PublicKey::<10>::from_bytes(&c_ref.pk).expect("decode C public key");
    assert_eq!(decoded_pk.to_bytes(), c_ref.pk.as_slice());

    let decoded_sk = SecretKey::<10>::from_bytes(&c_ref.sk).expect("decode C secret key");
    assert_eq!(
        &*decoded_sk.to_bytes(Compression::None),
        c_ref.sk.as_slice()
    );
    assert_eq!(
        decoded_sk
            .derive_public()
            .expect("derive public key")
            .to_bytes(),
        c_ref.pk.as_slice()
    );
}
