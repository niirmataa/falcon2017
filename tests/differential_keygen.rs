#![cfg(feature = "deterministic-tests")]

mod common;

use common::{c_reference, differential_bytes};
use falcon2017::{Compression, Falcon1024, Falcon512, PublicKey, SecretKey};

const KEYGEN_CASES_PER_LOGN: u32 = 512;

#[test]
fn falcon512_keygen_matches_reference_c_across_seed_campaign() {
    run_keygen_campaign_512();
}

#[test]
fn falcon1024_keygen_matches_reference_c_across_seed_campaign() {
    run_keygen_campaign_1024();
}

fn run_keygen_campaign_512() {
    for case in 0..KEYGEN_CASES_PER_LOGN {
        let seed = differential_bytes(b"step-r1-keygen-512", case, 32);
        let c_ref = c_reference::keygen(9, &seed, 0);
        let rust = Falcon512::keygen_from_seed(&seed)
            .unwrap_or_else(|err| panic!("Rust keygen failed for Falcon512 case {case}: {err:?}"));

        assert_eq!(
            rust.public.to_bytes(),
            c_ref.pk.as_slice(),
            "Falcon512 public key mismatch for case {case}"
        );
        assert_eq!(
            &*rust.secret.to_bytes(Compression::None),
            c_ref.sk.as_slice(),
            "Falcon512 secret key mismatch for case {case}"
        );
        assert_eq!(
            rust.secret
                .derive_public()
                .expect("derive public key")
                .to_bytes(),
            c_ref.pk.as_slice(),
            "Falcon512 derived public key mismatch for case {case}"
        );

        let decoded_pk = PublicKey::<9>::from_bytes(&c_ref.pk).expect("decode C public key");
        assert_eq!(
            decoded_pk.to_bytes(),
            c_ref.pk.as_slice(),
            "Falcon512 public key decode mismatch for case {case}"
        );

        let decoded_sk = SecretKey::<9>::from_bytes(&c_ref.sk).expect("decode C secret key");
        assert_eq!(
            &*decoded_sk.to_bytes(Compression::None),
            c_ref.sk.as_slice(),
            "Falcon512 secret key decode mismatch for case {case}"
        );
        assert_eq!(
            decoded_sk
                .derive_public()
                .expect("derive public key")
                .to_bytes(),
            c_ref.pk.as_slice(),
            "Falcon512 decoded secret key derive mismatch for case {case}"
        );
    }
}

fn run_keygen_campaign_1024() {
    for case in 0..KEYGEN_CASES_PER_LOGN {
        let seed = differential_bytes(b"step-r1-keygen-1024", case, 32);
        let c_ref = c_reference::keygen(10, &seed, 0);
        let rust = Falcon1024::keygen_from_seed(&seed)
            .unwrap_or_else(|err| panic!("Rust keygen failed for Falcon1024 case {case}: {err:?}"));

        assert_eq!(
            rust.public.to_bytes(),
            c_ref.pk.as_slice(),
            "Falcon1024 public key mismatch for case {case}"
        );
        assert_eq!(
            &*rust.secret.to_bytes(Compression::None),
            c_ref.sk.as_slice(),
            "Falcon1024 secret key mismatch for case {case}"
        );
        assert_eq!(
            rust.secret
                .derive_public()
                .expect("derive public key")
                .to_bytes(),
            c_ref.pk.as_slice(),
            "Falcon1024 derived public key mismatch for case {case}"
        );

        let decoded_pk = PublicKey::<10>::from_bytes(&c_ref.pk).expect("decode C public key");
        assert_eq!(
            decoded_pk.to_bytes(),
            c_ref.pk.as_slice(),
            "Falcon1024 public key decode mismatch for case {case}"
        );

        let decoded_sk = SecretKey::<10>::from_bytes(&c_ref.sk).expect("decode C secret key");
        assert_eq!(
            &*decoded_sk.to_bytes(Compression::None),
            c_ref.sk.as_slice(),
            "Falcon1024 secret key decode mismatch for case {case}"
        );
        assert_eq!(
            decoded_sk
                .derive_public()
                .expect("derive public key")
                .to_bytes(),
            c_ref.pk.as_slice(),
            "Falcon1024 decoded secret key derive mismatch for case {case}"
        );
    }
}
