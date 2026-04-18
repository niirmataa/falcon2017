mod common;

#[path = "../src/rng/shake256.rs"]
pub mod shake256_impl;

mod rng {
    pub use crate::shake256_impl as shake256;
}

mod math {
    pub mod ntt {
        pub const QB: u32 = 12289;
    }
}

#[path = "../src/falcon/hash_to_point.rs"]
mod hash_to_point_impl;

use common::c_reference;
#[cfg(feature = "deterministic-tests")]
use common::{differential_bytes, FixedRng};
use common::{extract_c_kat_table, extract_c_string, hex_to_bytes, C_TEST_FALCON};
#[cfg(feature = "deterministic-tests")]
use falcon2017::{Compression, Falcon1024, Falcon512};
use falcon2017::{Nonce, PublicKey};
use hash_to_point_impl::hash_message_to_point_binary;

#[cfg(feature = "deterministic-tests")]
const VERIFY_CASES_PER_LOGN: u32 = 512;

#[test]
fn verify_reference_c_known_signatures_for_512_and_1024() {
    verify_kat_table(9, "ntru_pkey_512", "KAT_SIG_512");
    verify_kat_table(10, "ntru_pkey_1024", "KAT_SIG_1024");
}

#[test]
fn hash_to_point_matches_reference_c_for_binary_512_and_1024() {
    let nonce_512 = b"step20-hash-to-point-nonce-512";
    let msg_512 = b"step20 hash-to-point message 512";
    let c0_512 = c_reference::hash_to_point_binary(9, nonce_512, msg_512);
    let rust_512 = hash_message_to_point_binary(nonce_512, msg_512, 9);
    assert_eq!(&*rust_512, c0_512.as_slice());

    let nonce_1024 = b"step20-hash-to-point-nonce-1024";
    let msg_1024 = b"step20 hash-to-point message 1024";
    let c0_1024 = c_reference::hash_to_point_binary(10, nonce_1024, msg_1024);
    let rust_1024 = hash_message_to_point_binary(nonce_1024, msg_1024, 10);
    assert_eq!(&*rust_1024, c0_1024.as_slice());
}

#[cfg(feature = "deterministic-tests")]
#[test]
fn rust_signatures_verify_in_reference_c_across_falcon512_campaign() {
    for case in 0..VERIFY_CASES_PER_LOGN {
        let seed = differential_bytes(b"step-r1-verify-key-512", case, 32);
        let keypair = Falcon512::keygen_from_seed(&seed).expect("seeded keygen");
        let msg = differential_bytes(b"step-r1-verify-msg-512", case, 1 + (case % 257) as usize);
        let nonce_bytes =
            differential_bytes(b"step-r1-verify-nonce-512", case, 1 + (case % 64) as usize);
        let nonce = Nonce::from_bytes(&nonce_bytes);
        let rng_bytes = differential_bytes(b"step-r1-verify-rng-512", case, 96);
        let mut rng = FixedRng::new(&rng_bytes);
        let compression = if (case & 1) == 0 {
            Compression::None
        } else {
            Compression::Static
        };
        let sig = keypair
            .secret
            .sign_ref_with_external_nonce(&msg, nonce.clone(), compression, &mut rng)
            .expect("sign ref");

        keypair
            .public
            .verify_detached(&msg, &sig)
            .expect("rust verify");
        let status = c_reference::verify(
            keypair.public.to_bytes(),
            nonce.as_bytes(),
            &msg,
            sig.body_bytes(),
        );
        assert_eq!(status, 1, "Falcon512 C verify mismatch for case {case}");
    }
}

#[cfg(feature = "deterministic-tests")]
#[test]
fn rust_signatures_verify_in_reference_c_across_falcon1024_campaign() {
    for case in 0..VERIFY_CASES_PER_LOGN {
        let seed = differential_bytes(b"step-r1-verify-key-1024", case, 32);
        let keypair = Falcon1024::keygen_from_seed(&seed).expect("seeded keygen");
        let msg = differential_bytes(b"step-r1-verify-msg-1024", case, 1 + (case % 257) as usize);
        let nonce_bytes =
            differential_bytes(b"step-r1-verify-nonce-1024", case, 1 + (case % 64) as usize);
        let nonce = Nonce::from_bytes(&nonce_bytes);
        let rng_bytes = differential_bytes(b"step-r1-verify-rng-1024", case, 96);
        let mut rng = FixedRng::new(&rng_bytes);
        let compression = if (case & 1) == 0 {
            Compression::None
        } else {
            Compression::Static
        };
        let sig = keypair
            .secret
            .sign_ref_with_external_nonce(&msg, nonce.clone(), compression, &mut rng)
            .expect("sign ref");

        keypair
            .public
            .verify_detached(&msg, &sig)
            .expect("rust verify");
        let status = c_reference::verify(
            keypair.public.to_bytes(),
            nonce.as_bytes(),
            &msg,
            sig.body_bytes(),
        );
        assert_eq!(status, 1, "Falcon1024 C verify mismatch for case {case}");
    }
}

fn verify_kat_table(logn: u32, pk_name: &str, kat_name: &str) {
    let pk = hex_to_bytes(&extract_c_string(C_TEST_FALCON, pk_name));
    let kats = extract_c_kat_table(C_TEST_FALCON, kat_name);

    match logn {
        9 => {
            let public = PublicKey::<9>::from_bytes(&pk).expect("public key");
            let prepared = public.prepare().expect("prepared public key");
            for (nonce_hex, message, sig_hex) in kats {
                let nonce = Nonce::from_bytes(&hex_to_bytes(&nonce_hex));
                let sig_body = hex_to_bytes(&sig_hex);
                let mut verifier = prepared.verifier(&nonce);
                verifier.update(message.as_bytes());
                verifier.finalize(&sig_body).expect("streaming verify");
            }
        }
        10 => {
            let public = PublicKey::<10>::from_bytes(&pk).expect("public key");
            let prepared = public.prepare().expect("prepared public key");
            for (nonce_hex, message, sig_hex) in kats {
                let nonce = Nonce::from_bytes(&hex_to_bytes(&nonce_hex));
                let sig_body = hex_to_bytes(&sig_hex);
                let mut verifier = prepared.verifier(&nonce);
                verifier.update(message.as_bytes());
                verifier.finalize(&sig_body).expect("streaming verify");
            }
        }
        _ => panic!("unsupported logn"),
    }
}
