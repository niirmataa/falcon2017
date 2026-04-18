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
use common::{extract_c_kat_table, extract_c_string, hex_to_bytes, C_TEST_FALCON};
use falcon2017::{Nonce, PublicKey};
use hash_to_point_impl::hash_message_to_point_binary;

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
