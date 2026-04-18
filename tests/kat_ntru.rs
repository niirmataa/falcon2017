mod common;

use common::{
    extract_c_i16_array, extract_c_kat_table, extract_c_string, hex_to_bytes, negacyclic_mul,
    C_TEST_FALCON,
};
use falcon2017::{Nonce, PublicKey};

#[test]
fn ntru_small_reference_vector_satisfies_equation() {
    let f = extract_c_i16_array(C_TEST_FALCON, "ntru_f_16");
    let g = extract_c_i16_array(C_TEST_FALCON, "ntru_g_16");
    let big_f = extract_c_i16_array(C_TEST_FALCON, "ntru_F_16");
    let big_g = extract_c_i16_array(C_TEST_FALCON, "ntru_G_16");

    let fg = negacyclic_mul(&f, &big_g);
    let gf = negacyclic_mul(&g, &big_f);
    for (idx, (&lhs, &rhs)) in fg.iter().zip(gf.iter()).enumerate() {
        let value = lhs - rhs;
        if idx == 0 {
            assert_eq!(value, 12289);
        } else {
            assert_eq!(value, 0);
        }
    }
}

#[test]
fn ntru_512_reference_kats_verify_via_public_api() {
    let pk = hex_to_bytes(&extract_c_string(C_TEST_FALCON, "ntru_pkey_512"));
    let public = PublicKey::<9>::from_bytes(&pk).expect("public key");
    let prepared = public.prepare().expect("prepared public key");
    let kats = extract_c_kat_table(C_TEST_FALCON, "KAT_SIG_512");
    assert_eq!(kats.len(), 10);

    for (nonce_hex, message, sig_hex) in kats {
        let nonce = Nonce::from_bytes(&hex_to_bytes(&nonce_hex));
        let sig_body = hex_to_bytes(&sig_hex);
        let mut verifier = prepared.verifier(&nonce);
        verifier.update(message.as_bytes());
        verifier
            .finalize(&sig_body)
            .expect("KAT signature must verify");
    }
}
