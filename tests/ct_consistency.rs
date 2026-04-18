mod common;

use common::{FixedRng, FixedSeedRng};
use falcon2017::{
    Compression, Error, ExpandCtWorkspace, Falcon1024, Falcon512, Nonce, SecretKey,
    SignCtWorkspace,
};
use std::time::Instant;

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
fn expand_ct_strict_in_matches_one_shot_for_public_parameter_sets() {
    let mut rng512 = FixedSeedRng::new(*b"falcon2017-step28-expand-in-512!");
    let keypair512 = Falcon512::keygen(&mut rng512).expect("keygen 512");
    let expanded512 = keypair512
        .secret
        .expand_ct_strict()
        .expect("expand ct strict 512");
    let mut ws512 = ExpandCtWorkspace::<9>::new();
    let expanded512_in = keypair512
        .secret
        .expand_ct_strict_in(&mut ws512)
        .expect("expand ct strict in 512");
    let msg512 = b"step28-expand-workspace-512";
    let nonce512 = Nonce::from_bytes(b"step28-expand-ct-nonce-512");
    let mut rng_one_shot512 = FixedRng::new(b"step28-expand-ct-seed-512");
    let mut rng_workspace512 = FixedRng::new(b"step28-expand-ct-seed-512");
    let sig_one_shot512 = expanded512
        .sign_ct_strict_with_external_nonce(
            msg512,
            nonce512.clone(),
            Compression::None,
            &mut rng_one_shot512,
        )
        .expect("one-shot signature 512");
    let sig_workspace512 = expanded512_in
        .sign_ct_strict_with_external_nonce(
            msg512,
            nonce512,
            Compression::None,
            &mut rng_workspace512,
        )
        .expect("workspace signature 512");
    assert_eq!(sig_workspace512, sig_one_shot512);

    let mut rng1024 = FixedSeedRng::new(*b"falcon2017-step28-expand-in-1024");
    let keypair1024 = Falcon1024::keygen(&mut rng1024).expect("keygen 1024");
    let expanded1024 = keypair1024
        .secret
        .expand_ct_strict()
        .expect("expand ct strict 1024");
    let mut ws1024 = ExpandCtWorkspace::<10>::new();
    let expanded1024_in = keypair1024
        .secret
        .expand_ct_strict_in(&mut ws1024)
        .expect("expand ct strict in 1024");
    let msg1024 = b"step28-expand-workspace-1024";
    let nonce1024 = Nonce::from_bytes(b"step28-expand-ct-nonce-1024");
    let mut rng_one_shot1024 = FixedRng::new(b"step28-expand-ct-seed-1024");
    let mut rng_workspace1024 = FixedRng::new(b"step28-expand-ct-seed-1024");
    let sig_one_shot1024 = expanded1024
        .sign_ct_strict_with_external_nonce(
            msg1024,
            nonce1024.clone(),
            Compression::None,
            &mut rng_one_shot1024,
        )
        .expect("one-shot signature 1024");
    let sig_workspace1024 = expanded1024_in
        .sign_ct_strict_with_external_nonce(
            msg1024,
            nonce1024,
            Compression::None,
            &mut rng_workspace1024,
        )
        .expect("workspace signature 1024");
    assert_eq!(sig_workspace1024, sig_one_shot1024);
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
fn sign_ct_strict_is_deterministic_for_same_seed_and_nonce() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-step25-ct-equal-keygn");
    let keypair = Falcon512::keygen(&mut keygen_rng).expect("keygen");
    let expanded = keypair.secret.expand_ct_strict().expect("expanded key");

    let msg = b"step25 sign deterministic";
    let mut sign_rng_a = FixedRng::new(b"falcon2017-step25-equal-sign-seed");
    let mut sign_rng_b = FixedRng::new(b"falcon2017-step25-equal-sign-seed");

    let sig_a = expanded
        .sign_ct_strict(msg, Compression::Static, &mut sign_rng_a)
        .expect("ct signature a");
    let sig_b = expanded
        .sign_ct_strict(msg, Compression::Static, &mut sign_rng_b)
        .expect("ct signature b");

    assert_eq!(sig_a, sig_b);
    keypair.public.verify_detached(msg, &sig_a).expect("verify");

    let nonce = Nonce::from_bytes(b"step25-external-ct-nonce");
    let mut sign_rng_a = FixedRng::new(b"falcon2017-step25-equal-ext-seed");
    let mut sign_rng_b = FixedRng::new(b"falcon2017-step25-equal-ext-seed");

    let sig_a = expanded
        .sign_ct_strict_with_external_nonce(msg, nonce.clone(), Compression::None, &mut sign_rng_a)
        .expect("ct external nonce signature a");
    let sig_b = expanded
        .sign_ct_strict_with_external_nonce(msg, nonce, Compression::None, &mut sign_rng_b)
        .expect("ct external nonce signature b");

    assert_eq!(sig_a, sig_b);
    keypair.public.verify_detached(msg, &sig_a).expect("verify");
}

#[test]
fn sign_ct_strict_in_roundtrips_for_public_parameter_sets() {
    let mut keygen_rng512 = FixedSeedRng::new(*b"falcon2017-step28-keygen-inseed1");
    let keypair512 = Falcon512::keygen(&mut keygen_rng512).expect("keygen 512");
    let expanded512 = keypair512
        .secret
        .expand_ct_strict()
        .expect("expand ct strict 512");
    let mut ws512 = SignCtWorkspace::<9>::new();
    let mut sign_rng512 = FixedRng::new(b"falcon2017-step28-sign-in-512");
    let sig512 = expanded512
        .sign_ct_strict_in(
            b"step28-workspace-roundtrip-512",
            Compression::Static,
            &mut sign_rng512,
            &mut ws512,
        )
        .expect("workspace signature 512");
    keypair512
        .public
        .verify_detached(b"step28-workspace-roundtrip-512", &sig512)
        .expect("verify 512");

    let mut keygen_rng1024 = FixedSeedRng::new(*b"falcon2017-step28-keygen-inseed2");
    let keypair1024 = Falcon1024::keygen(&mut keygen_rng1024).expect("keygen 1024");
    let expanded1024 = keypair1024
        .secret
        .expand_ct_strict()
        .expect("expand ct strict 1024");
    let mut ws1024 = SignCtWorkspace::<10>::new();
    let nonce = Nonce::from_bytes(b"step28-ct-workspace-nonce-1024");
    let mut sign_rng1024 = FixedRng::new(b"falcon2017-step28-sign-in-1024");
    let sig1024 = expanded1024
        .sign_ct_strict_with_external_nonce_in(
            b"step28-workspace-roundtrip-1024",
            nonce,
            Compression::None,
            &mut sign_rng1024,
            &mut ws1024,
        )
        .expect("workspace signature 1024");
    keypair1024
        .public
        .verify_detached(b"step28-workspace-roundtrip-1024", &sig1024)
        .expect("verify 1024");
}

#[test]
fn sign_ct_strict_in_matches_one_shot_for_same_seed_and_nonce() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-step28-equal-in-keyg!");
    let keypair = Falcon512::keygen(&mut keygen_rng).expect("keygen");
    let expanded = keypair.secret.expand_ct_strict().expect("expanded key");
    let mut ws = SignCtWorkspace::<9>::new();

    let msg = b"step28 workspace parity";
    let mut sign_rng_one_shot = FixedRng::new(b"falcon2017-step28-equal-in-seed");
    let mut sign_rng_workspace = FixedRng::new(b"falcon2017-step28-equal-in-seed");

    let sig_one_shot = expanded
        .sign_ct_strict(msg, Compression::Static, &mut sign_rng_one_shot)
        .expect("one-shot signature");
    let sig_workspace = expanded
        .sign_ct_strict_in(msg, Compression::Static, &mut sign_rng_workspace, &mut ws)
        .expect("workspace signature");

    assert_eq!(sig_workspace, sig_one_shot);

    let nonce = Nonce::from_bytes(b"step28-workspace-parity-nonce");
    let mut sign_rng_one_shot = FixedRng::new(b"falcon2017-step28-equal-extseed");
    let mut sign_rng_workspace = FixedRng::new(b"falcon2017-step28-equal-extseed");

    let sig_one_shot = expanded
        .sign_ct_strict_with_external_nonce(
            msg,
            nonce.clone(),
            Compression::None,
            &mut sign_rng_one_shot,
        )
        .expect("one-shot external nonce signature");
    let sig_workspace = expanded
        .sign_ct_strict_with_external_nonce_in(
            msg,
            nonce,
            Compression::None,
            &mut sign_rng_workspace,
            &mut ws,
        )
        .expect("workspace external nonce signature");

    assert_eq!(sig_workspace, sig_one_shot);
}

#[test]
fn ref_and_ct_strict_share_same_wire_header_and_none_layout() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-step30-format-keygen!");
    let keypair = Falcon512::keygen(&mut keygen_rng).expect("keygen");
    let expanded = keypair.secret.expand_ct_strict().expect("expanded key");
    let msg = b"step30 format parity";
    let nonce = Nonce::from_bytes(b"step30-format-parity-nonce-512");

    let mut ref_rng = FixedRng::new(b"falcon2017-step30-format-ref");
    let mut ct_rng = FixedRng::new(b"falcon2017-step30-format-ct!");

    let sig_ref = keypair
        .secret
        .sign_ref_with_external_nonce(msg, nonce.clone(), Compression::None, &mut ref_rng)
        .expect("ref signature");
    let sig_ct = expanded
        .sign_ct_strict_with_external_nonce(msg, nonce.clone(), Compression::None, &mut ct_rng)
        .expect("ct signature");

    assert_eq!(sig_ref.nonce().as_bytes(), nonce.as_bytes());
    assert_eq!(sig_ct.nonce().as_bytes(), nonce.as_bytes());
    assert_eq!(sig_ref.body_bytes()[0], sig_ct.body_bytes()[0]);
    assert_eq!(sig_ref.body_bytes()[0], 9);
    assert_eq!(sig_ref.body_bytes().len(), sig_ct.body_bytes().len());
    keypair.public.verify_detached(msg, &sig_ref).expect("verify ref");
    keypair.public.verify_detached(msg, &sig_ct).expect("verify ct");
}

#[test]
fn ref_and_ct_strict_share_same_wire_header_for_static_1024() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-step30-format-1024key");
    let keypair = Falcon1024::keygen(&mut keygen_rng).expect("keygen");
    let expanded = keypair.secret.expand_ct_strict().expect("expanded key");
    let msg = b"step30 static format parity";
    let nonce = Nonce::from_bytes(b"step30-static-format-nonce-1024");

    let mut ref_rng = FixedRng::new(b"falcon2017-step30-static-ref");
    let mut ct_rng = FixedRng::new(b"falcon2017-step30-static-ct!");

    let sig_ref = keypair
        .secret
        .sign_ref_with_external_nonce(msg, nonce.clone(), Compression::Static, &mut ref_rng)
        .expect("ref signature");
    let sig_ct = expanded
        .sign_ct_strict_with_external_nonce(msg, nonce.clone(), Compression::Static, &mut ct_rng)
        .expect("ct signature");

    assert_eq!(sig_ref.nonce().as_bytes(), nonce.as_bytes());
    assert_eq!(sig_ct.nonce().as_bytes(), nonce.as_bytes());
    assert_eq!(sig_ref.body_bytes()[0], sig_ct.body_bytes()[0]);
    assert_eq!(sig_ref.body_bytes()[0], 0x20 | 10);
    keypair.public.verify_detached(msg, &sig_ref).expect("verify ref");
    keypair.public.verify_detached(msg, &sig_ct).expect("verify ct");
}

#[test]
fn strict_modules_do_not_directly_import_ref_f64_or_libm() {
    for path in [
        "src/falcon/sign_ct_strict.rs",
        "src/sampler/sign_ct_strict.rs",
        "src/falcon/expand_ct.rs",
        "src/math/fft_soft.rs",
    ] {
        let src = std::fs::read_to_string(path).expect("source file");
        let production = src.split("#[cfg(test)]").next().expect("production slice");
        assert!(
            !production.contains("ref_f64"),
            "strict module {path} still imports ref_f64",
        );
        assert!(
            !production.contains("libm"),
            "strict module {path} still imports libm",
        );
    }
}

#[test]
fn sign_ct_strict_timing_smoke_has_no_extreme_seed_ratio() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-step30-time-keygen!!!");
    let keypair = Falcon512::keygen(&mut keygen_rng).expect("keygen");
    let expanded = keypair.secret.expand_ct_strict().expect("expanded key");
    let msg = b"step30 timing smoke";
    let nonce = Nonce::from_bytes(b"step30-timing-smoke-nonce");

    fn batch(
        expanded: &falcon2017::ExpandedSecretKeyCt<9>,
        msg: &[u8],
        nonce: &Nonce,
        seed: &[u8],
    ) -> u128 {
        let start = Instant::now();
        for _ in 0..32 {
            let mut rng = FixedRng::new(seed);
            let _ = expanded
                .sign_ct_strict_with_external_nonce(msg, nonce.clone(), Compression::None, &mut rng)
                .expect("signature");
        }
        start.elapsed().as_nanos().max(1)
    }

    let dur_a = batch(&expanded, msg, &nonce, b"falcon2017-step30-time-seed-a");
    let dur_b = batch(&expanded, msg, &nonce, b"falcon2017-step30-time-seed-b");
    let ratio_num = dur_a.max(dur_b);
    let ratio_den = dur_a.min(dur_b);
    assert!(
        ratio_num <= ratio_den * 6,
        "sign_ct_strict timing drift too large: {dur_a} vs {dur_b}",
    );
}
