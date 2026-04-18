mod common;

use common::{FixedRng, FixedSeedRng};
use falcon2017::{
    Compression, Falcon1024, Falcon512, KeygenWorkspace, Nonce, SignRefWorkspace, VerifyWorkspace,
};

#[test]
fn falcon512_roundtrip_works_for_one_shot_and_prepared_verify() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-step19-roundtrip-512!");
    let keypair = Falcon512::keygen(&mut keygen_rng).expect("keygen");
    let mut sign_rng = FixedRng::new(b"falcon2017-step19-sign-512");
    let sig = keypair
        .secret
        .sign_ref(b"step19-roundtrip-512", Compression::Static, &mut sign_rng)
        .expect("signature");

    keypair
        .public
        .verify_detached(b"step19-roundtrip-512", &sig)
        .expect("one-shot verify");

    let prepared = keypair.public.prepare().expect("prepared public key");
    prepared
        .verify_detached(b"step19-roundtrip-512", &sig)
        .expect("prepared verify");
}

#[test]
fn falcon1024_roundtrip_works_for_streaming_verify() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-step19-roundtrip-1024");
    let keypair = Falcon1024::keygen(&mut keygen_rng).expect("keygen");
    let mut sign_rng = FixedRng::new(b"falcon2017-step19-sign-1024");
    let sig = keypair
        .secret
        .sign_ref(
            b"step19-roundtrip-1024-message",
            Compression::None,
            &mut sign_rng,
        )
        .expect("signature");

    let prepared = keypair.public.prepare().expect("prepared public key");
    let mut verifier = prepared.verifier(sig.nonce());
    verifier.update(b"step19-");
    verifier.update(b"roundtrip-1024-");
    verifier.update(b"message");
    verifier
        .finalize(sig.body_bytes())
        .expect("streaming verify");
}

#[test]
fn falcon512_external_nonce_roundtrip_accepts_non_default_rlen() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-step19-external-nonce");
    let keypair = Falcon512::keygen(&mut keygen_rng).expect("keygen");
    let nonce = Nonce::from_bytes(&(0u8..28).collect::<Vec<_>>());
    let mut sign_rng = FixedRng::new(b"falcon2017-step19-sign-external");
    let sig = keypair
        .secret
        .sign_ref_with_external_nonce(
            b"step19-external-nonce",
            nonce.clone(),
            Compression::Static,
            &mut sign_rng,
        )
        .expect("signature");

    assert_eq!(sig.nonce().as_bytes(), nonce.as_bytes());
    keypair
        .public
        .verify_detached(b"step19-external-nonce", &sig)
        .expect("verify");
}

#[test]
fn falcon512_workspace_roundtrip_reuses_advanced_api_buffers() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-step21-workspace-512!");
    let mut keygen_ws = KeygenWorkspace::<9>::new();
    let keypair = Falcon512::keygen_in(&mut keygen_rng, &mut keygen_ws).expect("keygen");

    let mut sign_rng = FixedRng::new(b"falcon2017-step21-sign-workspace");
    let mut sign_ws = SignRefWorkspace::<9>::new();
    let sig = keypair
        .secret
        .sign_ref_in(
            b"step21-workspace-roundtrip-512",
            Compression::Static,
            &mut sign_rng,
            &mut sign_ws,
        )
        .expect("signature");

    let mut verify_ws = VerifyWorkspace::<9>::new();
    keypair
        .public
        .verify_detached_in(b"step21-workspace-roundtrip-512", &sig, &mut verify_ws)
        .expect("one-shot verify with workspace");

    let prepared = keypair.public.prepare().expect("prepared public key");
    prepared
        .verify_detached_in(b"step21-workspace-roundtrip-512", &sig, &mut verify_ws)
        .expect("prepared verify with workspace");
}

#[test]
fn falcon1024_workspace_roundtrip_accepts_external_nonce() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-step21-workspace-1024");
    let mut keygen_ws = KeygenWorkspace::<10>::new();
    let keypair = Falcon1024::keygen_in(&mut keygen_rng, &mut keygen_ws).expect("keygen");

    let nonce = Nonce::from_bytes(&(0u8..33).collect::<Vec<_>>());
    let mut sign_rng = FixedRng::new(b"falcon2017-step21-sign-external");
    let mut sign_ws = SignRefWorkspace::<10>::new();
    let sig = keypair
        .secret
        .sign_ref_with_external_nonce_in(
            b"step21-workspace-roundtrip-1024",
            nonce.clone(),
            Compression::None,
            &mut sign_rng,
            &mut sign_ws,
        )
        .expect("signature");

    assert_eq!(sig.nonce().as_bytes(), nonce.as_bytes());

    let mut verify_ws = VerifyWorkspace::<10>::new();
    keypair
        .public
        .verify_detached_in(b"step21-workspace-roundtrip-1024", &sig, &mut verify_ws)
        .expect("verify with workspace");
}

#[cfg(feature = "deterministic-tests")]
#[test]
fn seeded_workspace_keygen_matches_seeded_one_shot_api() {
    let mut ws512 = KeygenWorkspace::<9>::new();
    let one_shot_512 =
        Falcon512::keygen_from_seed(b"falcon2017-step21-seeded-ws-512").expect("seeded keygen");
    let advanced_512 =
        Falcon512::keygen_from_seed_in(b"falcon2017-step21-seeded-ws-512", &mut ws512)
            .expect("seeded workspace keygen");
    assert_eq!(
        advanced_512.public.to_bytes(),
        one_shot_512.public.to_bytes()
    );
    assert_eq!(
        &*advanced_512.secret.to_bytes(Compression::None),
        &*one_shot_512.secret.to_bytes(Compression::None)
    );

    let mut ws1024 = KeygenWorkspace::<10>::new();
    let one_shot_1024 =
        Falcon1024::keygen_from_seed(b"falcon2017-step21-seeded-ws-1024").expect("seeded keygen");
    let advanced_1024 =
        Falcon1024::keygen_from_seed_in(b"falcon2017-step21-seeded-ws-1024", &mut ws1024)
            .expect("seeded workspace keygen");
    assert_eq!(
        advanced_1024.public.to_bytes(),
        one_shot_1024.public.to_bytes()
    );
    assert_eq!(
        &*advanced_1024.secret.to_bytes(Compression::None),
        &*one_shot_1024.secret.to_bytes(Compression::None)
    );
}
