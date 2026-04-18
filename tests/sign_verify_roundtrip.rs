mod common;

use common::{FixedRng, FixedSeedRng};
use falcon2017::{Compression, Falcon1024, Falcon512, Nonce};

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
