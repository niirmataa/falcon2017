mod common;

use common::{FixedRng, FixedSeedRng};
use falcon2017::{Compression, Error, Falcon1024, Falcon512, Nonce, PublicKey, SecretKey};

#[test]
fn malformed_public_key_is_rejected() {
    let err = PublicKey::<9>::from_bytes(&[0x10, 0x00, 0x00]).expect_err("must reject");
    assert_eq!(err, Error::InvalidEncoding);
}

#[test]
fn malformed_secret_key_is_rejected() {
    match SecretKey::<9>::from_bytes(&[0x29, 0x00, 0x00]) {
        Ok(_) => panic!("must reject malformed secret key"),
        Err(err) => assert_eq!(err, Error::InvalidEncoding),
    }
}

#[test]
fn truncated_public_key_prefixes_are_rejected() {
    let mut rng = FixedSeedRng::new(*b"falcon2017-malformed-pk-prefixes");
    let keypair = Falcon512::keygen(&mut rng).expect("keygen");
    let bytes = keypair.public.to_bytes().to_vec();

    for prefix_len in 0..bytes.len() {
        let err = PublicKey::<9>::from_bytes(&bytes[..prefix_len]).expect_err("must reject");
        assert_eq!(err, Error::InvalidEncoding, "prefix length {prefix_len}");
    }
}

#[test]
fn truncated_secret_key_prefixes_are_rejected() {
    let mut rng = FixedSeedRng::new(*b"falcon2017-malformed-sk-prefixes");
    let keypair = Falcon512::keygen(&mut rng).expect("keygen");
    let bytes = keypair.secret.to_bytes(Compression::None).into_vec();

    for prefix_len in 0..bytes.len() {
        let err = match SecretKey::<9>::from_bytes(&bytes[..prefix_len]) {
            Ok(_) => panic!("must reject"),
            Err(err) => err,
        };
        assert_eq!(err, Error::InvalidEncoding, "prefix length {prefix_len}");
    }
}

#[test]
fn malformed_secret_key_header_bits_are_rejected() {
    let mut rng = FixedSeedRng::new(*b"falcon2017-malformed-sk-header!!");
    let keypair = Falcon512::keygen(&mut rng).expect("keygen");
    let mut bytes = keypair.secret.to_bytes(Compression::None).into_vec();

    bytes[0] |= 0x10;
    let err = match SecretKey::<9>::from_bytes(&bytes) {
        Ok(_) => panic!("must reject reserved bit"),
        Err(err) => err,
    };
    assert_eq!(err, Error::InvalidEncoding);

    let mut bytes = keypair.secret.to_bytes(Compression::None).into_vec();
    bytes[0] = (bytes[0] & !0x60) | 0x60;
    let err = match SecretKey::<9>::from_bytes(&bytes) {
        Ok(_) => panic!("must reject reserved compression"),
        Err(err) => err,
    };
    assert_eq!(err, Error::InvalidEncoding);
}

#[test]
fn malformed_public_key_header_bits_are_rejected_on_valid_material() {
    let mut rng = FixedSeedRng::new(*b"falcon2017-malformed-pk-header!!");
    let keypair = Falcon1024::keygen(&mut rng).expect("keygen");
    let mut bytes = keypair.public.to_bytes().to_vec();
    bytes[0] |= 0x70;

    let err = PublicKey::<10>::from_bytes(&bytes).expect_err("must reject reserved bits");
    assert_eq!(err, Error::InvalidEncoding);
}

#[test]
fn malformed_public_key_trailing_bytes_are_rejected() {
    let mut rng = FixedSeedRng::new(*b"falcon2017-malformed-pk-tail!!!!");
    let keypair = Falcon512::keygen(&mut rng).expect("keygen");
    let mut bytes = keypair.public.to_bytes().to_vec();
    bytes.push(0);

    let err = PublicKey::<9>::from_bytes(&bytes).expect_err("must reject trailing byte");
    assert_eq!(err, Error::InvalidEncoding);
}

#[test]
fn truncated_signature_body_prefixes_are_rejected() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-malformed-sig-keygen!");
    let keypair = Falcon512::keygen(&mut keygen_rng).expect("keygen");
    let mut sign_rng = FixedRng::new(b"falcon2017-malformed-sig-rng");
    let sig = keypair
        .secret
        .sign_ref(b"malformed signature prefixes", Compression::Static, &mut sign_rng)
        .expect("signature");
    let prepared = keypair.public.prepare().expect("prepared public key");

    for prefix_len in 0..sig.body_bytes().len() {
        let mut verifier = prepared.verifier(sig.nonce());
        verifier.update(b"malformed signature prefixes");
        let err = verifier
            .finalize(&sig.body_bytes()[..prefix_len])
            .expect_err("must reject");
        assert_eq!(err, Error::InvalidEncoding, "prefix length {prefix_len}");
    }
}

#[test]
fn malformed_signature_headers_and_trailing_bytes_are_rejected() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-malformed-sig-header!");
    let keypair = Falcon512::keygen(&mut keygen_rng).expect("keygen");
    let mut sign_rng = FixedRng::new(b"falcon2017-malformed-sig-body");
    let sig = keypair
        .secret
        .sign_ref(b"malformed signature body", Compression::None, &mut sign_rng)
        .expect("signature");
    let prepared = keypair.public.prepare().expect("prepared public key");

    let mut reserved = sig.body_bytes().to_vec();
    reserved[0] |= 0x10;
    let mut verifier = prepared.verifier(sig.nonce());
    verifier.update(b"malformed signature body");
    let err = verifier.finalize(&reserved).expect_err("must reject reserved bit");
    assert_eq!(err, Error::InvalidEncoding);

    let mut wrong_logn = sig.body_bytes().to_vec();
    wrong_logn[0] = (wrong_logn[0] & 0xF0) | 0x08;
    let mut verifier = prepared.verifier(sig.nonce());
    verifier.update(b"malformed signature body");
    let err = verifier.finalize(&wrong_logn).expect_err("must reject wrong logn");
    assert_eq!(err, Error::InvalidEncoding);

    let mut trailing = sig.body_bytes().to_vec();
    trailing.push(0);
    let mut verifier = prepared.verifier(sig.nonce());
    verifier.update(b"malformed signature body");
    let err = verifier.finalize(&trailing).expect_err("must reject trailing byte");
    assert_eq!(err, Error::InvalidEncoding);
}

#[test]
fn wrong_nonce_and_wrong_message_fail_as_invalid_signature() {
    let mut keygen_rng = FixedSeedRng::new(*b"falcon2017-malformed-semantics!!");
    let keypair = Falcon512::keygen(&mut keygen_rng).expect("keygen");
    let mut sign_rng = FixedRng::new(b"falcon2017-malformed-semantic-rng");
    let sig = keypair
        .secret
        .sign_ref(
            b"message used when signature was made",
            Compression::Static,
            &mut sign_rng,
        )
        .expect("signature");
    let prepared = keypair.public.prepare().expect("prepared public key");

    let wrong_nonce = Nonce::from_bytes(b"wrong nonce for malformed signature");
    let mut verifier = prepared.verifier(&wrong_nonce);
    verifier.update(b"message used when signature was made");
    let err = verifier
        .finalize(sig.body_bytes())
        .expect_err("must reject wrong nonce");
    assert_eq!(err, Error::InvalidSignature);

    let mut verifier = prepared.verifier(sig.nonce());
    verifier.update(b"wrong message");
    let err = verifier
        .finalize(sig.body_bytes())
        .expect_err("must reject wrong message");
    assert_eq!(err, Error::InvalidSignature);
}
