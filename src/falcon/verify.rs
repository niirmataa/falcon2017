//! Falcon signature verification.

use crate::compression::Compression;
use crate::encoding::{ring12289, smallvec};
use crate::error::{Error, Result};
use crate::falcon::hash_to_point::{hash_to_point_binary_into, is_short_binary};
use crate::falcon::workspace::VerifyWorkspace;
use crate::math::ntt::{
    mq_intt_binary, mq_ntt_binary, mq_poly_montymul_ntt, mq_poly_sub, mq_poly_tomonty, QB,
};
use crate::params::is_public_logn;
use crate::rng::shake256::ShakeContext;
use crate::types::{
    DetachedSignature, Nonce, PreparedPublicKey, PreparedPublicKeyInner, PublicKey, Verifier,
};

fn prepare_public_key_ntt(h: &[u16], logn: u32) -> Box<[u16]> {
    let mut prepared = h.to_vec();
    prepare_public_key_ntt_in(h, logn, &mut prepared);
    prepared.into_boxed_slice()
}

fn prepare_public_key_ntt_in(h: &[u16], logn: u32, prepared: &mut [u16]) {
    prepared.copy_from_slice(h);
    mq_ntt_binary(prepared, logn);
    mq_poly_tomonty(prepared, logn);
}

fn verify_raw_binary(c0: &[u16], s2: &[i16], h_ntt: &[u16], logn: u32) -> bool {
    let n = 1usize << logn;
    let mut x = vec![0u16; n];
    let mut s1 = vec![0i16; n];
    verify_raw_binary_in(c0, s2, h_ntt, logn, &mut x, &mut s1)
}

fn verify_raw_binary_in(
    c0: &[u16],
    s2: &[i16],
    h_ntt: &[u16],
    logn: u32,
    x: &mut [u16],
    s1: &mut [i16],
) -> bool {
    let n = 1usize << logn;
    if c0.len() != n || s2.len() != n || h_ntt.len() != n {
        return false;
    }
    debug_assert_eq!(x.len(), n);
    debug_assert_eq!(s1.len(), n);

    for u in 0..n {
        let mut w = s2[u] as i32;
        if w < 0 {
            w += QB as i32;
        }
        x[u] = w as u16;
    }

    mq_ntt_binary(x, logn);
    mq_poly_montymul_ntt(x, h_ntt, logn);
    mq_intt_binary(x, logn);
    mq_poly_sub(x, c0, logn);

    for u in 0..n {
        let mut w = i32::from(x[u]);
        if w > (QB as i32 >> 1) {
            w -= QB as i32;
        }
        s1[u] = w as i16;
    }
    is_short_binary(&s1, s2, logn)
}

fn decode_signature_s2<const LOGN: u32>(sig_body: &[u8]) -> Result<Box<[i16]>> {
    let mut s2 = vec![0i16; 1usize << LOGN];
    decode_signature_s2_into::<LOGN>(sig_body, &mut s2)?;
    Ok(s2.into_boxed_slice())
}

fn decode_signature_s2_into<const LOGN: u32>(sig_body: &[u8], s2: &mut [i16]) -> Result<()> {
    if !is_public_logn(LOGN) {
        return Err(Error::InvalidParameter);
    }
    if sig_body.len() <= 1 {
        return Err(Error::InvalidEncoding);
    }
    let fb = sig_body[0];
    if (fb & 0x10) != 0 {
        return Err(Error::InvalidEncoding);
    }
    let ternary = (fb >> 7) != 0;
    let logn = u32::from(fb & 0x0F);
    if ternary || logn != LOGN {
        return Err(Error::InvalidEncoding);
    }
    let compression = match (fb >> 5) & 0x03 {
        0 => Compression::None,
        1 => Compression::Static,
        _ => return Err(Error::InvalidEncoding),
    };
    let used = smallvec::decode_into(compression, QB, &sig_body[1..], LOGN, s2)?;
    if used != (sig_body.len() - 1) {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}

fn verify_prepared_hash<const LOGN: u32>(
    h_ntt: &[u16],
    hash: &mut ShakeContext,
    sig_body: &[u8],
) -> Result<()> {
    let n = 1usize << LOGN;
    let mut c0 = vec![0u16; n];
    let mut x = vec![0u16; n];
    let mut s1 = vec![0i16; n];
    let mut s2 = vec![0i16; n];
    verify_prepared_hash_in::<LOGN>(h_ntt, hash, sig_body, &mut c0, &mut x, &mut s1, &mut s2)
}

fn verify_prepared_hash_in<const LOGN: u32>(
    h_ntt: &[u16],
    hash: &mut ShakeContext,
    sig_body: &[u8],
    c0: &mut [u16],
    x: &mut [u16],
    s1: &mut [i16],
    s2: &mut [i16],
) -> Result<()> {
    decode_signature_s2_into::<LOGN>(sig_body, s2)?;
    hash_to_point_binary_into(hash, LOGN, c0);
    if verify_raw_binary_in(c0, s2, h_ntt, LOGN, x, s1) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

pub(crate) fn decode_public_key<const LOGN: u32>(bytes: &[u8]) -> Result<Box<[u16]>> {
    let mut h = vec![0u16; 1usize << LOGN];
    decode_public_key_into::<LOGN>(bytes, &mut h)?;
    Ok(h.into_boxed_slice())
}

fn decode_public_key_into<const LOGN: u32>(bytes: &[u8], h: &mut [u16]) -> Result<()> {
    if !is_public_logn(LOGN) {
        return Err(Error::InvalidParameter);
    }
    if bytes.len() <= 1 {
        return Err(Error::InvalidEncoding);
    }
    let fb = bytes[0];
    let ternary = (fb >> 7) != 0;
    let logn = u32::from(fb & 0x0F);
    if ternary || logn != LOGN || ((fb >> 4) & 0x07) != 0 {
        return Err(Error::InvalidEncoding);
    }
    ring12289::decode_into(&bytes[1..], LOGN, h)
}

pub(crate) fn public_key_from_bytes<const LOGN: u32>(bytes: &[u8]) -> Result<PublicKey<LOGN>> {
    let _ = decode_public_key::<LOGN>(bytes)?;
    Ok(PublicKey {
        bytes: bytes.to_vec().into_boxed_slice(),
    })
}

pub(crate) fn prepare_public_key<const LOGN: u32>(
    public: &PublicKey<LOGN>,
) -> Result<PreparedPublicKey<LOGN>> {
    let h = decode_public_key::<LOGN>(&public.bytes)?;
    Ok(PreparedPublicKey {
        inner: PreparedPublicKeyInner {
            h_ntt: prepare_public_key_ntt(&h, LOGN),
        },
    })
}

pub(crate) fn verify_prepared_detached<const LOGN: u32>(
    prepared: &PreparedPublicKey<LOGN>,
    msg: &[u8],
    sig: &DetachedSignature<LOGN>,
) -> Result<()> {
    let mut ws = VerifyWorkspace::<LOGN>::new();
    verify_prepared_detached_in(prepared, msg, sig, &mut ws)
}

pub(crate) fn verify_prepared_detached_in<const LOGN: u32>(
    prepared: &PreparedPublicKey<LOGN>,
    msg: &[u8],
    sig: &DetachedSignature<LOGN>,
    ws: &mut VerifyWorkspace<LOGN>,
) -> Result<()> {
    if !is_public_logn(LOGN) {
        return Err(Error::InvalidParameter);
    }

    let n = 1usize << LOGN;
    let mut hash = ShakeContext::shake256();
    hash.inject(sig.nonce.as_bytes());
    hash.inject(msg);
    hash.flip();
    verify_prepared_hash_in::<LOGN>(
        &prepared.inner.h_ntt,
        &mut hash,
        &sig.body,
        &mut ws.c0[..n],
        &mut ws.x[..n],
        &mut ws.s1[..n],
        &mut ws.s2[..n],
    )
}

pub(crate) fn start_verifier<const LOGN: u32>(
    prepared: &PreparedPublicKey<LOGN>,
    nonce: &Nonce,
) -> Verifier<LOGN> {
    let mut hash = ShakeContext::shake256();
    hash.inject(nonce.as_bytes());
    Verifier {
        hash,
        h_ntt: prepared.inner.h_ntt.clone(),
    }
}

pub(crate) fn finalize_verifier<const LOGN: u32>(
    verifier: Verifier<LOGN>,
    sig_body: &[u8],
) -> Result<()> {
    if !is_public_logn(LOGN) {
        return Err(Error::InvalidParameter);
    }

    let Verifier { mut hash, h_ntt } = verifier;
    hash.flip();
    verify_prepared_hash::<LOGN>(&h_ntt, &mut hash, sig_body)
}

pub(crate) fn verify_detached<const LOGN: u32>(
    public: &PublicKey<LOGN>,
    msg: &[u8],
    sig: &DetachedSignature<LOGN>,
) -> Result<()> {
    let mut ws = VerifyWorkspace::<LOGN>::new();
    verify_detached_in(public, msg, sig, &mut ws)
}

pub(crate) fn verify_detached_in<const LOGN: u32>(
    public: &PublicKey<LOGN>,
    msg: &[u8],
    sig: &DetachedSignature<LOGN>,
    ws: &mut VerifyWorkspace<LOGN>,
) -> Result<()> {
    if !is_public_logn(LOGN) {
        return Err(Error::InvalidParameter);
    }

    let n = 1usize << LOGN;
    decode_public_key_into::<LOGN>(&public.bytes, &mut ws.decoded_h[..n])?;
    prepare_public_key_ntt_in(&ws.decoded_h[..n], LOGN, &mut ws.h_ntt[..n]);

    let mut hash = ShakeContext::shake256();
    hash.inject(sig.nonce.as_bytes());
    hash.inject(msg);
    hash.flip();
    verify_prepared_hash_in::<LOGN>(
        &ws.h_ntt[..n],
        &mut hash,
        &sig.body,
        &mut ws.c0[..n],
        &mut ws.x[..n],
        &mut ws.s1[..n],
        &mut ws.s2[..n],
    )
}

#[cfg(test)]
mod tests {
    use super::{prepare_public_key_ntt, verify_raw_binary};
    use crate::compression::Compression;
    use crate::encoding::{public_key, signature};
    use crate::error::Error;
    use crate::falcon::hash_to_point::hash_message_to_point_binary;
    use crate::falcon::keygen::keygen_from_seed_material;
    use crate::types::{DetachedSignature, Nonce, PublicKey};

    include!("verify_step16_vector.rs");

    #[test]
    fn verify_detached_rejects_malformed_public_key() {
        let err = PublicKey::<9>::from_bytes(&[0x10, 0x00, 0x00]).expect_err("must reject");
        assert_eq!(err, Error::InvalidEncoding);
    }

    #[test]
    fn verify_raw_binary_accepts_zero_signature_for_zero_challenge() {
        let h = vec![1u16; 16];
        let h_ntt = prepare_public_key_ntt(&h, 4);
        let c0 = vec![0u16; 16];
        let s2 = vec![0i16; 16];

        assert!(verify_raw_binary(&c0, &s2, &h_ntt, 4));
    }

    #[test]
    fn verify_detached_distinguishes_invalid_signature_from_invalid_encoding() {
        let keypair =
            keygen_from_seed_material::<9>(b"falcon2017-step16-verify-keygen").expect("keygen");
        let nonce = Nonce(b"verify-step16-nonce".to_vec().into_boxed_slice());
        let c0 = hash_message_to_point_binary(nonce.as_bytes(), b"", 9);
        let body =
            signature::encode(false, Compression::None, 9, &vec![0i16; 1 << 9]).expect("sig");

        let sig = DetachedSignature {
            nonce: nonce.clone(),
            body,
        };
        let err = keypair
            .public
            .verify_detached(b"", &sig)
            .expect_err("wrong signature");
        assert_eq!(err, Error::InvalidSignature);

        let bad_sig = DetachedSignature {
            nonce,
            body: [0x10u8, 0x00, 0x00].to_vec().into_boxed_slice(),
        };
        let err = keypair
            .public
            .verify_detached(b"", &bad_sig)
            .expect_err("bad encoding");
        assert_eq!(err, Error::InvalidEncoding);

        let decoded = public_key::decode(keypair.public.to_bytes()).expect("pk decode");
        let h_ntt = prepare_public_key_ntt(&decoded.h, 9);
        assert!(!verify_raw_binary(&c0, &vec![0i16; 1 << 9], &h_ntt, 9));
    }

    #[test]
    fn verify_detached_accepts_reference_c_vector() {
        let public = PublicKey::<9>::from_bytes(&STEP16_PK).expect("public key");
        let sig = DetachedSignature {
            nonce: Nonce(STEP16_NONCE.to_vec().into_boxed_slice()),
            body: STEP16_SIG.to_vec().into_boxed_slice(),
        };

        public
            .verify_detached(&STEP16_MSG, &sig)
            .expect("reference C signature must verify");
    }

    #[test]
    fn prepared_public_key_accepts_reference_c_vector() {
        let public = PublicKey::<9>::from_bytes(&STEP16_PK).expect("public key");
        let prepared = public.prepare().expect("prepared public key");
        let sig = DetachedSignature {
            nonce: Nonce(STEP16_NONCE.to_vec().into_boxed_slice()),
            body: STEP16_SIG.to_vec().into_boxed_slice(),
        };

        prepared
            .verify_detached(&STEP16_MSG, &sig)
            .expect("reference C signature must verify");
    }

    #[test]
    fn streaming_verifier_accepts_reference_c_vector() {
        let public = PublicKey::<9>::from_bytes(&STEP16_PK).expect("public key");
        let prepared = public.prepare().expect("prepared public key");
        let nonce = Nonce(STEP16_NONCE.to_vec().into_boxed_slice());
        let mut verifier = prepared.verifier(&nonce);
        let split = STEP16_MSG.len() / 2;
        verifier.update(&STEP16_MSG[..split]);
        verifier.update(&STEP16_MSG[split..]);

        verifier
            .finalize(&STEP16_SIG)
            .expect("reference C signature must verify");
    }

    #[test]
    fn prepared_verify_preserves_error_split() {
        let keypair =
            keygen_from_seed_material::<9>(b"falcon2017-step18-prepared-verify").expect("keygen");
        let prepared = keypair.public.prepare().expect("prepared");
        let sig = DetachedSignature {
            nonce: Nonce(b"step18-nonce".to_vec().into_boxed_slice()),
            body: signature::encode(false, Compression::None, 9, &vec![0i16; 1 << 9])
                .expect("signature encoding"),
        };

        let err = prepared
            .verify_detached(b"", &sig)
            .expect_err("wrong signature");
        assert_eq!(err, Error::InvalidSignature);

        let bad_sig = DetachedSignature {
            nonce: sig.nonce.clone(),
            body: [0x10u8, 0x00, 0x00].to_vec().into_boxed_slice(),
        };
        let err = prepared
            .verify_detached(b"", &bad_sig)
            .expect_err("bad encoding");
        assert_eq!(err, Error::InvalidEncoding);
    }

    #[test]
    fn streaming_verifier_preserves_error_split() {
        let keypair =
            keygen_from_seed_material::<9>(b"falcon2017-step18-streaming-verify").expect("keygen");
        let prepared = keypair.public.prepare().expect("prepared");
        let nonce = Nonce(b"step18-streaming-nonce".to_vec().into_boxed_slice());
        let mut verifier = prepared.verifier(&nonce);
        verifier.update(b"hello");

        let err = verifier
            .clone()
            .finalize(
                &signature::encode(false, Compression::None, 9, &vec![0i16; 1 << 9])
                    .expect("signature encoding"),
            )
            .expect_err("wrong signature");
        assert_eq!(err, Error::InvalidSignature);

        let err = verifier
            .finalize(&[0x10u8, 0x00, 0x00])
            .expect_err("bad encoding");
        assert_eq!(err, Error::InvalidEncoding);
    }
}
