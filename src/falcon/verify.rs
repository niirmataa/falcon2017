//! Falcon signature verification.

use crate::encoding::{public_key, signature};
use crate::error::{Error, Result};
use crate::falcon::hash_to_point::{hash_message_to_point_binary, is_short_binary};
use crate::math::ntt::{
    mq_intt_binary, mq_ntt_binary, mq_poly_montymul_ntt, mq_poly_sub, mq_poly_tomonty, QB,
};
use crate::params::is_public_logn;
use crate::types::{DetachedSignature, PublicKey};

fn prepare_public_key_ntt(h: &[u16], logn: u32) -> Box<[u16]> {
    let mut prepared = h.to_vec();
    mq_ntt_binary(&mut prepared, logn);
    mq_poly_tomonty(&mut prepared, logn);
    prepared.into_boxed_slice()
}

fn verify_raw_binary(c0: &[u16], s2: &[i16], h_ntt: &[u16], logn: u32) -> bool {
    let n = 1usize << logn;
    if c0.len() != n || s2.len() != n || h_ntt.len() != n {
        return false;
    }

    let mut x = vec![0u16; n];
    for u in 0..n {
        let mut w = s2[u] as i32;
        if w < 0 {
            w += QB as i32;
        }
        x[u] = w as u16;
    }

    mq_ntt_binary(&mut x, logn);
    mq_poly_montymul_ntt(&mut x, h_ntt, logn);
    mq_intt_binary(&mut x, logn);
    mq_poly_sub(&mut x, c0, logn);

    let mut s1 = vec![0i16; n];
    for u in 0..n {
        let mut w = i32::from(x[u]);
        if w > (QB as i32 >> 1) {
            w -= QB as i32;
        }
        s1[u] = w as i16;
    }
    is_short_binary(&s1, s2, logn)
}

pub(crate) fn decode_public_key<const LOGN: u32>(bytes: &[u8]) -> Result<Box<[u16]>> {
    if !is_public_logn(LOGN) {
        return Err(Error::InvalidParameter);
    }
    let decoded = public_key::decode(bytes)?;
    if decoded.ternary || decoded.logn != LOGN {
        return Err(Error::InvalidEncoding);
    }
    Ok(decoded.h)
}

pub(crate) fn public_key_from_bytes<const LOGN: u32>(bytes: &[u8]) -> Result<PublicKey<LOGN>> {
    let _ = decode_public_key::<LOGN>(bytes)?;
    Ok(PublicKey {
        bytes: bytes.to_vec().into_boxed_slice(),
    })
}

pub(crate) fn verify_detached<const LOGN: u32>(
    public: &PublicKey<LOGN>,
    msg: &[u8],
    sig: &DetachedSignature<LOGN>,
) -> Result<()> {
    if !is_public_logn(LOGN) {
        return Err(Error::InvalidParameter);
    }

    let h = decode_public_key::<LOGN>(&public.bytes)?;
    let prepared = prepare_public_key_ntt(&h, LOGN);

    let sig_decoded = signature::decode(&sig.body)?;
    if sig_decoded.ternary || sig_decoded.logn != LOGN {
        return Err(Error::InvalidEncoding);
    }

    let c0 = hash_message_to_point_binary(sig.nonce.as_bytes(), msg, LOGN);
    if verify_raw_binary(&c0, &sig_decoded.s2, &prepared, LOGN) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
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
}
