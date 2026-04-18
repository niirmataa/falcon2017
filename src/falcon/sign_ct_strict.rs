//! Strict constant-time Falcon signing public entry points.

use crate::compression::Compression;
use crate::error::Result;
use crate::falcon::sign_ct_bridge_ref::sign_detached_with_rng_stream_in;
use crate::falcon::sign_ref::seed_prng_stream;
use crate::falcon::workspace::SignCtWorkspace;
use crate::params::{is_public_logn, DEFAULT_NONCE_LEN};
use crate::types::{DetachedSignature, ExpandedSecretKeyCt, Nonce};
use rand_core::{CryptoRng, RngCore};

pub(crate) fn sign_ct_strict<const LOGN: u32>(
    expanded: &ExpandedSecretKeyCt<LOGN>,
    msg: &[u8],
    comp: Compression,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<DetachedSignature<LOGN>> {
    let mut ws = SignCtWorkspace::<LOGN>::new();
    sign_ct_strict_in(expanded, msg, comp, rng, &mut ws)
}

pub(crate) fn sign_ct_strict_with_external_nonce<const LOGN: u32>(
    expanded: &ExpandedSecretKeyCt<LOGN>,
    msg: &[u8],
    nonce: Nonce,
    comp: Compression,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<DetachedSignature<LOGN>> {
    let mut ws = SignCtWorkspace::<LOGN>::new();
    sign_ct_strict_with_external_nonce_in(expanded, msg, nonce, comp, rng, &mut ws)
}

pub(crate) fn sign_ct_strict_in<const LOGN: u32>(
    expanded: &ExpandedSecretKeyCt<LOGN>,
    msg: &[u8],
    comp: Compression,
    rng: &mut (impl RngCore + CryptoRng),
    ws: &mut SignCtWorkspace<LOGN>,
) -> Result<DetachedSignature<LOGN>> {
    debug_assert!(is_public_logn(LOGN));
    let mut rng_stream = seed_prng_stream(rng)?;
    ws.nonce.clear();
    ws.nonce.resize(DEFAULT_NONCE_LEN, 0);
    rng_stream.extract(ws.nonce.as_mut_slice());
    let nonce = Nonce(ws.nonce.clone().into_boxed_slice());
    sign_detached_with_rng_stream_in(expanded, msg, nonce, comp, &mut rng_stream, ws)
}

pub(crate) fn sign_ct_strict_with_external_nonce_in<const LOGN: u32>(
    expanded: &ExpandedSecretKeyCt<LOGN>,
    msg: &[u8],
    nonce: Nonce,
    comp: Compression,
    rng: &mut (impl RngCore + CryptoRng),
    ws: &mut SignCtWorkspace<LOGN>,
) -> Result<DetachedSignature<LOGN>> {
    debug_assert!(is_public_logn(LOGN));
    let mut rng_stream = seed_prng_stream(rng)?;
    sign_detached_with_rng_stream_in(expanded, msg, nonce, comp, &mut rng_stream, ws)
}

#[cfg(test)]
mod tests {
    use crate::compression::Compression;
    use crate::types::{Nonce, SecretKey};
    use rand_core::{CryptoRng, Error as RandError, RngCore};

    include!("sign_step17_vector.rs");

    struct FixedRng {
        bytes: Vec<u8>,
        pos: usize,
    }

    impl FixedRng {
        fn new(bytes: &[u8]) -> Self {
            Self {
                bytes: bytes.to_vec(),
                pos: 0,
            }
        }

        fn next_byte(&mut self) -> u8 {
            let value = self.bytes[self.pos % self.bytes.len()];
            self.pos += 1;
            value
        }
    }

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            let mut out = [0u8; 4];
            self.fill_bytes(&mut out);
            u32::from_le_bytes(out)
        }

        fn next_u64(&mut self) -> u64 {
            let mut out = [0u8; 8];
            self.fill_bytes(&mut out);
            u64::from_le_bytes(out)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.next_byte();
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), RandError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for FixedRng {}

    #[test]
    fn sign_ct_strict_roundtrips_on_reference_material() {
        let sk = SecretKey::<9>::from_bytes(&STEP17_SK).expect("reference secret key");
        let pk = sk.derive_public().expect("public key");
        let expanded = sk.expand_ct_strict().expect("expanded key");
        let mut rng = FixedRng::new(&STEP17_SIGN_SEED_DEFAULT);
        let sig = expanded
            .sign_ct_strict(&STEP17_MSG, Compression::Static, &mut rng)
            .expect("signature");

        pk.verify_detached(&STEP17_MSG, &sig).expect("verify");
    }

    #[test]
    fn sign_ct_strict_with_external_nonce_roundtrips_on_reference_material() {
        let sk = SecretKey::<9>::from_bytes(&STEP17_SK).expect("reference secret key");
        let pk = sk.derive_public().expect("public key");
        let expanded = sk.expand_ct_strict().expect("expanded key");
        let mut rng = FixedRng::new(&STEP17_SIGN_SEED_EXTERNAL);
        let sig = expanded
            .sign_ct_strict_with_external_nonce(
                &STEP17_MSG,
                Nonce::from_bytes(&STEP17_NONCE_EXTERNAL),
                Compression::None,
                &mut rng,
            )
            .expect("signature");

        pk.verify_detached(&STEP17_MSG, &sig).expect("verify");
    }
}
