//! Strict constant-time Falcon signing.
//!
//! Step 25 keeps the expanded-key public API live by signing from the step-24
//! `ExpandedSecretKeyCt` representation while still executing the historical
//! Falcon/Extra signing flow on transient reference-`Fpr` scratch. The final
//! integer-only executor remains a later CT milestone.

use crate::compression::Compression;
use crate::encoding::signature;
use crate::error::{Error, Result};
use crate::falcon::hash_to_point::{hash_message_to_point_binary_into, is_short_binary};
use crate::falcon::sign_ref::seed_prng_stream;
use crate::falcon::workspace::{SignCtWorkspace, SignRefWorkspace};
use crate::math::fft::{
    fft, ifft, poly_add, poly_merge_fft, poly_mul_fft, poly_mulconst, poly_split_fft, poly_sub,
};
use crate::math::fpr::ref_f64::{fpr_inverse_of, fpr_neg, fpr_of, fpr_rint, Fpr};
use crate::math::ntt::QB;
use crate::params::{is_public_logn, DEFAULT_NONCE_LEN};
use crate::rng::prng::{Prng, PRNG_CHACHA20};
use crate::rng::shake256::ShakeContext;
use crate::sampler::sign_ref::sample_binary;
use crate::types::{DetachedSignature, ExpandedSecretKeyCt, ExpandedSecretKeyCtInner, Nonce};
use rand_core::{CryptoRng, RngCore};

struct ExpandedRefKey<'a> {
    logn: u32,
    data: &'a [Fpr],
}

impl ExpandedRefKey<'_> {
    fn b00(&self) -> &[Fpr] {
        let n = 1usize << self.logn;
        &self.data[..n]
    }

    fn b01(&self) -> &[Fpr] {
        let n = 1usize << self.logn;
        &self.data[n..2 * n]
    }

    fn b10(&self) -> &[Fpr] {
        let n = 1usize << self.logn;
        &self.data[2 * n..3 * n]
    }

    fn b11(&self) -> &[Fpr] {
        let n = 1usize << self.logn;
        &self.data[3 * n..4 * n]
    }

    fn tree(&self) -> &[Fpr] {
        let n = 1usize << self.logn;
        &self.data[4 * n..]
    }
}

const fn ffldl_treesize(logn: u32) -> usize {
    ((logn + 1) as usize) << logn
}

fn expanded_ref_key_len(logn: u32) -> usize {
    let n = 1usize << logn;
    4 * n + ffldl_treesize(logn)
}

fn copy_soft_to_ref(dst: &mut [Fpr], src: &[crate::math::fpr::soft::Fpr]) {
    assert_eq!(dst.len(), src.len());
    for (dst, src) in dst.iter_mut().zip(src.iter()) {
        *dst = Fpr::new(f64::from_bits(src.bits()));
    }
}

fn load_expanded_ref_key<'a, const LOGN: u32>(
    expanded: &ExpandedSecretKeyCtInner<LOGN>,
    prepared: &'a mut [Fpr],
) -> ExpandedRefKey<'a> {
    let n = 1usize << LOGN;
    let tree_len = ffldl_treesize(LOGN);
    let prepared = &mut prepared[..expanded_ref_key_len(LOGN)];
    assert_eq!(expanded.b00.len(), n);
    assert_eq!(expanded.b01.len(), n);
    assert_eq!(expanded.b10.len(), n);
    assert_eq!(expanded.b11.len(), n);
    assert_eq!(expanded.tree.len(), tree_len);

    let (b00, rest) = prepared.split_at_mut(n);
    let (b01, rest) = rest.split_at_mut(n);
    let (b10, rest) = rest.split_at_mut(n);
    let (b11, tree) = rest.split_at_mut(n);

    copy_soft_to_ref(b00, &expanded.b00);
    copy_soft_to_ref(b01, &expanded.b01);
    copy_soft_to_ref(b10, &expanded.b10);
    copy_soft_to_ref(b11, &expanded.b11);
    copy_soft_to_ref(tree, &expanded.tree);

    ExpandedRefKey {
        logn: LOGN,
        data: prepared,
    }
}

fn ffsampling_fft<S: FnMut(Fpr, Fpr) -> i32>(
    sampler: &mut S,
    z: (&mut [Fpr], &mut [Fpr]),
    tree: &[Fpr],
    t: (&[Fpr], &[Fpr]),
    logn: u32,
    tmp: &mut [Fpr],
) {
    let (z0, z1) = z;
    let (t0, t1) = t;
    let n = 1usize << logn;

    if n == 1 {
        let sigma = tree[0];
        z0[0] = fpr_of(i64::from(sampler(t0[0], sigma)));
        z1[0] = fpr_of(i64::from(sampler(t1[0], sigma)));
        return;
    }

    let hn = n >> 1;
    let left_size = ffldl_treesize(logn - 1);
    let tree_l10 = &tree[..n];
    let tree0 = &tree[n..n + left_size];
    let tree1 = &tree[n + left_size..n + left_size + left_size];

    let (z1_lo, z1_hi) = z1.split_at_mut(hn);
    poly_split_fft(z1_lo, z1_hi, t1, logn);
    let (tmp_lo, rest) = tmp.split_at_mut(hn);
    let (tmp_hi, tmp_next) = rest.split_at_mut(hn);
    ffsampling_fft(
        sampler,
        (tmp_lo, tmp_hi),
        tree1,
        (z1_lo, z1_hi),
        logn - 1,
        tmp_next,
    );
    poly_merge_fft(z1, tmp_lo, tmp_hi, logn);

    let (z0_lo, z0_hi) = z0.split_at_mut(hn);
    {
        let (tb0, _) = tmp.split_at_mut(n);
        tb0.copy_from_slice(t1);
        poly_sub(tb0, z1, logn);
        poly_mul_fft(tb0, tree_l10, logn);
        poly_add(tb0, t0, logn);
        poly_split_fft(z0_lo, z0_hi, tb0, logn);
    }

    let (tmp_rec, tmp_next) = tmp.split_at_mut(n);
    let (tmp_lo, tmp_hi) = tmp_rec.split_at_mut(hn);
    ffsampling_fft(
        sampler,
        (tmp_lo, tmp_hi),
        tree0,
        (z0_lo, z0_hi),
        logn - 1,
        tmp_next,
    );
    poly_merge_fft(z0, tmp_lo, tmp_hi, logn);
}

fn do_sign_binary_in(
    s1: &mut [i16],
    s2: &mut [i16],
    sk: &ExpandedRefKey<'_>,
    hm: &[u16],
    prng: &mut Prng,
    tmp: &mut [Fpr],
) {
    let logn = sk.logn;
    let n = 1usize << logn;
    let b00 = sk.b00();
    let b01 = sk.b01();
    let b10 = sk.b10();
    let b11 = sk.b11();
    let tree = sk.tree();

    let tmp = &mut tmp[..6 * n];
    let (t0, rest) = tmp.split_at_mut(n);
    let (t1, rest) = rest.split_at_mut(n);
    let (tx, rest) = rest.split_at_mut(n);
    let (ty, tz) = rest.split_at_mut(n);

    for (dst, &src) in t0.iter_mut().zip(hm.iter()) {
        *dst = fpr_of(i64::from(src));
    }

    fft(t0, logn);
    let ni = fpr_inverse_of(i64::from(QB));
    t1.copy_from_slice(t0);
    poly_mul_fft(t1, b01, logn);
    poly_mulconst(t1, fpr_neg(ni), logn);
    poly_mul_fft(t0, b11, logn);
    poly_mulconst(t0, ni, logn);

    ffsampling_fft(
        &mut |mu, sigma| sample_binary(prng, mu, sigma),
        (tx, ty),
        tree,
        (t0, t1),
        logn,
        tz,
    );

    t0.copy_from_slice(tx);
    t1.copy_from_slice(ty);
    poly_mul_fft(tx, b00, logn);
    poly_mul_fft(ty, b10, logn);
    poly_add(tx, ty, logn);
    ty.copy_from_slice(t0);
    poly_mul_fft(ty, b01, logn);

    t0.copy_from_slice(tx);
    poly_mul_fft(t1, b11, logn);
    poly_add(t1, ty, logn);

    ifft(t0, logn);
    ifft(t1, logn);

    for u in 0..n {
        let s1_value = i64::from(hm[u]) - fpr_rint(t0[u]);
        let s2_value = -fpr_rint(t1[u]);
        debug_assert!(i16::try_from(s1_value).is_ok());
        debug_assert!(i16::try_from(s2_value).is_ok());
        s1[u] = s1_value as i16;
        s2[u] = s2_value as i16;
    }
}

fn sign_detached_with_rng_stream_in<const LOGN: u32>(
    expanded: &ExpandedSecretKeyCt<LOGN>,
    msg: &[u8],
    nonce: Nonce,
    comp: Compression,
    rng_stream: &mut ShakeContext,
    ws: &mut SignRefWorkspace<LOGN>,
) -> Result<DetachedSignature<LOGN>> {
    if !is_public_logn(LOGN) {
        return Err(Error::InvalidParameter);
    }

    let n = 1usize << LOGN;
    let SignRefWorkspace {
        hm,
        s1,
        s2,
        prepared,
        prepare_tmp: _,
        sign_tmp,
        seed: _,
        nonce: _,
    } = ws;

    hash_message_to_point_binary_into(nonce.as_bytes(), msg, LOGN, &mut hm[..n]);
    let prepared = load_expanded_ref_key(&expanded.inner, prepared);

    loop {
        let mut prng = Prng::new(rng_stream, PRNG_CHACHA20).ok_or(Error::Internal)?;
        do_sign_binary_in(
            &mut s1[..n],
            &mut s2[..n],
            &prepared,
            &hm[..n],
            &mut prng,
            sign_tmp,
        );
        if is_short_binary(&s1[..n], &s2[..n], LOGN) {
            let body =
                signature::encode(false, comp, LOGN, &s2[..n]).map_err(|_| Error::Internal)?;
            return Ok(DetachedSignature { nonce, body });
        }
    }
}

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
    let mut rng_stream = seed_prng_stream(rng)?;
    ws.inner.nonce.clear();
    ws.inner.nonce.resize(DEFAULT_NONCE_LEN, 0);
    rng_stream.extract(ws.inner.nonce.as_mut_slice());
    let nonce = Nonce(ws.inner.nonce.clone().into_boxed_slice());
    sign_detached_with_rng_stream_in(expanded, msg, nonce, comp, &mut rng_stream, &mut ws.inner)
}

pub(crate) fn sign_ct_strict_with_external_nonce_in<const LOGN: u32>(
    expanded: &ExpandedSecretKeyCt<LOGN>,
    msg: &[u8],
    nonce: Nonce,
    comp: Compression,
    rng: &mut (impl RngCore + CryptoRng),
    ws: &mut SignCtWorkspace<LOGN>,
) -> Result<DetachedSignature<LOGN>> {
    let mut rng_stream = seed_prng_stream(rng)?;
    sign_detached_with_rng_stream_in(expanded, msg, nonce, comp, &mut rng_stream, &mut ws.inner)
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
    fn sign_ct_strict_matches_reference_c_vector() {
        let sk = SecretKey::<9>::from_bytes(&STEP17_SK).expect("reference secret key");
        let expanded = sk.expand_ct_strict().expect("expanded key");
        let mut rng = FixedRng::new(&STEP17_SIGN_SEED_DEFAULT);
        let sig = expanded
            .sign_ct_strict(&STEP17_MSG, Compression::Static, &mut rng)
            .expect("signature");

        assert_eq!(sig.nonce().as_bytes(), &STEP17_NONCE_DEFAULT);
        assert_eq!(sig.body_bytes(), &STEP17_SIG_DEFAULT);
    }

    #[test]
    fn sign_ct_strict_with_external_nonce_matches_reference_c_vector() {
        let sk = SecretKey::<9>::from_bytes(&STEP17_SK).expect("reference secret key");
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

        assert_eq!(sig.nonce().as_bytes(), &STEP17_NONCE_EXTERNAL);
        assert_eq!(sig.body_bytes(), &STEP17_SIG_EXTERNAL);
    }
}
