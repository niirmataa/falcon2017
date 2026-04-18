//! Reference Falcon signing.

use crate::compression::Compression;
use crate::encoding::signature;
use crate::error::{Error, Result};
use crate::falcon::hash_to_point::{hash_message_to_point_binary_into, is_short_binary};
use crate::falcon::workspace::SignRefWorkspace;
use crate::math::fft::{
    fft, ifft, poly_add, poly_adj_fft, poly_merge_fft, poly_mul_fft, poly_muladj_fft,
    poly_mulconst, poly_mulselfadj_fft, poly_neg, poly_split_fft, poly_sub,
};
use crate::math::fpr::ref_f64::{
    fpr_div, fpr_inverse_of, fpr_mul, fpr_neg, fpr_of, fpr_rint, fpr_sqrt, Fpr,
};
use crate::math::ntt::QB;
use crate::params::{is_public_logn, DEFAULT_NONCE_LEN};
use crate::rng::prng::{Prng, PRNG_CHACHA20};
use crate::rng::shake256::ShakeContext;
use crate::sampler::sign_ref::sample_binary;
use crate::types::{DetachedSignature, Nonce, SecretKey};
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

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

fn smallints_to_fpr(dst: &mut [Fpr], src: &[i8], logn: u32) {
    let n = 1usize << logn;
    assert_eq!(dst.len(), n);
    assert_eq!(src.len(), n);
    for (d, &s) in dst.iter_mut().zip(src.iter()) {
        *d = fpr_of(i64::from(s));
    }
}

fn ldl_fft(
    d11: &mut [Fpr],
    l10: &mut [Fpr],
    g00: &[Fpr],
    g01: &[Fpr],
    g11: &[Fpr],
    logn: u32,
    tmp: &mut [Fpr],
) {
    let n = 1usize << logn;
    let tmp = &mut tmp[..n];
    tmp.copy_from_slice(g01);
    crate::math::fft::poly_div_fft(tmp, g00, logn);
    l10.copy_from_slice(tmp);
    poly_adj_fft(l10, logn);
    poly_mul_fft(tmp, l10, logn);
    poly_mul_fft(tmp, g00, logn);
    d11.copy_from_slice(g11);
    poly_sub(d11, tmp, logn);
}

fn ldlqc_fft(
    d11: &mut [Fpr],
    l10: &mut [Fpr],
    g00: &[Fpr],
    g01: &[Fpr],
    logn: u32,
    tmp: &mut [Fpr],
) {
    ldl_fft(d11, l10, g00, g01, g00, logn, tmp);
}

fn ffldl_fft_inner(tree: &mut [Fpr], g0: &mut [Fpr], g1: &mut [Fpr], logn: u32, tmp: &mut [Fpr]) {
    let n = 1usize << logn;
    if n == 1 {
        tree[0] = g0[0];
        return;
    }

    let hn = n >> 1;
    let (tmp0, tmp1) = tmp.split_at_mut(n);
    ldlqc_fft(tmp0, &mut tree[..n], g0, g1, logn, tmp1);

    let (g1_lo, g1_hi) = g1.split_at_mut(hn);
    poly_split_fft(g1_lo, g1_hi, g0, logn);
    let (g0_lo, g0_hi) = g0.split_at_mut(hn);
    poly_split_fft(g0_lo, g0_hi, tmp0, logn);

    let left_size = ffldl_treesize(logn - 1);
    ffldl_fft_inner(&mut tree[n..n + left_size], g1_lo, g1_hi, logn - 1, tmp0);
    ffldl_fft_inner(
        &mut tree[n + left_size..n + left_size + left_size],
        g0_lo,
        g0_hi,
        logn - 1,
        tmp0,
    );
}

fn ffldl_fft(tree: &mut [Fpr], g00: &[Fpr], g01: &[Fpr], g11: &[Fpr], logn: u32, tmp: &mut [Fpr]) {
    let n = 1usize << logn;
    if n == 1 {
        tree[0] = g00[0];
        return;
    }

    let hn = n >> 1;
    let (d00, rest) = tmp.split_at_mut(n);
    let (d11, tmp2) = rest.split_at_mut(n);
    d00.copy_from_slice(g00);
    ldl_fft(d11, &mut tree[..n], g00, g01, g11, logn, tmp2);

    let (tmp_lo, rest) = tmp2.split_at_mut(hn);
    let (tmp_hi, _) = rest.split_at_mut(hn);
    poly_split_fft(tmp_lo, tmp_hi, d00, logn);
    let (d00_lo, d00_hi) = d00.split_at_mut(hn);
    poly_split_fft(d00_lo, d00_hi, d11, logn);
    d11[..n].copy_from_slice(&tmp2[..n]);

    let left_size = ffldl_treesize(logn - 1);
    let (d11_lo, d11_hi) = d11.split_at_mut(hn);
    ffldl_fft_inner(&mut tree[n..n + left_size], d11_lo, d11_hi, logn - 1, tmp2);
    ffldl_fft_inner(
        &mut tree[n + left_size..n + left_size + left_size],
        d00_lo,
        d00_hi,
        logn - 1,
        tmp2,
    );
}

fn ffldl_binary_normalize(tree: &mut [Fpr], sigma: Fpr, logn: u32) {
    let n = 1usize << logn;
    if n == 1 {
        tree[0] = fpr_div(sigma, fpr_sqrt(tree[0]));
        return;
    }

    let left_size = ffldl_treesize(logn - 1);
    ffldl_binary_normalize(&mut tree[n..n + left_size], sigma, logn - 1);
    ffldl_binary_normalize(
        &mut tree[n + left_size..n + left_size + left_size],
        sigma,
        logn - 1,
    );
}

fn prepare_signing_key_into<'a, const LOGN: u32>(
    secret: &SecretKey<LOGN>,
    data: &'a mut [Fpr],
    gram: &mut [Fpr],
    tmp: &mut [Fpr],
) -> ExpandedRefKey<'a> {
    let n = 1usize << LOGN;
    let data = &mut data[..expanded_ref_key_len(LOGN)];
    let gram = &mut gram[..4 * n];
    let tmp = &mut tmp[..4 * n];

    let (b00, rest) = data.split_at_mut(n);
    let (b01, rest) = rest.split_at_mut(n);
    let (b10, rest) = rest.split_at_mut(n);
    let (b11, tree) = rest.split_at_mut(n);

    smallints_to_fpr(b01, &secret.inner.f, LOGN);
    smallints_to_fpr(b00, &secret.inner.g, LOGN);
    smallints_to_fpr(b11, &secret.inner.big_f, LOGN);
    smallints_to_fpr(b10, &secret.inner.big_g, LOGN);

    fft(b00, LOGN);
    fft(b01, LOGN);
    fft(b10, LOGN);
    fft(b11, LOGN);
    poly_neg(b01, LOGN);
    poly_neg(b11, LOGN);

    let (g00, rest) = gram.split_at_mut(n);
    let (g01, rest) = rest.split_at_mut(n);
    let (g11, gxx) = rest.split_at_mut(n);

    g00.copy_from_slice(b00);
    poly_mulselfadj_fft(g00, LOGN);
    gxx.copy_from_slice(b01);
    poly_mulselfadj_fft(gxx, LOGN);
    poly_add(g00, gxx, LOGN);

    g01.copy_from_slice(b00);
    poly_muladj_fft(g01, b10, LOGN);
    gxx.copy_from_slice(b01);
    poly_muladj_fft(gxx, b11, LOGN);
    poly_add(g01, gxx, LOGN);

    g11.copy_from_slice(b10);
    poly_mulselfadj_fft(g11, LOGN);
    gxx.copy_from_slice(b11);
    poly_mulselfadj_fft(gxx, LOGN);
    poly_add(g11, gxx, LOGN);

    ffldl_fft(tree, g00, g01, g11, LOGN, tmp);
    let sigma = fpr_mul(
        fpr_sqrt(fpr_of(i64::from(QB))),
        fpr_div(fpr_of(155), fpr_of(100)),
    );
    ffldl_binary_normalize(tree, sigma, LOGN);

    ExpandedRefKey { logn: LOGN, data }
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

fn seed_prng_stream(rng: &mut (impl RngCore + CryptoRng)) -> Result<ShakeContext> {
    let mut seed = [0u8; 32];
    rng.try_fill_bytes(&mut seed)
        .map_err(|_| Error::Randomness)?;

    let mut sc = ShakeContext::shake256();
    sc.inject(&seed);
    #[cfg(feature = "zeroize")]
    seed.zeroize();
    sc.flip();
    Ok(sc)
}

#[cfg(test)]
fn sign_detached_with_rng_stream<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
    msg: &[u8],
    nonce: Nonce,
    comp: Compression,
    rng_stream: &mut ShakeContext,
) -> Result<DetachedSignature<LOGN>> {
    let mut ws = SignRefWorkspace::<LOGN>::new();
    sign_detached_with_rng_stream_in(secret, msg, nonce, comp, rng_stream, &mut ws)
}

fn sign_detached_with_rng_stream_in<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
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
        prepare_tmp,
        sign_tmp,
        seed: _,
        nonce: _,
    } = ws;

    hash_message_to_point_binary_into(nonce.as_bytes(), msg, LOGN, &mut hm[..n]);
    let prepared = prepare_signing_key_into(secret, prepared, sign_tmp, prepare_tmp);

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

pub(crate) fn sign_ref<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
    msg: &[u8],
    comp: Compression,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<DetachedSignature<LOGN>> {
    let mut ws = SignRefWorkspace::<LOGN>::new();
    sign_ref_in(secret, msg, comp, rng, &mut ws)
}

pub(crate) fn sign_ref_in<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
    msg: &[u8],
    comp: Compression,
    rng: &mut (impl RngCore + CryptoRng),
    ws: &mut SignRefWorkspace<LOGN>,
) -> Result<DetachedSignature<LOGN>> {
    let mut rng_stream = seed_prng_stream(rng)?;
    ws.nonce.clear();
    ws.nonce.resize(DEFAULT_NONCE_LEN, 0);
    rng_stream.extract(ws.nonce.as_mut_slice());
    sign_detached_with_rng_stream_in(
        secret,
        msg,
        Nonce(ws.nonce.clone().into_boxed_slice()),
        comp,
        &mut rng_stream,
        ws,
    )
}

pub(crate) fn sign_ref_with_external_nonce_in<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
    msg: &[u8],
    nonce: Nonce,
    comp: Compression,
    rng: &mut (impl RngCore + CryptoRng),
    ws: &mut SignRefWorkspace<LOGN>,
) -> Result<DetachedSignature<LOGN>> {
    let mut rng_stream = seed_prng_stream(rng)?;
    sign_detached_with_rng_stream_in(secret, msg, nonce, comp, &mut rng_stream, ws)
}

pub(crate) fn sign_ref_with_external_nonce<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
    msg: &[u8],
    nonce: Nonce,
    comp: Compression,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<DetachedSignature<LOGN>> {
    let mut ws = SignRefWorkspace::<LOGN>::new();
    sign_ref_with_external_nonce_in(secret, msg, nonce, comp, rng, &mut ws)
}

#[cfg(test)]
mod tests {
    use super::{seed_prng_stream, sign_detached_with_rng_stream};
    use crate::compression::Compression;
    use crate::error::Error;
    use crate::falcon::keygen::keygen_from_seed_material;
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
    fn sign_ref_generates_default_40_byte_nonce_and_roundtrips() {
        let keypair = keygen_from_seed_material::<9>(b"falcon2017-step17-keypair").expect("keygen");
        let mut rng = FixedRng::new(b"falcon2017-step17-sign-ref-seed");
        let sig = keypair
            .secret
            .sign_ref(b"step17-default-nonce", Compression::Static, &mut rng)
            .expect("signature");

        assert_eq!(sig.nonce().as_bytes().len(), 40);
        keypair
            .public
            .verify_detached(b"step17-default-nonce", &sig)
            .expect("signature must verify");
    }

    #[test]
    fn sign_ref_matches_reference_c_vector() {
        let sk = SecretKey::<9>::from_bytes(&STEP17_SK).expect("reference secret key");
        let mut rng = FixedRng::new(&STEP17_SIGN_SEED_DEFAULT);
        let sig = sk
            .sign_ref(&STEP17_MSG, Compression::Static, &mut rng)
            .expect("signature");

        assert_eq!(sig.nonce().as_bytes(), &STEP17_NONCE_DEFAULT);
        assert_eq!(sig.body_bytes(), &STEP17_SIG_DEFAULT);
    }

    #[test]
    fn sign_ref_with_external_nonce_roundtrips() {
        let keypair =
            keygen_from_seed_material::<10>(b"falcon2017-step17-keypair-1024").expect("keygen");
        let mut rng = FixedRng::new(b"falcon2017-step17-external-nonce-seed");
        let nonce = Nonce::from_bytes(b"external-step17-nonce");
        let sig = keypair
            .secret
            .sign_ref_with_external_nonce(
                b"step17-external-nonce",
                nonce,
                Compression::None,
                &mut rng,
            )
            .expect("signature");

        keypair
            .public
            .verify_detached(b"step17-external-nonce", &sig)
            .expect("signature must verify");
    }

    #[test]
    fn sign_ref_with_external_nonce_matches_reference_c_vector() {
        let sk = SecretKey::<9>::from_bytes(&STEP17_SK).expect("reference secret key");
        let mut rng = FixedRng::new(&STEP17_SIGN_SEED_EXTERNAL);
        let sig = sk
            .sign_ref_with_external_nonce(
                &STEP17_MSG,
                Nonce::from_bytes(&STEP17_NONCE_EXTERNAL),
                Compression::None,
                &mut rng,
            )
            .expect("signature");

        assert_eq!(sig.nonce().as_bytes(), &STEP17_NONCE_EXTERNAL);
        assert_eq!(sig.body_bytes(), &STEP17_SIG_EXTERNAL);
    }

    #[test]
    fn sign_ref_rejects_non_public_logn() {
        let sk = SecretKey::<4>::from_bytes(&[
            4, 0, 10, 0, 11, 255, 245, 0, 24, 255, 237, 255, 252, 255, 235, 0, 27, 255, 230, 0, 6,
            255, 239, 255, 255, 0, 39, 0, 5, 0, 18, 255, 244, 0, 24, 0, 25, 255, 252, 255, 241, 0,
            6, 0, 14, 0, 28, 255, 253, 0, 20, 0, 27, 0, 53, 0, 17, 0, 1, 255, 215, 255, 218, 0, 31,
            255, 242, 0, 51, 255, 225, 255, 195, 0, 13, 0, 26, 0, 55, 0, 43, 255, 232, 255, 248,
            255, 255, 0, 33, 0, 3, 0, 34, 255, 232, 0, 51, 0, 55, 0, 20, 255, 231, 0, 61, 0, 52,
            255, 255, 255, 214, 255, 255, 0, 49, 255, 242, 0, 36, 255, 229, 0, 10, 0, 5, 0, 3, 255,
            192,
        ])
        .expect("reference secret key");
        let mut rng = FixedRng::new(b"falcon2017-step17-invalid-logn");
        let err = sk
            .sign_ref(b"step17-invalid-logn", Compression::Static, &mut rng)
            .expect_err("must reject non-public logn");
        assert_eq!(err, Error::InvalidParameter);
    }

    #[test]
    fn internal_signer_accepts_arbitrary_external_nonce_length() {
        let keypair =
            keygen_from_seed_material::<9>(b"falcon2017-step17-internal-nonce").expect("keygen");
        let mut rng = FixedRng::new(b"falcon2017-step17-internal-seed");
        let mut rng_stream = seed_prng_stream(&mut rng).expect("rng stream");
        let sig = sign_detached_with_rng_stream(
            &keypair.secret,
            b"nonce-len-0",
            Nonce::from_bytes(&[]),
            Compression::Static,
            &mut rng_stream,
        )
        .expect("signature");

        keypair
            .public
            .verify_detached(b"nonce-len-0", &sig)
            .expect("signature must verify");
    }
}
