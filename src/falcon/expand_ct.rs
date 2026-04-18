//! Expanded-key generation for the strict constant-time backend.

use crate::error::{Error, Result};
use crate::falcon::workspace::ExpandCtWorkspace;
use crate::math::fft_soft::{
    fft, poly_add, poly_div_fft, poly_mul_fft, poly_muladj_fft, poly_mulselfadj_fft, poly_neg,
    poly_split_fft, poly_sub,
};
use crate::math::fpr::soft::{fpr_div, fpr_mul, fpr_of, fpr_sqrt, Fpr};
use crate::math::ntt::QB;
use crate::params::is_public_logn;
use crate::types::{ExpandedSecretKeyCt, ExpandedSecretKeyCtInner, SecretKey};
const fn ffldl_treesize(logn: u32) -> usize {
    ((logn + 1) as usize) << logn
}

fn alloc_soft_slice(len: usize) -> Box<[Fpr]> {
    vec![Fpr::from_bits(0); len].into_boxed_slice()
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
    poly_div_fft(tmp, g00, logn);
    l10.copy_from_slice(tmp);
    for value in &mut l10[(n >> 1)..] {
        *value = crate::math::fpr::soft::fpr_neg(*value);
    }
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

fn expand_ct_inner_with_scratch<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
    gram: &mut [Fpr],
    tmp: &mut [Fpr],
    normalize: bool,
) -> ExpandedSecretKeyCtInner<LOGN> {
    let n = 1usize << LOGN;
    let tree_len = ffldl_treesize(LOGN);
    let gram = &mut gram[..4 * n];
    let tmp = &mut tmp[..4 * n];

    let mut expanded = ExpandedSecretKeyCtInner {
        b00: alloc_soft_slice(n),
        b01: alloc_soft_slice(n),
        b10: alloc_soft_slice(n),
        b11: alloc_soft_slice(n),
        tree: alloc_soft_slice(tree_len),
    };

    smallints_to_fpr(&mut expanded.b01, &secret.inner.f, LOGN);
    smallints_to_fpr(&mut expanded.b00, &secret.inner.g, LOGN);
    smallints_to_fpr(&mut expanded.b11, &secret.inner.big_f, LOGN);
    smallints_to_fpr(&mut expanded.b10, &secret.inner.big_g, LOGN);

    fft(&mut expanded.b00, LOGN);
    fft(&mut expanded.b01, LOGN);
    fft(&mut expanded.b10, LOGN);
    fft(&mut expanded.b11, LOGN);
    poly_neg(&mut expanded.b01, LOGN);
    poly_neg(&mut expanded.b11, LOGN);

    let (g00, rest) = gram.split_at_mut(n);
    let (g01, rest) = rest.split_at_mut(n);
    let (g11, gxx) = rest.split_at_mut(n);

    g00.copy_from_slice(&expanded.b00);
    poly_mulselfadj_fft(g00, LOGN);
    gxx.copy_from_slice(&expanded.b01);
    poly_mulselfadj_fft(gxx, LOGN);
    poly_add(g00, gxx, LOGN);

    g01.copy_from_slice(&expanded.b00);
    poly_muladj_fft(g01, &expanded.b10, LOGN);
    gxx.copy_from_slice(&expanded.b01);
    poly_muladj_fft(gxx, &expanded.b11, LOGN);
    poly_add(g01, gxx, LOGN);

    g11.copy_from_slice(&expanded.b10);
    poly_mulselfadj_fft(g11, LOGN);
    gxx.copy_from_slice(&expanded.b11);
    poly_mulselfadj_fft(gxx, LOGN);
    poly_add(g11, gxx, LOGN);

    ffldl_fft(&mut expanded.tree, g00, g01, g11, LOGN, tmp);
    if normalize {
        let sigma = fpr_mul(
            fpr_sqrt(fpr_of(i64::from(QB))),
            fpr_div(fpr_of(155), fpr_of(100)),
        );
        ffldl_binary_normalize(&mut expanded.tree, sigma, LOGN);
    }

    #[cfg(feature = "zeroize")]
    {
        for value in gram.iter_mut() {
            *value = Fpr::from_bits(0);
        }
        for value in tmp.iter_mut() {
            *value = Fpr::from_bits(0);
        }
    }

    expanded
}

#[cfg(test)]
fn expand_ct_inner<const LOGN: u32>(secret: &SecretKey<LOGN>) -> ExpandedSecretKeyCtInner<LOGN> {
    let n = 1usize << LOGN;
    let mut gram = vec![Fpr::from_bits(0); 4 * n];
    let mut tmp = vec![Fpr::from_bits(0); 4 * n];
    expand_ct_inner_with_scratch(secret, &mut gram, &mut tmp, true)
}

pub(crate) fn expand_ct_strict<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
) -> Result<ExpandedSecretKeyCt<LOGN>> {
    let mut ws = ExpandCtWorkspace::<LOGN>::new();
    expand_ct_strict_in(secret, &mut ws)
}

pub(crate) fn expand_ct_strict_in<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
    ws: &mut ExpandCtWorkspace<LOGN>,
) -> Result<ExpandedSecretKeyCt<LOGN>> {
    if !is_public_logn(LOGN) {
        return Err(Error::InvalidParameter);
    }

    Ok(ExpandedSecretKeyCt {
        inner: expand_ct_inner_with_scratch(secret, &mut ws.gram, &mut ws.tmp, true),
    })
}

#[cfg(test)]
pub(crate) fn debug_expand_ct_inner<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
) -> ExpandedSecretKeyCtInner<LOGN> {
    expand_ct_inner(secret)
}

#[cfg(test)]
pub(crate) fn debug_expand_ct_inner_unnormalized<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
) -> ExpandedSecretKeyCtInner<LOGN> {
    let n = 1usize << LOGN;
    let mut gram = vec![Fpr::from_bits(0); 4 * n];
    let mut tmp = vec![Fpr::from_bits(0); 4 * n];
    expand_ct_inner_with_scratch(secret, &mut gram, &mut tmp, false)
}

#[cfg(test)]
mod tests {
    use super::{debug_expand_ct_inner, debug_expand_ct_inner_unnormalized};
    use crate::math::fft as ref_fft;
    use crate::math::fft_soft as soft_fft;
    use crate::math::fpr::ref_f64::{fpr_of as ref_fpr_of, Fpr as RefFpr};
    use crate::math::fpr::soft::{fpr_of as soft_fpr_of, Fpr};
    use crate::falcon::sign_ref::{prepare_signing_key_bits_ref, prepare_signing_key_bits_ref_unnormalized};
    use crate::types::SecretKey;

    const REF_SECRET_KEY_NONE: [u8; 129] = [
        4, 0, 10, 0, 11, 255, 245, 0, 24, 255, 237, 255, 252, 255, 235, 0, 27, 255, 230, 0, 6, 255,
        239, 255, 255, 0, 39, 0, 5, 0, 18, 255, 244, 0, 24, 0, 25, 255, 252, 255, 241, 0, 6, 0, 14,
        0, 28, 255, 253, 0, 20, 0, 27, 0, 53, 0, 17, 0, 1, 255, 215, 255, 218, 0, 31, 255, 242, 0,
        51, 255, 225, 255, 195, 0, 13, 0, 26, 0, 55, 0, 43, 255, 232, 255, 248, 255, 255, 0, 33, 0,
        3, 0, 34, 255, 232, 0, 51, 0, 55, 0, 20, 255, 231, 0, 61, 0, 52, 255, 255, 255, 214, 255,
        255, 0, 49, 255, 242, 0, 36, 255, 229, 0, 10, 0, 5, 0, 3, 255, 192,
    ];

    fn flatten_bits<const LOGN: u32>(
        expanded: &crate::types::ExpandedSecretKeyCtInner<LOGN>,
    ) -> Vec<u64> {
        let n = 1usize << LOGN;
        let tree_len = super::ffldl_treesize(LOGN);
        let mut out = Vec::with_capacity(4 * n + tree_len);
        out.extend(expanded.b00.iter().map(|x| x.bits()));
        out.extend(expanded.b01.iter().map(|x| x.bits()));
        out.extend(expanded.b10.iter().map(|x| x.bits()));
        out.extend(expanded.b11.iter().map(|x| x.bits()));
        out.extend(expanded.tree.iter().map(|x| x.bits()));
        out
    }

    fn smallints_to_ref(dst: &mut [RefFpr], src: &[i8]) {
        for (d, &s) in dst.iter_mut().zip(src.iter()) {
            *d = ref_fpr_of(i64::from(s));
        }
    }

    fn smallints_to_soft(dst: &mut [Fpr], src: &[i8]) {
        for (d, &s) in dst.iter_mut().zip(src.iter()) {
            *d = soft_fpr_of(i64::from(s));
        }
    }

    fn assert_ref_soft_bits_eq(soft: &[Fpr], reference: &[RefFpr], label: &str) {
        assert_eq!(soft.len(), reference.len(), "{label}: len mismatch");
        for (idx, (soft, reference)) in soft.iter().zip(reference.iter()).enumerate() {
            assert_eq!(
                soft.bits(),
                reference.v.to_bits(),
                "{label}: bit mismatch at index {idx}",
            );
        }
    }

    #[test]
    fn expanded_ct_root_ldl_matches_reference_step_by_step() {
        let secret = SecretKey::<4>::from_bytes(&REF_SECRET_KEY_NONE).expect("reference bytes");
        let logn = 4;
        let n = 1usize << logn;

        let mut ref_b00 = vec![RefFpr::new(0.0); n];
        let mut ref_b01 = vec![RefFpr::new(0.0); n];
        let mut ref_b10 = vec![RefFpr::new(0.0); n];
        let mut ref_b11 = vec![RefFpr::new(0.0); n];
        let mut soft_b00 = vec![Fpr::from_bits(0); n];
        let mut soft_b01 = vec![Fpr::from_bits(0); n];
        let mut soft_b10 = vec![Fpr::from_bits(0); n];
        let mut soft_b11 = vec![Fpr::from_bits(0); n];

        smallints_to_ref(&mut ref_b01, &secret.inner.f);
        smallints_to_ref(&mut ref_b00, &secret.inner.g);
        smallints_to_ref(&mut ref_b11, &secret.inner.big_f);
        smallints_to_ref(&mut ref_b10, &secret.inner.big_g);
        smallints_to_soft(&mut soft_b01, &secret.inner.f);
        smallints_to_soft(&mut soft_b00, &secret.inner.g);
        smallints_to_soft(&mut soft_b11, &secret.inner.big_f);
        smallints_to_soft(&mut soft_b10, &secret.inner.big_g);

        ref_fft::fft(&mut ref_b00, logn);
        ref_fft::fft(&mut ref_b01, logn);
        ref_fft::fft(&mut ref_b10, logn);
        ref_fft::fft(&mut ref_b11, logn);
        soft_fft::fft(&mut soft_b00, logn);
        soft_fft::fft(&mut soft_b01, logn);
        soft_fft::fft(&mut soft_b10, logn);
        soft_fft::fft(&mut soft_b11, logn);
        ref_fft::poly_neg(&mut ref_b01, logn);
        ref_fft::poly_neg(&mut ref_b11, logn);
        soft_fft::poly_neg(&mut soft_b01, logn);
        soft_fft::poly_neg(&mut soft_b11, logn);

        assert_ref_soft_bits_eq(&soft_b00, &ref_b00, "b00");
        assert_ref_soft_bits_eq(&soft_b01, &ref_b01, "b01");
        assert_ref_soft_bits_eq(&soft_b10, &ref_b10, "b10");
        assert_ref_soft_bits_eq(&soft_b11, &ref_b11, "b11");

        let mut ref_g00 = ref_b00.clone();
        ref_fft::poly_mulselfadj_fft(&mut ref_g00, logn);
        let mut tmp_ref = ref_b01.clone();
        ref_fft::poly_mulselfadj_fft(&mut tmp_ref, logn);
        ref_fft::poly_add(&mut ref_g00, &tmp_ref, logn);

        let mut soft_g00 = soft_b00.clone();
        soft_fft::poly_mulselfadj_fft(&mut soft_g00, logn);
        let mut tmp_soft = soft_b01.clone();
        soft_fft::poly_mulselfadj_fft(&mut tmp_soft, logn);
        soft_fft::poly_add(&mut soft_g00, &tmp_soft, logn);
        assert_ref_soft_bits_eq(&soft_g00, &ref_g00, "g00");

        let mut ref_g01 = ref_b00.clone();
        ref_fft::poly_muladj_fft(&mut ref_g01, &ref_b10, logn);
        tmp_ref.copy_from_slice(&ref_b01);
        ref_fft::poly_muladj_fft(&mut tmp_ref, &ref_b11, logn);
        ref_fft::poly_add(&mut ref_g01, &tmp_ref, logn);

        let mut soft_g01 = soft_b00.clone();
        soft_fft::poly_muladj_fft(&mut soft_g01, &soft_b10, logn);
        tmp_soft.copy_from_slice(&soft_b01);
        soft_fft::poly_muladj_fft(&mut tmp_soft, &soft_b11, logn);
        soft_fft::poly_add(&mut soft_g01, &tmp_soft, logn);
        assert_ref_soft_bits_eq(&soft_g01, &ref_g01, "g01");

        let mut ref_g11 = ref_b10.clone();
        ref_fft::poly_mulselfadj_fft(&mut ref_g11, logn);
        tmp_ref.copy_from_slice(&ref_b11);
        ref_fft::poly_mulselfadj_fft(&mut tmp_ref, logn);
        ref_fft::poly_add(&mut ref_g11, &tmp_ref, logn);

        let mut soft_g11 = soft_b10.clone();
        soft_fft::poly_mulselfadj_fft(&mut soft_g11, logn);
        tmp_soft.copy_from_slice(&soft_b11);
        soft_fft::poly_mulselfadj_fft(&mut tmp_soft, logn);
        soft_fft::poly_add(&mut soft_g11, &tmp_soft, logn);
        assert_ref_soft_bits_eq(&soft_g11, &ref_g11, "g11");

        let mut ref_div = ref_g01.clone();
        ref_fft::poly_div_fft(&mut ref_div, &ref_g00, logn);
        let mut soft_div = soft_g01.clone();
        soft_fft::poly_div_fft(&mut soft_div, &soft_g00, logn);
        if soft_div[0].bits() != ref_div[0].v.to_bits() {
            let ref_m = crate::math::fpr::ref_f64::fpr_add(
                crate::math::fpr::ref_f64::fpr_sqr(ref_g00[0]),
                crate::math::fpr::ref_f64::fpr_sqr(ref_g00[n >> 1]),
            );
            let soft_m = crate::math::fpr::soft::fpr_add(
                crate::math::fpr::soft::fpr_sqr(soft_g00[0]),
                crate::math::fpr::soft::fpr_sqr(soft_g00[n >> 1]),
            );
            let ref_inv = crate::math::fpr::ref_f64::fpr_div(ref_g00[0], ref_m);
            let soft_inv = crate::math::fpr::soft::fpr_div(soft_g00[0], soft_m);
            let ref_inv_im = crate::math::fpr::ref_f64::fpr_div(
                crate::math::fpr::ref_f64::fpr_neg(ref_g00[n >> 1]),
                ref_m,
            );
            let soft_inv_im = crate::math::fpr::soft::fpr_div(
                crate::math::fpr::soft::fpr_neg(soft_g00[n >> 1]),
                soft_m,
            );
            let ref_mul_re = crate::math::fpr::ref_f64::fpr_mul(ref_g01[0], ref_inv);
            let soft_mul_re = crate::math::fpr::soft::fpr_mul(soft_g01[0], soft_inv);
            let ref_mul_im = crate::math::fpr::ref_f64::fpr_mul(ref_g01[n >> 1], ref_inv);
            let soft_mul_im = crate::math::fpr::soft::fpr_mul(soft_g01[n >> 1], soft_inv);
            let soft_cross = crate::math::fpr::soft::fpr_mul(soft_g01[n >> 1], soft_inv_im);
            let ref_cross = crate::math::fpr::ref_f64::fpr_mul(ref_g01[n >> 1], ref_inv_im);
            panic!(
                "g01/g00 idx0: a=({:#018x},{:#018x}) b=({:#018x},{:#018x}) m=({:#018x},{:#018x}) inv=({:#018x},{:#018x}) inv_im=({:#018x},{:#018x}) mul_re=({:#018x},{:#018x}) mul_im=({:#018x},{:#018x}) cross=({:#018x},{:#018x}) soft=({:#018x},{:#018x}) ref=({:#018x},{:#018x})",
                soft_g01[0].bits(),
                soft_g01[n >> 1].bits(),
                soft_g00[0].bits(),
                soft_g00[n >> 1].bits(),
                soft_m.bits(),
                ref_m.v.to_bits(),
                soft_inv.bits(),
                ref_inv.v.to_bits(),
                soft_inv_im.bits(),
                ref_inv_im.v.to_bits(),
                soft_mul_re.bits(),
                ref_mul_re.v.to_bits(),
                soft_mul_im.bits(),
                ref_mul_im.v.to_bits(),
                soft_cross.bits(),
                ref_cross.v.to_bits(),
                soft_div[0].bits(),
                soft_div[n >> 1].bits(),
                ref_div[0].v.to_bits(),
                ref_div[n >> 1].v.to_bits(),
            );
        }
        assert_ref_soft_bits_eq(&soft_div, &ref_div, "g01/g00");

        ref_fft::poly_adj_fft(&mut ref_div, logn);
        soft_fft::poly_adj_fft(&mut soft_div, logn);
        assert_ref_soft_bits_eq(&soft_div, &ref_div, "adj(g01/g00)");

        let mut ref_prod = ref_g00.clone();
        ref_fft::poly_mul_fft(&mut ref_prod, &ref_div, logn);
        let mut soft_prod = soft_g00.clone();
        soft_fft::poly_mul_fft(&mut soft_prod, &soft_div, logn);
        assert_ref_soft_bits_eq(&soft_prod, &ref_prod, "g00*l10");

        ref_fft::poly_mul_fft(&mut ref_prod, &ref_div, logn);
        soft_fft::poly_mul_fft(&mut soft_prod, &soft_div, logn);
        assert_ref_soft_bits_eq(&soft_prod, &ref_prod, "g00*l10*l10");

        let mut ref_d11 = ref_g11.clone();
        ref_fft::poly_sub(&mut ref_d11, &ref_prod, logn);
        let mut soft_d11 = soft_g11.clone();
        soft_fft::poly_sub(&mut soft_d11, &soft_prod, logn);
        assert_ref_soft_bits_eq(&soft_d11, &ref_d11, "d11");
    }

    #[test]
    fn expanded_ct_matches_reference_preparation_bits() {
        let secret = SecretKey::<4>::from_bytes(&REF_SECRET_KEY_NONE).expect("reference bytes");
        let expanded = debug_expand_ct_inner(&secret);

        assert_eq!(
            flatten_bits(&expanded),
            prepare_signing_key_bits_ref(&secret)
        );
    }

    #[test]
    fn expanded_ct_matches_reference_preparation_bits_before_normalization() {
        let secret = SecretKey::<4>::from_bytes(&REF_SECRET_KEY_NONE).expect("reference bytes");
        let expanded = debug_expand_ct_inner_unnormalized(&secret);

        assert_eq!(
            flatten_bits(&expanded),
            prepare_signing_key_bits_ref_unnormalized(&secret)
        );
    }
}
