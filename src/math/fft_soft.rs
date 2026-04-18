//! FFT primitives for the strict constant-time backend.

use crate::math::fpr::soft::{
    fpr_add, fpr_div, fpr_half, fpr_mul, fpr_neg, fpr_of, fpr_sqr, fpr_sub, Fpr,
};

include!("fft_gm_bits_table.rs");

pub(crate) fn fft(f: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    assert_eq!(f.len(), n);

    if logn <= 1 {
        return;
    }

    let hn = n >> 1;
    let mut t = hn;
    let mut m = 2usize;
    for _ in 1..logn {
        let ht = t >> 1;
        let hm = m >> 1;
        let mut j1 = 0usize;
        for i1 in 0..hm {
            let (s_re, s_im) = gm_entry(m + i1);
            let j2 = j1 + ht;
            for j in j1..j2 {
                let x_re = f[j];
                let x_im = f[j + hn];
                let y_re = f[j + ht];
                let y_im = f[j + ht + hn];
                let (y_re, y_im) = complex_mul(y_re, y_im, s_re, s_im);
                let (sum_re, sum_im) = complex_add(x_re, x_im, y_re, y_im);
                let (sub_re, sub_im) = complex_sub(x_re, x_im, y_re, y_im);
                f[j] = sum_re;
                f[j + hn] = sum_im;
                f[j + ht] = sub_re;
                f[j + ht + hn] = sub_im;
            }
            j1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

pub(crate) fn ifft(f: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    assert_eq!(f.len(), n);

    let hn = n >> 1;
    let mut t = 1usize;
    let mut m = n;
    for _ in (2..=logn).rev() {
        let hm = m >> 1;
        let dt = t << 1;
        let mut i1 = 0usize;
        let mut j1 = 0usize;
        while j1 < hn {
            let (s_re, s_im) = gm_entry(hm + i1);
            let s_im = fpr_neg(s_im);
            let j2 = j1 + t;
            for j in j1..j2 {
                let x_re = f[j];
                let x_im = f[j + hn];
                let y_re = f[j + t];
                let y_im = f[j + t + hn];
                let (sum_re, sum_im) = complex_add(x_re, x_im, y_re, y_im);
                let (diff_re, diff_im) = complex_sub(x_re, x_im, y_re, y_im);
                let (prod_re, prod_im) = complex_mul(diff_re, diff_im, s_re, s_im);
                f[j] = sum_re;
                f[j + hn] = sum_im;
                f[j + t] = prod_re;
                f[j + t + hn] = prod_im;
            }
            i1 += 1;
            j1 += dt;
        }
        t = dt;
        m = hm;
    }

    if logn > 0 {
        let ni = crate::math::fpr::soft::fpr_scaled(2, -(logn as i32));
        for value in f.iter_mut() {
            *value = fpr_mul(*value, ni);
        }
    }
}

pub(crate) fn poly_add(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x = fpr_add(*x, *y);
    }
}

pub(crate) fn poly_addconst(a: &mut [Fpr], x: Fpr, _logn: u32) {
    a[0] = fpr_add(a[0], x);
}

pub(crate) fn poly_addconst_fft(a: &mut [Fpr], x: Fpr, logn: u32) {
    if logn == 0 {
        a[0] = fpr_add(a[0], x);
        return;
    }

    let hn = 1usize << (logn - 1);
    for value in &mut a[..hn] {
        *value = fpr_add(*value, x);
    }
}

pub(crate) fn poly_sub(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x = fpr_sub(*x, *y);
    }
}

pub(crate) fn poly_neg(a: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    assert_eq!(a.len(), n);
    for value in a.iter_mut() {
        *value = fpr_neg(*value);
    }
}

pub(crate) fn poly_adj_fft(a: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    assert_eq!(a.len(), n);
    for value in &mut a[(n >> 1)..] {
        *value = fpr_neg(*value);
    }
}

pub(crate) fn poly_mul_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);

    for u in 0..hn {
        let (re, im) = complex_mul(a[u], a[u + hn], b[u], b[u + hn]);
        a[u] = re;
        a[u + hn] = im;
    }
}

pub(crate) fn poly_muladj_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);

    for u in 0..hn {
        let (re, im) = complex_mul(a[u], a[u + hn], b[u], fpr_neg(b[u + hn]));
        a[u] = re;
        a[u + hn] = im;
    }
}

pub(crate) fn poly_mulselfadj_fft(a: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    assert_eq!(a.len(), n);

    for u in 0..hn {
        let a_re = a[u];
        let a_im = a[u + hn];
        a[u] = fpr_add(fpr_sqr(a_re), fpr_sqr(a_im));
        a[u + hn] = fpr_of(0);
    }
}

pub(crate) fn poly_mulconst(a: &mut [Fpr], x: Fpr, logn: u32) {
    let n = 1usize << logn;
    assert_eq!(a.len(), n);
    for value in a.iter_mut() {
        *value = fpr_mul(*value, x);
    }
}

pub(crate) fn poly_div_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);

    for u in 0..hn {
        let (re, im) = complex_div(a[u], a[u + hn], b[u], b[u + hn]);
        a[u] = re;
        a[u + hn] = im;
    }
}

pub(crate) fn poly_split_fft(f0: &mut [Fpr], f1: &mut [Fpr], f: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let qn = hn >> 1;
    assert_eq!(f.len(), n);
    assert_eq!(f0.len(), hn);
    assert_eq!(f1.len(), hn);

    f0[0] = f[0];
    f1[0] = f[hn];

    for u in 0..qn {
        let a_re = f[u << 1];
        let a_im = f[(u << 1) + hn];
        let b_re = f[(u << 1) + 1];
        let b_im = f[(u << 1) + 1 + hn];

        let (t_re, t_im) = complex_add(a_re, a_im, b_re, b_im);
        f0[u] = fpr_half(t_re);
        f0[u + qn] = fpr_half(t_im);

        let (t_re, t_im) = complex_sub(a_re, a_im, b_re, b_im);
        let (g_re, g_im) = gm_entry(u + hn);
        let (t_re, t_im) = complex_mul(t_re, t_im, g_re, fpr_neg(g_im));
        f1[u] = fpr_half(t_re);
        f1[u + qn] = fpr_half(t_im);
    }
}

pub(crate) fn poly_merge_fft(f: &mut [Fpr], f0: &[Fpr], f1: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    let qn = hn >> 1;
    assert_eq!(f.len(), n);
    assert_eq!(f0.len(), hn);
    assert_eq!(f1.len(), hn);

    f[0] = f0[0];
    f[hn] = f1[0];

    for u in 0..qn {
        let a_re = f0[u];
        let a_im = f0[u + qn];
        let (g_re, g_im) = gm_entry(u + hn);
        let (b_re, b_im) = complex_mul(f1[u], f1[u + qn], g_re, g_im);
        let (t0_re, t0_im) = complex_add(a_re, a_im, b_re, b_im);
        let (t1_re, t1_im) = complex_sub(a_re, a_im, b_re, b_im);
        f[u << 1] = t0_re;
        f[(u << 1) + hn] = t0_im;
        f[(u << 1) + 1] = t1_re;
        f[(u << 1) + 1 + hn] = t1_im;
    }
}

fn complex_add(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    (fpr_add(a_re, b_re), fpr_add(a_im, b_im))
}

fn complex_sub(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    (fpr_sub(a_re, b_re), fpr_sub(a_im, b_im))
}

fn complex_mul(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    (
        fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im)),
        fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re)),
    )
}

fn complex_div(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    let m = fpr_add(fpr_sqr(b_re), fpr_sqr(b_im));
    complex_mul(a_re, a_im, fpr_div(b_re, m), fpr_div(fpr_neg(b_im), m))
}

fn gm_entry(index: usize) -> (Fpr, Fpr) {
    let (re, im) = FPR_GM_TAB_BITS[index];
    (Fpr::from_bits(re), Fpr::from_bits(im))
}

#[cfg(test)]
mod tests {
    use super::{
        fft as soft_fft, ifft as soft_ifft, poly_div_fft as soft_poly_div_fft,
        poly_merge_fft as soft_poly_merge_fft, poly_muladj_fft as soft_poly_muladj_fft,
        poly_mulselfadj_fft as soft_poly_mulselfadj_fft, poly_split_fft as soft_poly_split_fft,
        Fpr,
    };
    use crate::math::fft::{
        fft as ref_fft, ifft as ref_ifft, poly_div_fft as ref_poly_div_fft,
        poly_merge_fft as ref_poly_merge_fft, poly_muladj_fft as ref_poly_muladj_fft,
        poly_mulselfadj_fft as ref_poly_mulselfadj_fft, poly_split_fft as ref_poly_split_fft,
    };
    use crate::math::fpr::ref_f64::Fpr as RefFpr;

    fn deterministic_real_poly_ref(logn: u32, seed: i32) -> Vec<RefFpr> {
        let n = 1usize << logn;
        (0..n)
            .map(|i| {
                let x = ((i as i32 * 17 + seed * 23 + 5) % 29) - 14;
                RefFpr::new((x as f64) / 8.0)
            })
            .collect()
    }

    fn to_soft(src: &[RefFpr]) -> Vec<Fpr> {
        src.iter().map(|x| Fpr::from_bits(x.v.to_bits())).collect()
    }

    fn assert_bits_eq(soft: &[Fpr], reference: &[RefFpr]) {
        assert_eq!(soft.len(), reference.len());
        for (idx, (soft, reference)) in soft.iter().zip(reference.iter()).enumerate() {
            assert_eq!(
                soft.bits(),
                reference.v.to_bits(),
                "bit mismatch at index {idx}",
            );
        }
    }

    #[test]
    fn soft_fft_and_ifft_match_reference_bits() {
        let logn = 4;
        let mut reference = deterministic_real_poly_ref(logn, 7);
        let mut soft = to_soft(&reference);

        ref_fft(&mut reference, logn);
        soft_fft(&mut soft, logn);
        assert_bits_eq(&soft, &reference);

        ref_ifft(&mut reference, logn);
        soft_ifft(&mut soft, logn);
        assert_bits_eq(&soft, &reference);
    }

    #[test]
    fn soft_poly_muladj_matches_reference_bits() {
        let logn = 4;
        let mut ref_a = deterministic_real_poly_ref(logn, 3);
        let mut ref_b = deterministic_real_poly_ref(logn, 11);
        ref_fft(&mut ref_a, logn);
        ref_fft(&mut ref_b, logn);

        let mut soft_a = to_soft(&ref_a);
        let soft_b = to_soft(&ref_b);

        ref_poly_muladj_fft(&mut ref_a, &ref_b, logn);
        soft_poly_muladj_fft(&mut soft_a, &soft_b, logn);
        assert_bits_eq(&soft_a, &ref_a);
    }

    #[test]
    fn soft_poly_mulselfadj_matches_reference_bits() {
        let logn = 4;
        let mut reference = deterministic_real_poly_ref(logn, 5);
        ref_fft(&mut reference, logn);
        let mut soft = to_soft(&reference);

        ref_poly_mulselfadj_fft(&mut reference, logn);
        soft_poly_mulselfadj_fft(&mut soft, logn);
        assert_bits_eq(&soft, &reference);
    }

    #[test]
    fn soft_poly_div_matches_reference_bits() {
        let logn = 4;
        let mut ref_a = deterministic_real_poly_ref(logn, 2);
        let mut ref_b = deterministic_real_poly_ref(logn, 9);
        ref_fft(&mut ref_a, logn);
        ref_fft(&mut ref_b, logn);
        for value in &mut ref_b {
            value.v += 3.0;
        }

        let mut soft_a = to_soft(&ref_a);
        let soft_b = to_soft(&ref_b);

        ref_poly_div_fft(&mut ref_a, &ref_b, logn);
        soft_poly_div_fft(&mut soft_a, &soft_b, logn);
        assert_bits_eq(&soft_a, &ref_a);
    }

    #[test]
    fn soft_split_merge_matches_reference_bits() {
        let logn = 4;
        let mut reference = deterministic_real_poly_ref(logn, 13);
        ref_fft(&mut reference, logn);
        let soft = to_soft(&reference);

        let hn = 1usize << (logn - 1);
        let mut ref0 = vec![RefFpr::new(0.0); hn];
        let mut ref1 = vec![RefFpr::new(0.0); hn];
        let mut soft0 = vec![Fpr::from_bits(0); hn];
        let mut soft1 = vec![Fpr::from_bits(0); hn];

        ref_poly_split_fft(&mut ref0, &mut ref1, &reference, logn);
        soft_poly_split_fft(&mut soft0, &mut soft1, &soft, logn);
        assert_bits_eq(&soft0, &ref0);
        assert_bits_eq(&soft1, &ref1);

        let mut ref_merged = vec![RefFpr::new(0.0); 1usize << logn];
        let mut soft_merged = vec![Fpr::from_bits(0); 1usize << logn];
        ref_poly_merge_fft(&mut ref_merged, &ref0, &ref1, logn);
        soft_poly_merge_fft(&mut soft_merged, &soft0, &soft1, logn);
        assert_bits_eq(&soft_merged, &ref_merged);
    }
}
