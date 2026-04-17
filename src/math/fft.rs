//! FFT primitives ported from the binary portion of `falcon-fft.c`.

use crate::math::fpr::ref_f64::{
    fpr_add, fpr_div, fpr_double, fpr_half, fpr_inv, fpr_mul, fpr_neg, fpr_of, fpr_scaled, fpr_sqr,
    fpr_sub, Fpr,
};

include!("fft_gm_table.rs");

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
            let (s_re, s_im) = gm_entry(m + i1, logn);
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
            let (s_re, s_im) = gm_entry(hm + i1, logn);
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
        let ni = fpr_scaled(2, -(logn as i32));
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

pub(crate) fn poly_adj(a: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    assert_eq!(a.len(), n);

    for u in 1..hn {
        let t = fpr_neg(a[u]);
        a[u] = fpr_neg(a[n - u]);
        a[n - u] = t;
    }
    a[hn] = fpr_neg(a[hn]);
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

pub(crate) fn poly_sqr_fft(a: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    assert_eq!(a.len(), n);

    for u in 0..hn {
        let (re, im) = complex_sqr(a[u], a[u + hn]);
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

pub(crate) fn poly_inv_fft(a: &mut [Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    assert_eq!(a.len(), n);

    for u in 0..hn {
        let (re, im) = complex_inv(a[u], a[u + hn]);
        a[u] = re;
        a[u + hn] = im;
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

pub(crate) fn poly_divadj_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);

    for u in 0..hn {
        let (re, im) = complex_div(a[u], a[u + hn], b[u], fpr_neg(b[u + hn]));
        a[u] = re;
        a[u + hn] = im;
    }
}

pub(crate) fn poly_invnorm2_fft(d: &mut [Fpr], a: &[Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    assert!(d.len() >= hn);
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);

    for u in 0..hn {
        d[u] = fpr_inv(fpr_add(
            fpr_add(fpr_sqr(a[u]), fpr_sqr(a[u + hn])),
            fpr_add(fpr_sqr(b[u]), fpr_sqr(b[u + hn])),
        ));
    }
}

pub(crate) fn poly_add_muladj_fft(
    d: &mut [Fpr],
    big_f: &[Fpr],
    big_g: &[Fpr],
    f: &[Fpr],
    g: &[Fpr],
    logn: u32,
) {
    let n = 1usize << logn;
    let hn = n >> 1;
    assert_eq!(d.len(), n);
    assert_eq!(big_f.len(), n);
    assert_eq!(big_g.len(), n);
    assert_eq!(f.len(), n);
    assert_eq!(g.len(), n);

    for u in 0..hn {
        let (a_re, a_im) = complex_mul(big_f[u], big_f[u + hn], f[u], fpr_neg(f[u + hn]));
        let (b_re, b_im) = complex_mul(big_g[u], big_g[u + hn], g[u], fpr_neg(g[u + hn]));
        d[u] = fpr_add(a_re, b_re);
        d[u + hn] = fpr_add(a_im, b_im);
    }
}

pub(crate) fn poly_mul_autoadj_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), hn);

    for u in 0..hn {
        a[u] = fpr_mul(a[u], b[u]);
        a[u + hn] = fpr_mul(a[u + hn], b[u]);
    }
}

pub(crate) fn poly_div_autoadj_fft(a: &mut [Fpr], b: &[Fpr], logn: u32) {
    let n = 1usize << logn;
    let hn = n >> 1;
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), hn);

    for u in 0..hn {
        a[u] = fpr_div(a[u], b[u]);
        a[u + hn] = fpr_div(a[u + hn], b[u]);
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
        let (g_re, g_im) = gm_entry(u + hn, logn);
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
        let (g_re, g_im) = gm_entry(u + hn, logn);
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

fn complex_sqr(a_re: Fpr, a_im: Fpr) -> (Fpr, Fpr) {
    (
        fpr_sub(fpr_sqr(a_re), fpr_sqr(a_im)),
        fpr_double(fpr_mul(a_re, a_im)),
    )
}

fn complex_inv(a_re: Fpr, a_im: Fpr) -> (Fpr, Fpr) {
    let m = fpr_add(fpr_sqr(a_re), fpr_sqr(a_im));
    (fpr_div(a_re, m), fpr_div(fpr_neg(a_im), m))
}

fn complex_div(a_re: Fpr, a_im: Fpr, b_re: Fpr, b_im: Fpr) -> (Fpr, Fpr) {
    let m = fpr_add(fpr_sqr(b_re), fpr_sqr(b_im));
    complex_mul(a_re, a_im, fpr_div(b_re, m), fpr_div(fpr_neg(b_im), m))
}

fn gm_entry(index: usize, _logn: u32) -> (Fpr, Fpr) {
    let (re, im) = FPR_GM_TAB[index];
    (Fpr::new(re), Fpr::new(im))
}

#[cfg(test)]
mod tests {
    use super::{
        fft, ifft, poly_add, poly_add_muladj_fft, poly_adj_fft, poly_div_fft, poly_divadj_fft,
        poly_inv_fft, poly_invnorm2_fft, poly_merge_fft, poly_mul_fft, poly_muladj_fft,
        poly_mulconst, poly_mulselfadj_fft, poly_neg, poly_split_fft, poly_sub, Fpr,
    };
    use crate::math::fpr::ref_f64::{fpr, fpr_add, fpr_inv, fpr_sqr};

    fn deterministic_real_poly(logn: u32, seed: i32) -> Vec<Fpr> {
        let n = 1usize << logn;
        (0..n)
            .map(|i| {
                let x = ((i as i32 * 17 + seed * 23 + 5) % 29) - 14;
                fpr((x as f64) / 8.0)
            })
            .collect()
    }

    fn assert_vec_close(a: &[Fpr], b: &[Fpr], eps: f64) {
        assert_eq!(a.len(), b.len());
        for (idx, (x, y)) in a.iter().zip(b.iter()).enumerate() {
            let diff = (x.v - y.v).abs();
            assert!(diff <= eps, "idx={idx} x={} y={} diff={diff}", x.v, y.v);
        }
    }

    #[test]
    fn fft_roundtrips_real_polynomials() {
        for logn in 1..=8 {
            let mut poly = deterministic_real_poly(logn, 7);
            let original = poly.clone();
            fft(&mut poly, logn);
            ifft(&mut poly, logn);
            assert_vec_close(&poly, &original, 1e-9);
        }
    }

    #[test]
    fn split_merge_roundtrip_in_fft_domain() {
        for logn in 2..=8 {
            let mut poly = deterministic_real_poly(logn, 11);
            fft(&mut poly, logn);
            let hn = 1usize << (logn - 1);
            let mut f0 = vec![fpr(0.0); hn];
            let mut f1 = vec![fpr(0.0); hn];
            let mut merged = vec![fpr(0.0); 1usize << logn];

            poly_split_fft(&mut f0, &mut f1, &poly, logn);
            poly_merge_fft(&mut merged, &f0, &f1, logn);

            assert_vec_close(&merged, &poly, 1e-9);
        }
    }

    #[test]
    fn fft_matches_reference_vector_for_logn4() {
        let logn = 4;
        let mut poly = deterministic_real_poly(logn, 7);
        fft(&mut poly, logn);

        let expected = [
            0xbfcfdd505e0d4758,
            0xc005cb4e8b47f40e,
            0x3ff9cca1f9067261,
            0xc001aeb96b98862c,
            0x400bb74b8a815c08,
            0xbfd926ceb563a240,
            0x401f6a827304d4c0,
            0xbfd6af54cd03de00,
            0xbff26ac34ba7b216,
            0x3ff696f0553fb638,
            0xbff97a756c6ace8c,
            0xbff1525603ac7164,
            0x40070cff3cde4d87,
            0x400bdc8d25565357,
            0xc00b6631f570b326,
            0xc004330b39844fd0,
        ];
        let got: Vec<u64> = poly.iter().map(|x| x.v.to_bits()).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn div_then_mul_identity() {
        for logn in 2..=8 {
            let mut a = deterministic_real_poly(logn, 3);
            let mut b = deterministic_real_poly(logn, 7);
            fft(&mut a, logn);
            fft(&mut b, logn);

            let original = a.clone();
            poly_div_fft(&mut a, &b, logn);
            poly_mul_fft(&mut a, &b, logn);
            assert_vec_close(&a, &original, 1e-6);
        }
    }

    #[test]
    fn muladj_matches_mul_of_adjoint() {
        for logn in 2..=8 {
            let mut a = deterministic_real_poly(logn, 9);
            let mut b = deterministic_real_poly(logn, 13);
            fft(&mut a, logn);
            fft(&mut b, logn);

            let mut via_muladj = a.clone();
            poly_muladj_fft(&mut via_muladj, &b, logn);

            let mut b_adj = b.clone();
            poly_adj_fft(&mut b_adj, logn);
            let mut via_mul = a.clone();
            poly_mul_fft(&mut via_mul, &b_adj, logn);

            assert_vec_close(&via_muladj, &via_mul, 1e-9);
        }
    }

    #[test]
    fn mulselfadj_matches_norm_squared() {
        for logn in 2..=8 {
            let mut a = deterministic_real_poly(logn, 17);
            fft(&mut a, logn);
            let n = 1usize << logn;
            let hn = n >> 1;
            let expected: Vec<f64> = (0..hn)
                .map(|u| a[u].v * a[u].v + a[u + hn].v * a[u + hn].v)
                .collect();

            poly_mulselfadj_fft(&mut a, logn);
            for (u, exp) in expected.iter().enumerate() {
                let diff = (a[u].v - exp).abs();
                assert!(diff < 1e-9, "logn={logn} u={u} got={} exp={exp}", a[u].v);
                assert!(a[u + hn].v.abs() < 1e-15);
            }
        }
    }

    #[test]
    fn invnorm2_matches_naive_formula() {
        for logn in 2..=8 {
            let mut a = deterministic_real_poly(logn, 19);
            let mut b = deterministic_real_poly(logn, 23);
            fft(&mut a, logn);
            fft(&mut b, logn);

            let hn = 1usize << (logn - 1);
            let expected: Vec<Fpr> = (0..hn)
                .map(|u| {
                    fpr_inv(fpr_add(
                        fpr_add(fpr_sqr(a[u]), fpr_sqr(a[u + hn])),
                        fpr_add(fpr_sqr(b[u]), fpr_sqr(b[u + hn])),
                    ))
                })
                .collect();

            let mut d = vec![fpr(0.0); hn];
            poly_invnorm2_fft(&mut d, &a, &b, logn);
            assert_vec_close(&d, &expected, 1e-15);
        }
    }

    #[test]
    fn divadj_matches_division_by_adjoint() {
        for logn in 2..=8 {
            let mut a = deterministic_real_poly(logn, 29);
            let mut b = deterministic_real_poly(logn, 31);
            fft(&mut a, logn);
            fft(&mut b, logn);

            let mut via_divadj = a.clone();
            poly_divadj_fft(&mut via_divadj, &b, logn);

            let mut b_adj = b.clone();
            poly_adj_fft(&mut b_adj, logn);
            let mut via_div = a.clone();
            poly_div_fft(&mut via_div, &b_adj, logn);

            assert_vec_close(&via_divadj, &via_div, 1e-6);
        }
    }

    #[test]
    fn add_muladj_matches_manual_construction() {
        for logn in 2..=8 {
            let n = 1usize << logn;
            let mut big_f = deterministic_real_poly(logn, 37);
            let mut big_g = deterministic_real_poly(logn, 41);
            let mut f = deterministic_real_poly(logn, 43);
            let mut g = deterministic_real_poly(logn, 47);
            fft(&mut big_f, logn);
            fft(&mut big_g, logn);
            fft(&mut f, logn);
            fft(&mut g, logn);

            let mut t1 = big_f.clone();
            poly_muladj_fft(&mut t1, &f, logn);
            let mut t2 = big_g.clone();
            poly_muladj_fft(&mut t2, &g, logn);
            let expected: Vec<Fpr> = t1
                .iter()
                .zip(t2.iter())
                .map(|(&x, &y)| fpr_add(x, y))
                .collect();

            let mut d = vec![fpr(0.0); n];
            poly_add_muladj_fft(&mut d, &big_f, &big_g, &f, &g, logn);
            assert_vec_close(&d, &expected, 1e-9);
        }
    }

    #[test]
    fn basic_time_and_fft_domain_ops_are_consistent() {
        let logn = 3;
        let mut a = deterministic_real_poly(logn, 5);
        let b = deterministic_real_poly(logn, 8);
        let original = a.clone();

        poly_add(&mut a, &b, logn);
        poly_sub(&mut a, &b, logn);
        assert_vec_close(&a, &original, 0.0);

        poly_neg(&mut a, logn);
        poly_neg(&mut a, logn);
        assert_vec_close(&a, &original, 0.0);

        poly_mulconst(&mut a, fpr(2.0), logn);
        poly_mulconst(&mut a, fpr(0.5), logn);
        assert_vec_close(&a, &original, 1e-15);
    }

    #[test]
    fn inverse_then_multiply_gives_one() {
        for logn in 2..=8 {
            let mut a = deterministic_real_poly(logn, 51);
            fft(&mut a, logn);

            let mut inv = a.clone();
            poly_inv_fft(&mut inv, logn);
            poly_mul_fft(&mut inv, &a, logn);

            let n = 1usize << logn;
            let hn = n >> 1;
            for u in 0..hn {
                assert!((inv[u].v - 1.0).abs() < 1e-9);
                assert!(inv[u + hn].v.abs() < 1e-9);
            }
        }
    }
}
