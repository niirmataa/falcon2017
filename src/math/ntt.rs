//! Number-theoretic transform helpers.

use crate::math::modp::{
    modp_add, modp_div, modp_montymul, modp_r, modp_r2, modp_sub,
};

include!("mq_binary_tables.rs");

pub(crate) const QB: u32 = 12_289;
pub(crate) const Q0IB: u32 = 12_287;
pub(crate) const RB: u32 = 4_091;
pub(crate) const R2B: u32 = 10_952;

#[inline]
fn bit_reverse_10(x: usize) -> usize {
    ((x as u16).reverse_bits() >> 6) as usize
}

pub(crate) fn modp_mkgm2(
    gm: &mut [u32],
    igm: &mut [u32],
    logn: u32,
    mut g: u32,
    p: u32,
    p0i: u32,
) {
    assert!(logn <= 10);
    let n = 1usize << logn;
    assert!(gm.len() >= n);
    assert!(igm.len() >= n);

    let r2 = modp_r2(p, p0i);
    g = modp_montymul(g, r2, p, p0i);
    for _ in logn..10 {
        g = modp_montymul(g, g, p, p0i);
    }

    let ig = modp_div(r2, g, p, p0i, modp_r(p));
    let k = 10 - logn;
    let mut x1 = modp_r(p);
    let mut x2 = modp_r(p);
    for u in 0..n {
        let v = bit_reverse_10(u << k);
        gm[v] = x1;
        igm[v] = x2;
        x1 = modp_montymul(x1, g, p, p0i);
        x2 = modp_montymul(x2, ig, p, p0i);
    }
}

pub(crate) fn modp_ntt2_ext(
    a: &mut [u32],
    stride: usize,
    gm: &[u32],
    logn: u32,
    p: u32,
    p0i: u32,
) {
    if logn == 0 {
        return;
    }

    let n = 1usize << logn;
    assert!(gm.len() >= n);
    assert!(a.len() >= (n - 1) * stride + 1);

    let mut t = n;
    let mut m = 1usize;
    while m < n {
        let ht = t >> 1;
        let mut v1 = 0usize;
        for u in 0..m {
            let s = gm[m + u];
            let mut r1 = v1 * stride;
            let mut r2 = r1 + ht * stride;
            for _ in 0..ht {
                let x = a[r1];
                let y = modp_montymul(a[r2], s, p, p0i);
                a[r1] = modp_add(x, y, p);
                a[r2] = modp_sub(x, y, p);
                r1 += stride;
                r2 += stride;
            }
            v1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

pub(crate) fn modp_intt2_ext(
    a: &mut [u32],
    stride: usize,
    igm: &[u32],
    logn: u32,
    p: u32,
    p0i: u32,
) {
    if logn == 0 {
        return;
    }

    let n = 1usize << logn;
    assert!(igm.len() >= n);
    assert!(a.len() >= (n - 1) * stride + 1);

    let mut t = 1usize;
    let mut m = n;
    while m > 1 {
        let hm = m >> 1;
        let dt = t << 1;
        let mut v1 = 0usize;
        for u in 0..hm {
            let s = igm[hm + u];
            let mut r1 = v1 * stride;
            let mut r2 = r1 + t * stride;
            for _ in 0..t {
                let x = a[r1];
                let y = a[r2];
                a[r1] = modp_add(x, y, p);
                a[r2] = modp_montymul(modp_sub(x, y, p), s, p, p0i);
                r1 += stride;
                r2 += stride;
            }
            v1 += dt;
        }
        t = dt;
        m = hm;
    }

    let ni = 1u32 << (31 - logn);
    let mut r = 0usize;
    for _ in 0..n {
        a[r] = modp_montymul(a[r], ni, p, p0i);
        r += stride;
    }
}

#[inline]
pub(crate) fn modp_ntt2(a: &mut [u32], gm: &[u32], logn: u32, p: u32, p0i: u32) {
    modp_ntt2_ext(a, 1, gm, logn, p, p0i);
}

#[inline]
pub(crate) fn modp_intt2(a: &mut [u32], igm: &[u32], logn: u32, p: u32, p0i: u32) {
    modp_intt2_ext(a, 1, igm, logn, p, p0i);
}

#[inline]
pub(crate) fn mq_conv_small(x: i32, q: u32) -> u32 {
    let mut y = x as u32;
    y = y.wrapping_add(q & 0u32.wrapping_sub(y >> 31));
    y
}

#[inline]
pub(crate) fn mq_add(x: u32, y: u32, q: u32) -> u32 {
    let mut d = x.wrapping_add(y).wrapping_sub(q);
    d = d.wrapping_add(q & 0u32.wrapping_sub(d >> 31));
    d
}

#[inline]
pub(crate) fn mq_sub(x: u32, y: u32, q: u32) -> u32 {
    let mut d = x.wrapping_sub(y);
    d = d.wrapping_add(q & 0u32.wrapping_sub(d >> 31));
    d
}

#[inline]
pub(crate) fn mq_rshift1(mut x: u32, q: u32) -> u32 {
    x = x.wrapping_add(q & 0u32.wrapping_sub(x & 1));
    x >> 1
}

#[inline]
pub(crate) fn mq_montymul(x: u32, y: u32, q: u32, q0i: u32) -> u32 {
    let mut z = x.wrapping_mul(y);
    let w = (z.wrapping_mul(q0i) & 0xFFFF).wrapping_mul(q);
    z = z.wrapping_add(w) >> 16;
    z = z.wrapping_sub(q);
    z = z.wrapping_add(q & 0u32.wrapping_sub(z >> 31));
    z
}

#[inline]
pub(crate) fn mq_montysqr(x: u32, q: u32, q0i: u32) -> u32 {
    mq_montymul(x, x, q, q0i)
}

pub(crate) fn mq_div_12289(x: u32, y: u32) -> u32 {
    let y0 = mq_montymul(y, R2B, QB, Q0IB);
    let y1 = mq_montysqr(y0, QB, Q0IB);
    let y2 = mq_montymul(y1, y0, QB, Q0IB);
    let y3 = mq_montymul(y2, y1, QB, Q0IB);
    let y4 = mq_montysqr(y3, QB, Q0IB);
    let y5 = mq_montysqr(y4, QB, Q0IB);
    let y6 = mq_montysqr(y5, QB, Q0IB);
    let y7 = mq_montysqr(y6, QB, Q0IB);
    let y8 = mq_montysqr(y7, QB, Q0IB);
    let y9 = mq_montymul(y8, y2, QB, Q0IB);
    let y10 = mq_montymul(y9, y8, QB, Q0IB);
    let y11 = mq_montysqr(y10, QB, Q0IB);
    let y12 = mq_montysqr(y11, QB, Q0IB);
    let y13 = mq_montymul(y12, y9, QB, Q0IB);
    let y14 = mq_montysqr(y13, QB, Q0IB);
    let y15 = mq_montysqr(y14, QB, Q0IB);
    let y16 = mq_montymul(y15, y10, QB, Q0IB);
    let y17 = mq_montysqr(y16, QB, Q0IB);
    let y18 = mq_montymul(y17, y0, QB, Q0IB);
    mq_montymul(y18, x, QB, Q0IB)
}

pub(crate) fn mq_ntt_binary(a: &mut [u16], logn: u32) {
    let n = 1usize << logn;
    assert!(a.len() >= n);

    let mut t = n;
    let mut m = 1usize;
    while m < n {
        let ht = t >> 1;
        let mut j1 = 0usize;
        for i in 0..m {
            let s = GMB[m + i] as u32;
            let j2 = j1 + ht;
            for j in j1..j2 {
                let u = a[j] as u32;
                let v = mq_montymul(a[j + ht] as u32, s, QB, Q0IB);
                a[j] = mq_add(u, v, QB) as u16;
                a[j + ht] = mq_sub(u, v, QB) as u16;
            }
            j1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

pub(crate) fn mq_intt_binary(a: &mut [u16], logn: u32) {
    let n = 1usize << logn;
    assert!(a.len() >= n);

    let mut t = 1usize;
    let mut m = n;
    while m > 1 {
        let hm = m >> 1;
        let dt = t << 1;
        let mut j1 = 0usize;
        for i in 0..hm {
            let s = IGMB[hm + i] as u32;
            let j2 = j1 + t;
            for j in j1..j2 {
                let u = a[j] as u32;
                let v = a[j + t] as u32;
                a[j] = mq_add(u, v, QB) as u16;
                let w = mq_sub(u, v, QB);
                a[j + t] = mq_montymul(w, s, QB, Q0IB) as u16;
            }
            j1 += dt;
        }
        t = dt;
        m = hm;
    }

    let mut ni = RB;
    let mut m = n;
    while m > 1 {
        ni = mq_rshift1(ni, QB);
        m >>= 1;
    }
    for value in a.iter_mut().take(n) {
        *value = mq_montymul(*value as u32, ni, QB, Q0IB) as u16;
    }
}

pub(crate) fn mq_poly_tomonty(f: &mut [u16], logn: u32) {
    let n = 1usize << logn;
    assert!(f.len() >= n);
    for value in f.iter_mut().take(n) {
        *value = mq_montymul(*value as u32, R2B, QB, Q0IB) as u16;
    }
}

pub(crate) fn mq_poly_montymul_ntt(f: &mut [u16], g: &[u16], logn: u32) {
    let n = 1usize << logn;
    assert!(f.len() >= n);
    assert!(g.len() >= n);
    for (x, y) in f.iter_mut().zip(g.iter()).take(n) {
        *x = mq_montymul(*x as u32, *y as u32, QB, Q0IB) as u16;
    }
}

pub(crate) fn mq_poly_sub(f: &mut [u16], g: &[u16], logn: u32) {
    let n = 1usize << logn;
    assert!(f.len() >= n);
    assert!(g.len() >= n);
    for (x, y) in f.iter_mut().zip(g.iter()).take(n) {
        *x = mq_sub(*x as u32, *y as u32, QB) as u16;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        modp_intt2, modp_mkgm2, modp_ntt2, mq_div_12289, mq_intt_binary, mq_montymul,
        mq_ntt_binary, mq_poly_montymul_ntt, mq_poly_sub, mq_poly_tomonty, Q0IB, QB, R2B,
    };
    use crate::math::modp::modp_ninv31;
    use crate::math::primes::PRIMES2;

    #[test]
    fn modp_ntt_roundtrip_restores_input() {
        let logn = 4;
        let n = 1usize << logn;
        let p = PRIMES2[0].p;
        let p0i = modp_ninv31(p);
        let mut gm = vec![0u32; n];
        let mut igm = vec![0u32; n];
        modp_mkgm2(&mut gm, &mut igm, logn, PRIMES2[0].g, p, p0i);

        let mut poly: Vec<u32> = (0..n)
            .map(|i| ((i * 17 + 23) as u32 % (p - 1)) + 1)
            .collect();
        let original = poly.clone();
        modp_ntt2(&mut poly, &gm, logn, p, p0i);
        modp_intt2(&mut poly, &igm, logn, p, p0i);
        assert_eq!(poly, original);
    }

    #[test]
    fn mq_binary_ntt_roundtrip_restores_input() {
        let logn = 4;
        let n = 1usize << logn;
        let mut poly: Vec<u16> = (0..n).map(|i| ((i * 19 + 5) % QB as usize) as u16).collect();
        let original = poly.clone();
        mq_ntt_binary(&mut poly, logn);
        mq_intt_binary(&mut poly, logn);
        assert_eq!(poly, original);
    }

    #[test]
    fn mq_division_matches_montgomery_inverse() {
        let x = 3210;
        let y = 7654;
        let quotient = mq_div_12289(x, y);
        let y_m = mq_montymul(y, R2B, QB, Q0IB);
        assert_eq!(mq_montymul(quotient, y_m, QB, Q0IB), x);
        assert_eq!(mq_div_12289(x, 0), 0);
    }

    #[test]
    fn mq_poly_helpers_match_naive_pointwise_ops() {
        let logn = 4;
        let n = 1usize << logn;
        let mut f: Vec<u16> = (0..n).map(|i| ((i * 13 + 7) % QB as usize) as u16).collect();
        let g: Vec<u16> = (0..n).map(|i| ((i * 29 + 3) % QB as usize) as u16).collect();

        let mut expected = f.clone();
        mq_poly_tomonty(&mut expected, logn);
        for (x, y) in expected.iter_mut().zip(g.iter()) {
            *x = mq_montymul(*x as u32, *y as u32, QB, Q0IB) as u16;
            *x = ((*x as u32 + QB - (*y as u32)) % QB) as u16;
        }

        mq_poly_tomonty(&mut f, logn);
        mq_poly_montymul_ntt(&mut f, &g, logn);
        mq_poly_sub(&mut f, &g, logn);
        assert_eq!(f, expected);
    }

    #[test]
    fn modp_binary_ntt_matches_reference_vector() {
        let logn = 4;
        let n = 1usize << logn;
        let p = PRIMES2[0].p;
        let p0i = modp_ninv31(p);
        let mut gm = vec![0u32; n];
        let mut igm = vec![0u32; n];
        modp_mkgm2(&mut gm, &mut igm, logn, PRIMES2[0].g, p, p0i);

        let expected_gm = [
            10_239,
            1_211_775_442,
            844_192_849,
            380_966_363,
            1_642_906_936,
            510_722_630,
            1_508_861_108,
            414_755_385,
            2_109_245_776,
            1_087_146_993,
            713_248_495,
            1_265_826_808,
            1_080_677_998,
            1_362_297_708,
            861_384_770,
            1_704_046_399,
        ];
        assert_eq!(&gm[..n], &expected_gm);

        let mut poly: Vec<u32> = (0..n)
            .map(|i| ((i * 17 + 23) as u32 % (p - 1)) + 1)
            .collect();
        modp_ntt2(&mut poly, &gm, logn, p, p0i);
        let expected_poly = [
            1_334_830_942,
            1_485_069_122,
            1_401_884_069,
            337_133_614,
            211_000_779,
            352_471_768,
            1_996_719_127,
            142_173_480,
            988_511_460,
            1_575_857_383,
            1_468_780_606,
            759_426_803,
            1_535_543_011,
            1_822_595_633,
            1_267_958_000,
            499_831_859,
        ];
        assert_eq!(&poly[..n], &expected_poly);
    }

    #[test]
    fn mq_binary_ntt_matches_reference_vector() {
        let logn = 4;
        let n = 1usize << logn;
        let mut poly: Vec<u16> = (0..n).map(|i| ((i * 19 + 5) % QB as usize) as u16).collect();
        mq_ntt_binary(&mut poly, logn);

        assert_eq!(mq_div_12289(3210, 7654), 9_226);
        assert_eq!(
            &poly[..n],
            &[
                4_374, 10_685, 5_745, 8_299, 2_514, 566, 9_990, 5_038, 10_604, 6_665, 2_484,
                3_629, 990, 1_017, 6_736, 6_767,
            ]
        );
    }
}
