//! Modular arithmetic helpers.

#[inline]
pub(crate) fn modp_set(x: i32, p: u32) -> u32 {
    let mut w = x as u32;
    w = w.wrapping_add(p & 0u32.wrapping_sub(w >> 31));
    w
}

#[inline]
pub(crate) fn modp_norm(x: u32, p: u32) -> i32 {
    x.wrapping_sub(
        p & (x
            .wrapping_sub((p + 1) >> 1)
            .wrapping_shr(31)
            .wrapping_sub(1)),
    ) as i32
}

pub(crate) fn modp_ninv31(p: u32) -> u32 {
    let mut y = 2u32.wrapping_sub(p);
    y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
    y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
    y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
    y = y.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(y)));
    0x7FFF_FFFF & 0u32.wrapping_sub(y)
}

#[inline]
pub(crate) fn modp_r(p: u32) -> u32 {
    (1u32 << 31).wrapping_sub(p)
}

#[inline]
pub(crate) fn modp_add(a: u32, b: u32, p: u32) -> u32 {
    let mut d = a.wrapping_add(b).wrapping_sub(p);
    d = d.wrapping_add(p & 0u32.wrapping_sub(d >> 31));
    d
}

#[inline]
pub(crate) fn modp_sub(a: u32, b: u32, p: u32) -> u32 {
    let mut d = a.wrapping_sub(b);
    d = d.wrapping_add(p & 0u32.wrapping_sub(d >> 31));
    d
}

#[inline]
pub(crate) fn modp_half(mut a: u32, p: u32) -> u32 {
    a = a.wrapping_add(p & 0u32.wrapping_sub(a & 1));
    a >> 1
}

#[inline]
pub(crate) fn modp_montymul(a: u32, b: u32, p: u32, p0i: u32) -> u32 {
    let z = (a as u64) * (b as u64);
    let w = ((z.wrapping_mul(p0i as u64)) & 0x7FFF_FFFFu64) * (p as u64);
    let mut d = ((z + w) >> 31) as u32;
    d = d.wrapping_sub(p);
    d = d.wrapping_add(p & 0u32.wrapping_sub(d >> 31));
    d
}

pub(crate) fn modp_r2(p: u32, p0i: u32) -> u32 {
    let mut z = modp_r(p);
    z = modp_add(z, z, p);
    z = modp_montymul(z, z, p, p0i);
    z = modp_montymul(z, z, p, p0i);
    z = modp_montymul(z, z, p, p0i);
    z = modp_montymul(z, z, p, p0i);
    z = modp_montymul(z, z, p, p0i);
    modp_half(z, p)
}

pub(crate) fn modp_rx(x: u32, p: u32, p0i: u32, r2: u32) -> u32 {
    debug_assert!(x > 0);

    let x = x - 1;
    let mut r = r2;
    let mut z = modp_r(p);
    let mut i = 0u32;
    while (1u32 << i) <= x {
        if (x & (1u32 << i)) != 0 {
            z = modp_montymul(z, r, p, p0i);
        }
        r = modp_montymul(r, r, p, p0i);
        i += 1;
    }
    z
}

pub(crate) fn modp_div(a: u32, b: u32, p: u32, p0i: u32, r: u32) -> u32 {
    let e = p - 2;
    let mut z = r;
    for i in (0..=30u32).rev() {
        z = modp_montymul(z, z, p, p0i);
        let z2 = modp_montymul(z, b, p, p0i);
        let mask = 0u32.wrapping_sub((e >> i) & 1);
        z ^= (z ^ z2) & mask;
    }
    z = modp_montymul(z, 1, p, p0i);
    modp_montymul(a, z, p, p0i)
}

#[cfg(test)]
mod tests {
    use super::{
        modp_add, modp_div, modp_half, modp_montymul, modp_ninv31, modp_norm, modp_r, modp_r2,
        modp_rx, modp_set, modp_sub,
    };
    use crate::math::primes::PRIMES2;

    #[test]
    fn montgomery_helpers_are_self_consistent() {
        let p = PRIMES2[0].p;
        let p0i = modp_ninv31(p);
        let r = modp_r(p);
        let r2 = modp_r2(p, p0i);

        assert_eq!(modp_set(-17, p), p - 17);
        assert_eq!(modp_norm(p - 17, p), -17);
        assert_eq!(modp_add(p - 1, 5, p), 4);
        assert_eq!(modp_sub(5, 9, p), p - 4);
        assert_eq!(modp_half(9, p), (p + 9) >> 1);
        assert_eq!(modp_montymul(1, r2, p, p0i), r);
        assert_eq!(modp_montymul(r, r, p, p0i), r);
        assert_eq!(modp_div(123_456, 0, p, p0i, r), 0);
    }

    #[test]
    fn rx_matches_repeated_multiplication() {
        let p = PRIMES2[0].p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);

        let mut z = 1u128;
        let base = (1u128 << 31) % (p as u128);
        for _ in 0..7 {
            z = (z * base) % (p as u128);
        }
        assert_eq!(modp_rx(7, p, p0i, r2), z as u32);
    }

    #[test]
    fn helpers_match_reference_vectors() {
        let p = PRIMES2[0].p;
        let p0i = modp_ninv31(p);
        let r = modp_r(p);
        let r2 = modp_r2(p, p0i);

        assert_eq!(p0i, 2_042_615_807);
        assert_eq!(r, 10_239);
        assert_eq!(r2, 104_837_121);
        assert_eq!(modp_rx(7, p, p0i, r2), 98_366_116);
        assert_eq!(modp_div(12_345_678, 87_654_321, p, p0i, r), 1_257_904_292);
        assert_eq!(modp_montymul(123_456_789, 987_654_321, p, p0i), 588_659_901);
    }
}
