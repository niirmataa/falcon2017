//! Big-integer helpers used by NTRU solving.

use crate::math::modp::{
    modp_add, modp_div, modp_montymul, modp_ninv31, modp_r, modp_r2, modp_sub,
};
use crate::math::primes::primes2;

const MASK31: u32 = 0x7FFF_FFFF;

pub(crate) fn zint_add(a: &mut [u32], b: &[u32]) -> u32 {
    let mut cc = 0u32;
    for (aw, bw) in a.iter_mut().zip(b.iter()) {
        let w = aw.wrapping_add(*bw).wrapping_add(cc);
        *aw = w & MASK31;
        cc = w >> 31;
    }
    cc
}

pub(crate) fn zint_sub(a: &mut [u32], b: &[u32]) -> u32 {
    let mut cc = 0u32;
    for (aw, bw) in a.iter_mut().zip(b.iter()) {
        let w = aw.wrapping_sub(*bw).wrapping_sub(cc);
        *aw = w & MASK31;
        cc = w >> 31;
    }
    cc
}

pub(crate) fn zint_mul_small(m: &mut [u32], x: u32) -> u32 {
    let mut cc = 0u32;
    for w in m.iter_mut() {
        let z = (*w as u64) * (x as u64) + (cc as u64);
        *w = (z as u32) & MASK31;
        cc = (z >> 31) as u32;
    }
    cc
}

pub(crate) fn zint_mod_small_unsigned(d: &[u32], p: u32, p0i: u32, r2: u32) -> u32 {
    let mut x = 0u32;
    for &word in d.iter().rev() {
        x = modp_montymul(x, r2, p, p0i);
        let mut w = word.wrapping_sub(p);
        w = w.wrapping_add(p & 0u32.wrapping_sub(w >> 31));
        x = modp_add(x, w, p);
    }
    x
}

pub(crate) fn zint_mod_small_signed(d: &[u32], p: u32, p0i: u32, r2: u32, rx: u32) -> u32 {
    if d.is_empty() {
        return 0;
    }
    let z = zint_mod_small_unsigned(d, p, p0i, r2);
    modp_sub(z, rx & 0u32.wrapping_sub(d[d.len() - 1] >> 30), p)
}

pub(crate) fn zint_add_mul_small(x: &mut [u32], y: &[u32], len: usize, s: u32) {
    let mut cc = 0u32;
    for u in 0..len {
        let z = (y[u] as u64) * (s as u64) + (x[u] as u64) + (cc as u64);
        x[u] = (z as u32) & MASK31;
        cc = (z >> 31) as u32;
    }
    x[len] = cc;
}

pub(crate) fn zint_rshift1(d: &mut [u32]) -> u32 {
    let mut cc = 0u32;
    for w in d.iter_mut().rev() {
        let old = *w;
        *w = (old >> 1) | (cc << 30);
        cc = old & 1;
    }
    cc
}

pub(crate) fn zint_rshift1_mod(x: &mut [u32], p: &[u32]) {
    let hi = if (x[0] & 1) != 0 { zint_add(x, p) } else { 0 };
    zint_rshift1(x);
    let last = x.len() - 1;
    x[last] |= hi << 30;
}

pub(crate) fn zint_sub_mod(x: &mut [u32], y: &[u32], p: &[u32]) {
    if zint_sub(x, y) != 0 {
        zint_add(x, p);
    }
}

pub(crate) fn zint_ucmp(a: &[u32], b: &[u32]) -> i32 {
    for (&wa, &wb) in a.iter().zip(b.iter()).rev() {
        if wa < wb {
            return -1;
        }
        if wa > wb {
            return 1;
        }
    }
    0
}

pub(crate) fn zint_norm_zero(x: &mut [u32], p: &[u32]) {
    let mut cc = 0u32;
    for u in (0..p.len()).rev() {
        let w = (p[u] >> 1) | (cc << 30);
        cc = p[u] & 1;
        if x[u] < w {
            return;
        }
        if x[u] > w {
            zint_sub(x, p);
            return;
        }
    }
}

pub(crate) fn zint_rebuild_crt(
    xx: &mut [u32],
    xlen: usize,
    xstride: usize,
    num: usize,
    normalize_signed: bool,
) {
    let primes = primes2();
    let mut tmp = vec![0u32; xlen];
    tmp[0] = primes[0].p;
    for u in 1..xlen {
        let p = primes[u].p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let qmod = zint_mod_small_unsigned(&tmp[..u], p, p0i, r2);
        let s = modp_div(modp_r(p), qmod, p, p0i, modp_r(p));
        for v in 0..num {
            let x = &mut xx[v * xstride..][..xlen];
            let xp = x[u];
            let xq = zint_mod_small_unsigned(&x[..u], p, p0i, r2);
            let xr = modp_montymul(s, modp_sub(xp, xq, p), p, p0i);
            zint_add_mul_small(x, &tmp, u, xr);
        }
        tmp[u] = zint_mul_small(&mut tmp[..u], p);
    }
    if normalize_signed {
        for v in 0..num {
            let x = &mut xx[v * xstride..][..xlen];
            zint_norm_zero(x, &tmp);
        }
    }
}

pub(crate) fn zint_exact_length(x: &[u32]) -> usize {
    let mut xlen = x.len();
    while xlen > 0 && x[xlen - 1] == 0 {
        xlen -= 1;
    }
    xlen
}

pub(crate) fn zint_co_reduce(
    a: &mut [u32],
    b: &mut [u32],
    xa: i32,
    xb: i32,
    ya: i32,
    yb: i32,
) -> i32 {
    let len = a.len();
    let mut cca = 0i32;
    let mut ccb = 0i32;
    for u in 0..len {
        let wa = a[u] as i32;
        let wb = b[u] as i32;
        let za = wa as i64 * xa as i64 + wb as i64 * xb as i64 + cca as i64;
        let zb = wa as i64 * ya as i64 + wb as i64 * yb as i64 + ccb as i64;
        if u > 0 {
            a[u - 1] = (za as u32) & MASK31;
            b[u - 1] = (zb as u32) & MASK31;
        }
        cca = (za >> 31) as i32;
        ccb = (zb >> 31) as i32;
    }
    a[len - 1] = cca as u32;
    b[len - 1] = ccb as u32;

    let mut r = 0i32;
    if cca < 0 {
        let mut c = 1u32;
        for w in a.iter_mut() {
            let nw = c.wrapping_add(!*w);
            *w = nw & MASK31;
            c = (!nw) >> 31;
        }
        r |= 1;
    }
    if ccb < 0 {
        let mut c = 1u32;
        for w in b.iter_mut() {
            let nw = c.wrapping_add(!*w);
            *w = nw & MASK31;
            c = (!nw) >> 31;
        }
        r |= 2;
    }
    r
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn zint_co_reduce_mod(
    a: &mut [u32],
    b: &mut [u32],
    m: &[u32],
    m0i: u32,
    xa: i32,
    xb: i32,
    ya: i32,
    yb: i32,
) {
    let len = a.len();
    let fx = a[0]
        .wrapping_mul(xa as u32)
        .wrapping_add(b[0].wrapping_mul(xb as u32))
        .wrapping_mul(m0i)
        & MASK31;
    let fy = a[0]
        .wrapping_mul(ya as u32)
        .wrapping_add(b[0].wrapping_mul(yb as u32))
        .wrapping_mul(m0i)
        & MASK31;

    let mut cca = 0i64;
    let mut ccb = 0i64;
    for u in 0..len {
        let wa = a[u] as i64;
        let wb = b[u] as i64;
        let mut za = wa * xa as i64 + wb * xb as i64 + cca;
        let mut zb = wa * ya as i64 + wb * yb as i64 + ccb;
        za += m[u] as i64 * fx as i64;
        zb += m[u] as i64 * fy as i64;
        if u > 0 {
            a[u - 1] = (za as u32) & MASK31;
            b[u - 1] = (zb as u32) & MASK31;
        }
        cca = za >> 31;
        ccb = zb >> 31;
    }
    a[len - 1] = (cca as u32) & MASK31;
    b[len - 1] = (ccb as u32) & MASK31;

    if cca < 0 {
        zint_add(a, m);
    } else if zint_ucmp(a, m) >= 0 {
        zint_sub(a, m);
    }
    if ccb < 0 {
        zint_add(b, m);
    } else if zint_ucmp(b, m) >= 0 {
        zint_sub(b, m);
    }
}

pub(crate) fn zint_reduce(a: &mut [u32], b: &[u32], k: i32) -> bool {
    let len = a.len();
    let mut cc = 0i32;
    for u in 0..len {
        let wa = a[u] as i32;
        let wb = b[u] as i32;
        let z = wb as i64 * k as i64 + wa as i64 + cc as i64;
        if u > 0 {
            a[u - 1] = (z as u32) & MASK31;
        }
        cc = (z >> 31) as i32;
    }
    a[len - 1] = cc as u32;
    if cc < 0 {
        let mut c = 1u32;
        for w in a.iter_mut() {
            let nw = c.wrapping_add(!*w);
            *w = nw & MASK31;
            c = (!nw) >> 31;
        }
        true
    } else {
        false
    }
}

pub(crate) fn zint_reduce_mod(a: &mut [u32], b: &[u32], m: &[u32], m0i: u32, k: i32) {
    let len = a.len();
    let f = a[0]
        .wrapping_add(b[0].wrapping_mul(k as u32))
        .wrapping_mul(m0i)
        & MASK31;
    let mut cc = 0i32;
    for u in 0..len {
        let z = a[u] as i64 + b[u] as i64 * k as i64 + cc as i64 + m[u] as i64 * f as i64;
        if u > 0 {
            a[u - 1] = (z as u32) & MASK31;
        }
        cc = (z >> 31) as i32;
    }
    a[len - 1] = (cc as u32) & MASK31;
    if cc < 0 {
        zint_add(a, m);
    } else if zint_ucmp(a, m) >= 0 {
        zint_sub(a, m);
    }
}

pub(crate) fn zint_bezout(x: &[u32], y: &[u32]) -> Option<(Vec<u32>, Vec<u32>)> {
    let len = x.len();
    let xlen = zint_exact_length(x);
    let ylen = zint_exact_length(y);
    if xlen == 0 || ylen == 0 || (x[0] & y[0] & 1) == 0 {
        return None;
    }

    let mut u0 = vec![0u32; len];
    let mut v0 = vec![0u32; len];
    let mut u1 = vec![0u32; len];
    let mut v1 = vec![0u32; len];
    let mut a = vec![0u32; len];
    let mut b = vec![0u32; len];

    a[..xlen].copy_from_slice(&x[..xlen]);
    b[..ylen].copy_from_slice(&y[..ylen]);
    u0[0] = 1;
    u1[..ylen].copy_from_slice(&y[..ylen]);
    v1[..xlen].copy_from_slice(&x[..xlen]);
    v1[0] &= !1;

    if xlen == 1 && x[0] == 1 {
        return Some((u0, v0));
    }
    if ylen == 1 && y[0] == 1 {
        return Some((u1, v1));
    }

    let x0i = modp_ninv31(x[0]);
    let y0i = modp_ninv31(y[0]);
    let mut alen = xlen;
    let mut blen = ylen;

    loop {
        if alen >= 3 || blen >= 3 {
            let work_len = alen.max(blen);
            let mut a_hi = ((a[work_len - 1] as u64) << 31) | a[work_len - 2] as u64;
            let mut b_hi = ((b[work_len - 1] as u64) << 31) | b[work_len - 2] as u64;
            let mut a_lo = a[0];
            let mut b_lo = b[0];
            let mut uxa = 1u32;
            let mut uxb = 0u32;
            let mut uya = 0u32;
            let mut uyb = 1u32;

            for i in 0..31 {
                let m = 1u32 << i;
                if (a_lo & m) == 0 {
                    a_hi >>= 1;
                    b_lo <<= 1;
                    uya <<= 1;
                    uyb <<= 1;
                } else if (b_lo & m) == 0 {
                    b_hi >>= 1;
                    a_lo <<= 1;
                    uxa <<= 1;
                    uxb <<= 1;
                } else if a_hi > b_hi {
                    a_hi -= b_hi;
                    a_lo = a_lo.wrapping_sub(b_lo);
                    uxa = uxa.wrapping_sub(uya);
                    uxb = uxb.wrapping_sub(uyb);
                    a_hi >>= 1;
                    b_lo <<= 1;
                    uya <<= 1;
                    uyb <<= 1;
                } else {
                    b_hi -= a_hi;
                    b_lo = b_lo.wrapping_sub(a_lo);
                    uya = uya.wrapping_sub(uxa);
                    uyb = uyb.wrapping_sub(uxb);
                    b_hi >>= 1;
                    a_lo <<= 1;
                    uxa <<= 1;
                    uxb <<= 1;
                }
            }

            if uxa == 0x8000_0000 {
                if uxb != 0 || uyb != 1 {
                    return None;
                }
                let mut ya = uya as i32;
                if zint_reduce(&mut b[..work_len], &a[..work_len], ya) {
                    ya = -ya;
                }
                zint_reduce_mod(&mut u1[..ylen], &u0[..ylen], &y[..ylen], y0i, ya);
                zint_reduce_mod(&mut v1[..xlen], &v0[..xlen], &x[..xlen], x0i, ya);
            } else if uyb == 0x8000_0000 {
                if uya != 0 || uxa != 1 {
                    return None;
                }
                let mut xb = uxb as i32;
                if zint_reduce(&mut a[..work_len], &b[..work_len], xb) {
                    xb = -xb;
                }
                zint_reduce_mod(&mut u0[..ylen], &u1[..ylen], &y[..ylen], y0i, xb);
                zint_reduce_mod(&mut v0[..xlen], &v1[..xlen], &x[..xlen], x0i, xb);
            } else {
                let mut xa = uxa as i32;
                let mut xb = uxb as i32;
                let mut ya = uya as i32;
                let mut yb = uyb as i32;
                let r = zint_co_reduce(&mut a[..work_len], &mut b[..work_len], xa, xb, ya, yb);
                if (r & 1) != 0 {
                    xa = -xa;
                    xb = -xb;
                }
                if (r & 2) != 0 {
                    ya = -ya;
                    yb = -yb;
                }
                zint_co_reduce_mod(
                    &mut u0[..ylen],
                    &mut u1[..ylen],
                    &y[..ylen],
                    y0i,
                    xa,
                    xb,
                    ya,
                    yb,
                );
                zint_co_reduce_mod(
                    &mut v0[..xlen],
                    &mut v1[..xlen],
                    &x[..xlen],
                    x0i,
                    xa,
                    xb,
                    ya,
                    yb,
                );
            }
            alen = zint_exact_length(&a[..alen]);
            blen = zint_exact_length(&b[..blen]);
            continue;
        }

        if (a[0] & 1) == 0 {
            zint_rshift1(&mut a[..alen]);
            alen = zint_exact_length(&a[..alen]);
            zint_rshift1_mod(&mut u0[..ylen], &y[..ylen]);
            zint_rshift1_mod(&mut v0[..xlen], &x[..xlen]);
            continue;
        }
        if (b[0] & 1) == 0 {
            zint_rshift1(&mut b[..blen]);
            blen = zint_exact_length(&b[..blen]);
            zint_rshift1_mod(&mut u1[..ylen], &y[..ylen]);
            zint_rshift1_mod(&mut v1[..xlen], &x[..xlen]);
            continue;
        }

        let r = if alen < blen {
            -1
        } else if alen > blen {
            1
        } else {
            zint_ucmp(&a[..alen], &b[..blen])
        };
        if r == 0 {
            return if alen == 1 && a[0] == 1 {
                Some((u0, v0))
            } else {
                None
            };
        }

        if r > 0 {
            zint_sub(&mut a[..alen], &b[..alen]);
            alen = zint_exact_length(&a[..alen]);
            zint_sub_mod(&mut u0[..ylen], &u1[..ylen], &y[..ylen]);
            zint_sub_mod(&mut v0[..xlen], &v1[..xlen], &x[..xlen]);
        } else {
            zint_sub(&mut b[..blen], &a[..blen]);
            blen = zint_exact_length(&b[..blen]);
            zint_sub_mod(&mut u1[..ylen], &u0[..ylen], &y[..ylen]);
            zint_sub_mod(&mut v1[..xlen], &v0[..xlen], &x[..xlen]);
        }
    }
}

#[inline]
pub(crate) fn bitlength(x: u32) -> u32 {
    if x == 0 {
        0
    } else {
        32 - x.leading_zeros()
    }
}

pub(crate) fn zint_signed_bit_length(x: &[u32]) -> u32 {
    if x.is_empty() {
        return 0;
    }
    let sign = if (x[x.len() - 1] >> 30) != 0 {
        MASK31
    } else {
        0
    };
    let mut xlen = x.len();
    while xlen > 0 && x[xlen - 1] == sign {
        xlen -= 1;
    }
    if xlen == 0 {
        0
    } else {
        ((xlen - 1) as u32) * 31 + bitlength(x[xlen - 1] ^ sign)
    }
}

pub(crate) fn zint_get_top(x: &[u32], sc: u32) -> i64 {
    if x.is_empty() {
        return 0;
    }
    let sign = 0u32.wrapping_sub(x[x.len() - 1] >> 30);
    let k = (sc / 31) as usize;
    let off = sc - 31 * (k as u32);
    let (w0, w1, w2) = if (k + 2) < x.len() {
        (x[k], x[k + 1], x[k + 2] | (sign << 31))
    } else if (k + 1) < x.len() {
        (x[k], x[k + 1], sign)
    } else if k < x.len() {
        (x[k], sign, sign)
    } else {
        (sign, sign, sign)
    };
    let z = ((w0 as u64) >> off) | ((w1 as u64) << (31 - off)) | ((w2 as u64) << (62 - off));
    z as i64
}

pub(crate) fn zint_add_scaled_mul_small(
    x: &mut [u32],
    y: &[u32],
    ylen: usize,
    k: i32,
    sch: u32,
    scl: u32,
) {
    if ylen == 0 {
        return;
    }
    let ysign = if (y[ylen - 1] >> 30) != 0 { MASK31 } else { 0 };
    let mut tw = 0u32;
    let mut cc = 0i32;
    for (u, xw) in x.iter_mut().enumerate().skip(sch as usize) {
        let v = u - sch as usize;
        let wy = if v < ylen { y[v] } else { ysign };
        let wys = ((wy << scl) & MASK31) | tw;
        tw = if scl == 0 { 0 } else { wy >> (31 - scl) };
        let z = wys as i64 * k as i64 + *xw as i64 + cc as i64;
        *xw = (z as u32) & MASK31;
        cc = (z >> 31) as i32;
    }
}

pub(crate) fn zint_sub_scaled(x: &mut [u32], y: &[u32], ylen: usize, sch: u32, scl: u32) {
    if ylen == 0 {
        return;
    }
    let ysign = if (y[ylen - 1] >> 30) != 0 { MASK31 } else { 0 };
    let mut tw = 0u32;
    let mut cc = 0u32;
    for (u, xw) in x.iter_mut().enumerate().skip(sch as usize) {
        let v = u - sch as usize;
        let wy = if v < ylen { y[v] } else { ysign };
        let wys = ((wy << scl) & MASK31) | tw;
        tw = if scl == 0 { 0 } else { wy >> (31 - scl) };
        let w = xw.wrapping_sub(wys).wrapping_sub(cc);
        *xw = w & MASK31;
        cc = w >> 31;
    }
}

pub(crate) fn zint_one_to_plain(x: &[u32]) -> i32 {
    let mut w = x[0];
    w |= (w & 0x4000_0000) << 1;
    w as i32
}

#[cfg(test)]
mod tests {
    use super::{
        bitlength, zint_add, zint_bezout, zint_exact_length, zint_get_top, zint_mod_small_signed,
        zint_mod_small_unsigned, zint_mul_small, zint_one_to_plain, zint_rebuild_crt,
        zint_signed_bit_length, zint_sub,
    };
    use crate::math::modp::{modp_ninv31, modp_r2, modp_rx};
    use crate::math::primes::PRIMES2;

    fn limbs_from_i128(mut x: i128, len: usize) -> Vec<u32> {
        let negative = x < 0;
        if negative {
            x = -x;
        }
        let mut out = vec![0u32; len];
        let mut ux = x as u128;
        for w in &mut out {
            *w = (ux as u32) & 0x7FFF_FFFF;
            ux >>= 31;
        }
        if negative {
            let mut carry = 1u32;
            for w in &mut out {
                let nw = carry.wrapping_add(!*w);
                *w = nw & 0x7FFF_FFFF;
                carry = (!nw) >> 31;
            }
        }
        out
    }

    fn i128_from_unsigned_limbs(x: &[u32]) -> i128 {
        let mut acc = 0i128;
        for &w in x.iter().rev() {
            acc = (acc << 31) | i128::from(w);
        }
        acc
    }

    fn i128_from_signed_limbs(x: &[u32]) -> i128 {
        if x.is_empty() {
            return 0;
        }
        let negative = (x[x.len() - 1] >> 30) != 0;
        if !negative {
            return i128_from_unsigned_limbs(x);
        }
        let mut tmp = x.to_vec();
        let mut carry = 1u32;
        for w in &mut tmp {
            let nw = carry.wrapping_add(!*w);
            *w = nw & 0x7FFF_FFFF;
            carry = (!nw) >> 31;
        }
        -(i128_from_unsigned_limbs(&tmp))
    }

    #[test]
    fn add_sub_and_mul_small_match_i128() {
        let a = 123_456_789_012_345i128;
        let b = 98_765_432_101i128;
        let mut aa = limbs_from_i128(a, 4);
        let bb = limbs_from_i128(b, 4);

        assert_eq!(zint_add(&mut aa, &bb), 0);
        assert_eq!(i128_from_unsigned_limbs(&aa), a + b);

        assert_eq!(zint_sub(&mut aa, &bb), 0);
        assert_eq!(i128_from_unsigned_limbs(&aa), a);

        let carry = zint_mul_small(&mut aa[..3], 17);
        let product = a * 17;
        let expected = limbs_from_i128(product, 4);
        assert_eq!(carry, expected[3]);
        assert_eq!(&aa[..3], &expected[..3]);
    }

    #[test]
    fn mod_small_signed_and_unsigned_match_reference_arithmetic() {
        let x = limbs_from_i128(-1_234_567_890_123i128, 4);
        let p = PRIMES2[5].p;
        let p0i = modp_ninv31(p);
        let r2 = modp_r2(p, p0i);
        let rx = modp_rx(x.len() as u32, p, p0i, r2);

        let signed = zint_mod_small_signed(&x, p, p0i, r2, rx);
        let unsigned = zint_mod_small_unsigned(&x, p, p0i, r2);
        let xv = i128_from_signed_limbs(&x);
        let expected_signed = ((xv % i128::from(p)) + i128::from(p)) % i128::from(p);
        let expected_unsigned = i128_from_unsigned_limbs(&x) % i128::from(p);

        assert_eq!(signed, expected_signed as u32);
        assert_eq!(unsigned, expected_unsigned as u32);
    }

    #[test]
    fn rebuild_crt_roundtrips_small_signed_values() {
        let values = [-45_678i128, 12_345i128, -7i128, 0i128];
        let xlen = 3usize;
        let mut residues = vec![0u32; values.len() * xlen];

        for (u, &value) in values.iter().enumerate() {
            for v in 0..xlen {
                let p = PRIMES2[v].p as i128;
                residues[u * xlen + v] = value.rem_euclid(p) as u32;
            }
        }

        zint_rebuild_crt(&mut residues, xlen, xlen, values.len(), true);

        for (u, &value) in values.iter().enumerate() {
            let got = i128_from_signed_limbs(&residues[u * xlen..u * xlen + xlen]);
            assert_eq!(got, value);
        }
    }

    #[test]
    fn bezout_returns_coefficients_for_odd_inputs() {
        let x = limbs_from_i128(1_234_567, 3);
        let y = limbs_from_i128(7_654_321, 3);
        let (u, v) = zint_bezout(&x, &y).expect("odd coprime inputs");
        let ux = i128_from_unsigned_limbs(&u);
        let vx = i128_from_unsigned_limbs(&v);
        let lhs = ux * 1_234_567i128 - vx * 7_654_321i128;
        assert_eq!(lhs, 1);
    }

    #[test]
    fn bit_helpers_match_reference_shapes() {
        let signed = limbs_from_i128(-123_456_789, 3);
        assert_eq!(bitlength(0), 0);
        assert_eq!(bitlength(1), 1);
        assert_eq!(bitlength(0x4000_0000), 31);
        assert_eq!(zint_exact_length(&[1, 2, 0, 0]), 2);
        assert_eq!(zint_signed_bit_length(&signed), 27);
        assert_eq!(zint_one_to_plain(&[0x7FFF_FFFE]), -2);
        assert_eq!(zint_get_top(&signed, 0), -123_456_789);
    }
}
