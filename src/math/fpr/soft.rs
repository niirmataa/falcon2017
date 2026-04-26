//! Integer-only binary64 emulation for the strict constant-time backend.

const SIGN_MASK: u64 = 1u64 << 63;
const EXP_MASK: u64 = 0x7ff0_0000_0000_0000;
const FRAC_MASK: u64 = 0x000f_ffff_ffff_ffff;

const POS_ZERO_BITS: u64 = 0x0000_0000_0000_0000;
const POS_INF_BITS: u64 = 0x7ff0_0000_0000_0000;
const ONE_BITS: u64 = 0x3ff0_0000_0000_0000;
const TWO_BITS: u64 = 0x4000_0000_0000_0000;

const P1_BITS: u64 = 0x3fc5_5555_5555_553e;
const P2_BITS: u64 = 0xbf66_c16c_16be_bd93;
const P3_BITS: u64 = 0x3f11_566a_af25_de2c;
const P4_BITS: u64 = 0xbebb_bd41_c5d2_6bf1;
const P5_BITS: u64 = 0x3e66_3769_72be_a4d0;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FprSoft {
    bits: u64,
}

pub(crate) type Fpr = FprSoft;

#[derive(Clone, Copy, Debug)]
struct Decoded {
    sign: bool,
    sig: u64,
    exp: i32,
}

impl FprSoft {
    pub(crate) const fn from_bits(bits: u64) -> Self {
        Self { bits }
    }

    pub(crate) const fn bits(self) -> u64 {
        self.bits
    }

    const fn sign(self) -> bool {
        (self.bits & SIGN_MASK) != 0
    }

    const fn is_zero(self) -> bool {
        (self.bits & !SIGN_MASK) == 0
    }
}

const FPR_ZERO: Fpr = Fpr::from_bits(POS_ZERO_BITS);
const FPR_ONE: Fpr = Fpr::from_bits(ONE_BITS);
const FPR_TWO: Fpr = Fpr::from_bits(TWO_BITS);

pub(crate) const FPR_LOG2: Fpr = Fpr::from_bits(0x3fe6_2e42_fefa_39ef);
pub(crate) const FPR_P55: Fpr = Fpr::from_bits(0x4360_0000_0000_0000);
pub(crate) const FPR_P63: Fpr = Fpr::from_bits(0x43e0_0000_0000_0000);
pub(crate) const FPR_P64: Fpr = Fpr::from_bits(0x43f0_0000_0000_0000);

pub(crate) const FPR_W1R: Fpr = Fpr::from_bits(0x3fe0_0000_0000_0000);
pub(crate) const FPR_W1I: Fpr = Fpr::from_bits(0x3feb_b67a_e858_4caa);
pub(crate) const FPR_W2R: Fpr = Fpr::from_bits(0xbfe0_0000_0000_0000);
pub(crate) const FPR_W2I: Fpr = Fpr::from_bits(0x3feb_b67a_e858_4caa);
pub(crate) const FPR_W4R: Fpr = Fpr::from_bits(0xbfe0_0000_0000_0000);
pub(crate) const FPR_W4I: Fpr = Fpr::from_bits(0xbfeb_b67a_e858_4caa);
pub(crate) const FPR_W5R: Fpr = Fpr::from_bits(0x3fe0_0000_0000_0000);
pub(crate) const FPR_W5I: Fpr = Fpr::from_bits(0xbfeb_b67a_e858_4caa);
pub(crate) const FPR_IW1I: Fpr = Fpr::from_bits(0x3ff2_79a7_4590_331c);

const FPR_P1: Fpr = Fpr::from_bits(P1_BITS);
const FPR_P2: Fpr = Fpr::from_bits(P2_BITS);
const FPR_P3: Fpr = Fpr::from_bits(P3_BITS);
const FPR_P4: Fpr = Fpr::from_bits(P4_BITS);
const FPR_P5: Fpr = Fpr::from_bits(P5_BITS);

fn abs_i64_to_u64(i: i64) -> u64 {
    let x = i as u64;
    let mask = (i >> 63) as u64;
    (x ^ mask).wrapping_sub(mask)
}

fn ct_mask_u64(take: bool) -> u64 {
    0u64.wrapping_sub(u64::from(take))
}

fn ct_select_u64(a: u64, b: u64, take_b: bool) -> u64 {
    a ^ ((a ^ b) & ct_mask_u64(take_b))
}

fn ct_select_u128(a: u128, b: u128, take_b: bool) -> u128 {
    let mask = 0u128.wrapping_sub(u128::from(take_b));
    a ^ ((a ^ b) & mask)
}

fn ct_select_u32(a: u32, b: u32, take_b: bool) -> u32 {
    ct_select_u64(u64::from(a), u64::from(b), take_b) as u32
}

fn ct_select_i32(a: i32, b: i32, take_b: bool) -> i32 {
    ct_select_u32(a as u32, b as u32, take_b) as i32
}

fn ct_select_i64(a: i64, b: i64, take_b: bool) -> i64 {
    ct_select_u64(a as u64, b as u64, take_b) as i64
}

fn ct_select_fpr(a: Fpr, b: Fpr, take_b: bool) -> Fpr {
    Fpr::from_bits(ct_select_u64(a.bits(), b.bits(), take_b))
}

fn i64_from_mag_sat(sign: bool, mag: u128) -> i64 {
    let pos = ct_select_i64(mag as i64, i64::MAX, mag > i64::MAX as u128);
    let neg = ct_select_i64((mag as u64).wrapping_neg() as i64, i64::MIN, mag >= (1u128 << 63));
    ct_select_i64(pos, neg, sign)
}

fn shr_sticky_u64(x: u64, shift: u32) -> u64 {
    let s = shift & 63;
    let ge64 = ct_mask_u64(shift >= 64);
    let mask = ((1u64 << s).wrapping_sub(1)) | ge64;
    let hi = (x >> s) & !ge64;
    hi | u64::from((x & mask) != 0)
}

fn shr_sticky_u128_in_range(x: u128, shift: u32) -> u128 {
    debug_assert!((1..128).contains(&shift));
    let mask = (1u128 << shift) - 1;
    let lost = x & mask;
    let hi = x >> shift;
    hi | u128::from(lost != 0)
}

fn round_shift_right_even_u64(x: u64, shift: u32) -> u64 {
    let s = shift & 63;
    let hi = x >> s;
    let mask = (1u64 << s).wrapping_sub(1);
    let lo = x & mask;
    let half = 1u64 << ((s.wrapping_sub(1)) & 63);
    let inc = (lo > half) | ((lo == half) & ((hi & 1) != 0));
    ct_select_u64(hi.wrapping_add(u64::from(inc)), 0, shift >= 64)
}

fn ct_max_i32_zero(x: i32) -> u32 {
    (x & !(x >> 31)) as u32
}

fn decode(x: Fpr) -> Decoded {
    let sign = x.sign();
    let exp_bits = ((x.bits() & EXP_MASK) >> 52) as i32;
    let frac = x.bits() & FRAC_MASK;
    let normal = exp_bits != 0;
    let subnormal = (!normal) & (frac != 0);
    Decoded {
        sign,
        sig: ct_select_u64(frac, (1u64 << 52) | frac, normal),
        exp: ct_select_i32(ct_select_i32(0, -1074, subnormal), exp_bits - 1075, normal),
    }
}

fn normalize53(d: Decoded) -> Decoded {
    let nonzero = d.sig != 0;
    let top = 63 - d.sig.leading_zeros() as i32;
    let shift = (52 - top) as u32;
    Decoded {
        sign: d.sign,
        sig: d.sig << shift,
        exp: ct_select_i32(d.exp, d.exp - shift as i32, nonzero),
    }
}

fn round_pack(sign: bool, exp2: i32, sig_ext: u64) -> Fpr {
    let sign_bits = u64::from(sign) << 63;
    let top = 63i32 - sig_ext.leading_zeros() as i32;
    let delta = top - 55;
    let right = ct_max_i32_zero(delta);
    let left = ct_max_i32_zero(-delta);
    let sig_right = shr_sticky_u64(sig_ext, right);
    let sig_left = sig_ext << left;
    let sig_norm = ct_select_u64(sig_left, sig_right, delta > 0);
    let exp_norm = i64::from(exp2) + i64::from(delta);
    let e = exp_norm + 55;

    let mant0 = sig_norm >> 3;
    let rem = sig_norm & 7;
    let inc = (rem > 4) | ((rem == 4) & ((mant0 & 1) != 0));
    let mant1 = mant0.wrapping_add(u64::from(inc));
    let carry = mant1 >= (1u64 << 53);
    let mant = ct_select_u64(mant1, mant1 >> 1, carry);
    let e_rounded = e + i64::from(carry);
    let normal_bits = sign_bits | (((e_rounded + 1023) as u64) << 52) | (mant & FRAC_MASK);
    let inf_bits = sign_bits | POS_INF_BITS;
    let normal_or_inf = ct_select_u64(normal_bits, inf_bits, e_rounded > 1023);

    let sub_shift = (-1074i64 - exp_norm) as u32;
    let sub_frac = round_shift_right_even_u64(sig_norm, sub_shift);
    let sub_payload = ct_select_u64(sub_frac, 1u64 << 52, sub_frac >= (1u64 << 52));
    let sub_signed = sign_bits | sub_payload;
    let sub_bits = ct_select_u64(POS_ZERO_BITS, sub_signed, sub_frac != 0);

    let packed = ct_select_u64(sub_bits, normal_or_inf, e >= -1022);
    Fpr::from_bits(ct_select_u64(packed, POS_ZERO_BITS, sig_ext == 0))
}

fn add_decoded(x: Decoded, y: Decoded) -> Fpr {
    let x = normalize53(x);
    let y = normalize53(y);

    let sx = x.sig << 3;
    let sy = y.sig << 3;
    let x_exp_gt = x.exp > y.exp;
    let y_exp_gt = y.exp > x.exp;
    let exp_eq = x.exp == y.exp;
    let exp_delta = i64::from(x.exp) - i64::from(y.exp);
    let exp_diff = exp_delta.unsigned_abs() as u32;

    let sx_to_y = shr_sticky_u64(sx, exp_diff);
    let sy_to_x = shr_sticky_u64(sy, exp_diff);

    let same_sx = ct_select_u64(sx, sx_to_y, y_exp_gt);
    let same_sy = ct_select_u64(sy, sy_to_x, x_exp_gt);
    let same_exp = ct_select_i32(x.exp - 3, y.exp - 3, y_exp_gt);
    let same_sign = round_pack(x.sign, same_exp, same_sx + same_sy);

    let x_nonzero = x.sig != 0;
    let y_nonzero = y.sig != 0;
    let x_abs_gt = x_nonzero & ((!y_nonzero) | x_exp_gt | (exp_eq & (x.sig > y.sig)));
    let y_abs_gt = y_nonzero & ((!x_nonzero) | y_exp_gt | (exp_eq & (y.sig > x.sig)));
    let abs_eq = !(x_abs_gt | y_abs_gt);

    let x_minus_y = round_pack(x.sign, x.exp - 3, sx.wrapping_sub(sy_to_x));
    let y_minus_x = round_pack(y.sign, y.exp - 3, sy.wrapping_sub(sx_to_y));
    let diff_nonzero = ct_select_fpr(x_minus_y, y_minus_x, y_abs_gt);
    let diff_sign = ct_select_fpr(diff_nonzero, FPR_ZERO, abs_eq);

    ct_select_fpr(diff_sign, same_sign, x.sign == y.sign)
}

fn isqrt_u128(n: u128) -> u128 {
    let mut op = n;
    let mut res = 0u128;
    let mut one = 1u128 << 126;
    for _ in 0..64 {
        let trial = res + one;
        let take = op >= trial;
        op = ct_select_u128(op, op.wrapping_sub(trial), take);
        res = ct_select_u128(res >> 1, (res >> 1) + one, take);
        one >>= 2;
    }
    res
}

fn divrem_u128_ct(num: u128, den: u128) -> (u128, u128) {
    let mut q = 0u128;
    let mut r = 0u128;
    // fpr_div() shifts a 53-bit significand by at most 56 bits, so bit 108
    // is the highest possible numerator bit. The fixed scan avoids hardware
    // integer division, whose latency may depend on secret significands.
    for bit in (0..109).rev() {
        r = (r << 1) | ((num >> bit) & 1);
        let ge = r >= den;
        r = ct_select_u128(r, r.wrapping_sub(den), ge);
        q = (q << 1) | u128::from(ge);
    }
    (q, r)
}

pub(crate) fn fpr_of(i: i64) -> Fpr {
    round_pack(i < 0, 0, abs_i64_to_u64(i))
}

pub(crate) fn fpr_scaled(i: i64, sc: i32) -> Fpr {
    round_pack(i < 0, sc, abs_i64_to_u64(i))
}

pub(crate) fn fpr_inverse_of(i: i64) -> Fpr {
    fpr_div(FPR_ONE, fpr_of(i))
}

pub(crate) fn fpr_rint(x: Fpr) -> i64 {
    let d = decode(x);
    let exp_nonneg = d.exp >= 0;

    let pos_shift = (d.exp as u32) & 127;
    let pos_mag = ct_select_u128((d.sig as u128) << pos_shift, u128::MAX, d.exp >= 128);

    let shift = d.exp.wrapping_neg() as u32;
    let s = shift & 63;
    let ge64 = shift >= 64;
    let ge64_mask = ct_mask_u64(ge64);
    let int_part = (d.sig >> s) & !ge64_mask;
    let mask = (1u64 << s).wrapping_sub(1);
    let rem = (d.sig & mask) & !ge64_mask;
    let half = 1u64 << ((s.wrapping_sub(1)) & 63);
    let inc = (rem > half) | ((rem == half) & ((int_part & 1) != 0));
    let neg_mag = int_part as u128 + u128::from(inc & !ge64);

    i64_from_mag_sat(d.sign, ct_select_u128(neg_mag, pos_mag, exp_nonneg))
}

pub(crate) fn fpr_floor(x: Fpr) -> i64 {
    let d = decode(x);
    let exp_nonneg = d.exp >= 0;

    let pos_shift = (d.exp as u32) & 127;
    let pos_mag = ct_select_u128((d.sig as u128) << pos_shift, u128::MAX, d.exp >= 128);

    let shift = d.exp.wrapping_neg() as u32;
    let s = shift & 63;
    let ge64_mask = ct_mask_u64(shift >= 64);
    let int_part = (d.sig >> s) & !ge64_mask;
    let mask = ((1u64 << s).wrapping_sub(1)) | ge64_mask;
    let frac = d.sig & mask;
    let neg_mag = int_part as u128 + u128::from(d.sign && frac != 0);

    i64_from_mag_sat(d.sign, ct_select_u128(neg_mag, pos_mag, exp_nonneg))
}

pub(crate) fn fpr_add(x: Fpr, y: Fpr) -> Fpr {
    let dx = decode(x);
    let dy = decode(y);
    let both_zero = x.is_zero() && y.is_zero();
    let both_zero_result = Fpr::from_bits(ct_select_u64(POS_ZERO_BITS, SIGN_MASK, x.sign() && y.sign()));
    let result = ct_select_fpr(add_decoded(dx, dy), y, dx.sig == 0);
    let result = ct_select_fpr(result, x, dy.sig == 0);
    ct_select_fpr(result, both_zero_result, both_zero)
}

pub(crate) fn fpr_sub(x: Fpr, y: Fpr) -> Fpr {
    let dx = decode(x);
    let dy = decode(y);
    let neg_y = fpr_neg(y);
    let both_zero = x.is_zero() && y.is_zero();
    let both_zero_result = Fpr::from_bits(ct_select_u64(POS_ZERO_BITS, SIGN_MASK, x.sign() && !y.sign()));
    let result = add_decoded(
        dx,
        Decoded {
            sign: !dy.sign,
            ..dy
        },
    );
    let result = ct_select_fpr(result, neg_y, dx.sig == 0);
    let result = ct_select_fpr(result, x, dy.sig == 0);
    ct_select_fpr(result, both_zero_result, both_zero)
}

pub(crate) fn fpr_neg(x: Fpr) -> Fpr {
    Fpr::from_bits(x.bits() ^ SIGN_MASK)
}

pub(crate) fn fpr_half(x: Fpr) -> Fpr {
    let d = decode(x);
    ct_select_fpr(round_pack(d.sign, d.exp - 1, d.sig), x, d.sig == 0)
}

pub(crate) fn fpr_double(x: Fpr) -> Fpr {
    let d = decode(x);
    ct_select_fpr(round_pack(d.sign, d.exp + 1, d.sig), x, d.sig == 0)
}

pub(crate) fn fpr_mul(x: Fpr, y: Fpr) -> Fpr {
    let dx = normalize53(decode(x));
    let dy = normalize53(decode(y));
    let sign = dx.sign ^ dy.sign;
    let prod = (dx.sig as u128) * (dy.sig as u128);
    let shift = ct_select_u32(49, 50, prod >= (1u128 << 105));
    let sig_ext = shr_sticky_u128_in_range(prod, shift) as u64;
    let result = round_pack(sign, dx.exp + dy.exp + shift as i32, sig_ext);
    ct_select_fpr(result, Fpr::from_bits(u64::from(sign) << 63), (dx.sig == 0) || (dy.sig == 0))
}

pub(crate) fn fpr_sqr(x: Fpr) -> Fpr {
    fpr_mul(x, x)
}

pub(crate) fn fpr_inv(x: Fpr) -> Fpr {
    fpr_div(FPR_ONE, x)
}

pub(crate) fn fpr_div(x: Fpr, y: Fpr) -> Fpr {
    let dx = normalize53(decode(x));
    let dy = normalize53(decode(y));
    let sign = dx.sign ^ dy.sign;

    // Produce a 56-bit extended significand directly in the range expected by
    // round_pack(): [2^55, 2^56). This preserves the exact quotient scale and
    // leaves the low bits of q available as round/sticky bits.
    let shift = ct_select_u32(55, 56, dx.sig < dy.sig);
    let num = (dx.sig as u128) << shift;
    let den = ct_select_u64(dy.sig, 1, dy.sig == 0) as u128;
    let (q, r) = divrem_u128_ct(num, den);
    let sig_ext = (q as u64) | u64::from(r != 0);
    let result = round_pack(sign, dx.exp - dy.exp - shift as i32, sig_ext);
    let result = ct_select_fpr(result, Fpr::from_bits((u64::from(sign) << 63) | POS_INF_BITS), dy.sig == 0);
    ct_select_fpr(result, Fpr::from_bits(u64::from(sign) << 63), dx.sig == 0)
}

pub(crate) fn fpr_sqrt(x: Fpr) -> Fpr {
    let dx = normalize53(decode(x));
    let odd_exp = (dx.exp & 1) != 0;
    let sig = ct_select_u64(dx.sig, dx.sig << 1, odd_exp);
    let exp = ct_select_i32(dx.exp, dx.exp - 1, odd_exp);
    let num = (sig as u128) << 58;
    let root0 = isqrt_u128(num);
    let root = root0 | u128::from(root0 * root0 != num);
    let result = round_pack(false, (exp >> 1) - 29, root as u64);
    let result = ct_select_fpr(result, FPR_ZERO, dx.sign);
    ct_select_fpr(result, x, dx.sig == 0)
}

pub(crate) fn fpr_max(x: Fpr, y: Fpr) -> Fpr {
    let result = ct_select_fpr(x, y, fpr_lt(x, y));
    ct_select_fpr(result, FPR_ZERO, x.is_zero() && y.is_zero())
}

pub(crate) fn fpr_lt(x: Fpr, y: Fpr) -> bool {
    let x_zero = x.is_zero();
    let y_zero = y.is_zero();
    let both_zero = x_zero & y_zero;
    let x_sign = x.sign();
    let y_sign = y.sign();
    let sign_diff = x_sign ^ y_sign;

    let dx = normalize53(decode(x));
    let dy = normalize53(decode(y));
    let x_nonzero = dx.sig != 0;
    let y_nonzero = dy.sig != 0;
    let x_exp_gt = dx.exp > dy.exp;
    let y_exp_gt = dy.exp > dx.exp;
    let exp_eq = dx.exp == dy.exp;
    let x_abs_gt = x_nonzero & ((!y_nonzero) | x_exp_gt | (exp_eq & (dx.sig > dy.sig)));
    let y_abs_gt = y_nonzero & ((!x_nonzero) | y_exp_gt | (exp_eq & (dy.sig > dx.sig)));

    let same_sign_lt = (x_sign & x_abs_gt) | ((!x_sign) & y_abs_gt);
    let sign_diff_lt = x_sign;
    ((!both_zero) & sign_diff & sign_diff_lt) | ((!both_zero) & (!sign_diff) & same_sign_lt)
}

pub(crate) fn fpr_exp_small(x: Fpr) -> Fpr {
    let mut s = fpr_half(x);
    let t = fpr_sqr(s);
    let c = fpr_sub(
        s,
        fpr_mul(
            t,
            fpr_add(
                FPR_P1,
                fpr_mul(
                    t,
                    fpr_add(
                        FPR_P2,
                        fpr_mul(
                            t,
                            fpr_add(FPR_P3, fpr_mul(t, fpr_add(FPR_P4, fpr_mul(t, FPR_P5)))),
                        ),
                    ),
                ),
            ),
        ),
    );
    s = fpr_sub(
        FPR_ONE,
        fpr_sub(fpr_div(fpr_mul(s, c), fpr_sub(c, FPR_TWO)), s),
    );
    fpr_sqr(s)
}

#[cfg(test)]
mod tests {
    use super::{
        fpr_add, fpr_div, fpr_double, fpr_exp_small, fpr_floor, fpr_half, fpr_inv, fpr_inverse_of,
        fpr_lt, fpr_max, fpr_mul, fpr_neg, fpr_of, fpr_rint, fpr_scaled, fpr_sqr, fpr_sqrt,
        fpr_sub, Fpr, FPR_IW1I, FPR_LOG2, FPR_P55, FPR_P63, FPR_P64, FPR_W1I, FPR_W1R, FPR_W2I,
        FPR_W2R, FPR_W4I, FPR_W4R, FPR_W5I, FPR_W5R,
    };
    use crate::math::fpr::ref_f64;

    fn f64_of(x: Fpr) -> f64 {
        f64::from_bits(x.bits())
    }

    fn from_f64(x: f64) -> Fpr {
        Fpr::from_bits(x.to_bits())
    }

    #[test]
    fn reviewed_branch_patterns_stay_removed() {
        let src = include_str!("soft.rs");
        assert!(!src.contains(concat!("fn ", "cmp_abs_decoded")));
        assert!(!src.contains(concat!("let shift = if pro", "d >=")));
        assert!(!src.contains(concat!("let shift = if dx.", "sig < dy.sig")));
        assert!(!src.contains(concat!("if shift ", "== 0")));
        assert!(!src.contains(concat!("if shift ", ">= 64")));
        assert!(src.contains(concat!("ct_select_u32", "(49, 50")));
        assert!(src.contains(concat!("ct_select_u32", "(55, 56")));
        assert!(src.contains("divrem_u128_ct"));
        assert!(!src.contains(concat!("num ", "/ den")));
        assert!(!src.contains(concat!("num ", "% den")));

        let production_end = src.find(concat!("#[", "cfg(test)]")).unwrap();
        let production = &src[..production_end];
        assert!(!production.contains(concat!("if", " ")));
        assert!(!production.contains(concat!("while", " ")));
        assert!(!production.contains(concat!("match", " ")));
        assert!(!production.contains(concat!("return", " ")));
        assert!(!production.contains(" / "));
        assert!(!production.contains(" % "));
    }

    #[test]
    fn scalar_constants_match_reference_bits() {
        assert_eq!(FPR_LOG2.bits(), 0x3fe6_2e42_fefa_39ef);
        assert_eq!(FPR_P55.bits(), 0x4360_0000_0000_0000);
        assert_eq!(FPR_P63.bits(), 0x43e0_0000_0000_0000);
        assert_eq!(FPR_P64.bits(), 0x43f0_0000_0000_0000);
        assert_eq!(FPR_W1R.bits(), 0x3fe0_0000_0000_0000);
        assert_eq!(FPR_W1I.bits(), 0x3feb_b67a_e858_4caa);
        assert_eq!(FPR_W2R.bits(), 0xbfe0_0000_0000_0000);
        assert_eq!(FPR_W2I.bits(), 0x3feb_b67a_e858_4caa);
        assert_eq!(FPR_W4R.bits(), 0xbfe0_0000_0000_0000);
        assert_eq!(FPR_W4I.bits(), 0xbfeb_b67a_e858_4caa);
        assert_eq!(FPR_W5R.bits(), 0x3fe0_0000_0000_0000);
        assert_eq!(FPR_W5I.bits(), 0xbfeb_b67a_e858_4caa);
        assert_eq!(FPR_IW1I.bits(), 0x3ff2_79a7_4590_331c);
    }

    #[test]
    fn integer_conversions_match_native_binary64() {
        let ints = [
            i64::MIN,
            -9_223_372_036_854_775_000,
            -1_048_577,
            -17,
            -3,
            -1,
            0,
            1,
            3,
            17,
            1_048_577,
            9_223_372_036_854_775_000,
            i64::MAX,
        ];
        for i in ints {
            assert_eq!(fpr_of(i).bits(), (i as f64).to_bits(), "i={i}");
        }

        let cases = [
            (-17, -17),
            (-17, -3),
            (-17, 0),
            (-17, 19),
            (3, -7),
            (3, -1),
            (3, 0),
            (3, 9),
            (1_048_577, -12),
            (1_048_577, 0),
            (1_048_577, 12),
        ];
        for (i, sc) in cases {
            let expected = (i as f64) * 2.0f64.powi(sc);
            assert_eq!(
                fpr_scaled(i, sc).bits(),
                expected.to_bits(),
                "i={i}, sc={sc}"
            );
        }
    }

    #[test]
    fn arithmetic_matches_native_binary64_on_fixed_vectors() {
        let vals = [
            -1.0e100, -123456.75, -17.5, -3.0, -0.5, -0.0, 0.0, 0.5, 1.0, 1.25, 3.5, 17.75,
            123456.75, 1.0e100,
        ];

        for x in vals {
            let sx = from_f64(x);
            assert_eq!(fpr_neg(sx).bits(), (-x).to_bits(), "neg {x}");
            assert_eq!(fpr_half(sx).bits(), (x * 0.5).to_bits(), "half {x}");
            assert_eq!(fpr_double(sx).bits(), (x + x).to_bits(), "double {x}");
            assert_eq!(fpr_sqr(sx).bits(), (x * x).to_bits(), "sqr {x}");
            if x != 0.0 {
                assert_eq!(fpr_inv(sx).bits(), (1.0 / x).to_bits(), "inv {x}");
            }
        }

        for x in vals {
            for y in vals {
                let sx = from_f64(x);
                let sy = from_f64(y);
                assert_eq!(fpr_add(sx, sy).bits(), (x + y).to_bits(), "add {x} {y}");
                assert_eq!(fpr_sub(sx, sy).bits(), (x - y).to_bits(), "sub {x} {y}");
                assert_eq!(fpr_mul(sx, sy).bits(), (x * y).to_bits(), "mul {x} {y}");
                if y != 0.0 {
                    assert_eq!(fpr_div(sx, sy).bits(), (x / y).to_bits(), "div {x} {y}");
                }
            }
        }
    }

    #[test]
    fn sqrt_matches_native_binary64() {
        let vals = [0.0, 0.25, 0.5, 1.0, 2.0, 3.0, 81.0, 1.0e-20, 1.0e20];
        for x in vals {
            let sx = from_f64(x);
            assert_eq!(fpr_sqrt(sx).bits(), x.sqrt().to_bits(), "sqrt {x}");
        }
    }

    #[test]
    fn rounding_matches_reference_semantics() {
        let vals = [
            -10.75, -3.99, -3.5, -3.49, -2.5, -0.75, -0.5, -0.49, 0.0, 0.49, 0.5, 0.75, 2.5, 3.49,
            3.5, 3.99, 10.75,
        ];
        for x in vals {
            let sx = from_f64(x);
            assert_eq!(fpr_rint(sx), x.round_ties_even() as i64, "rint {x}");
            assert_eq!(fpr_floor(sx), x.floor() as i64, "floor {x}");
        }
        assert_eq!(fpr_inverse_of(8).bits(), 0.125f64.to_bits());
    }

    #[test]
    fn subtraction_with_signed_zero_preserves_operand_bits() {
        let pos = from_f64(1.161_602_574_801_729_8);
        assert_eq!(fpr_sub(pos, from_f64(0.0)).bits(), pos.bits());
        assert_eq!(fpr_sub(pos, from_f64(-0.0)).bits(), pos.bits());

        let neg = from_f64(-2.75);
        assert_eq!(fpr_sub(neg, from_f64(0.0)).bits(), neg.bits());
        assert_eq!(fpr_sub(neg, from_f64(-0.0)).bits(), neg.bits());

        assert_eq!(fpr_sub(from_f64(0.0), from_f64(3.5)).bits(), from_f64(-3.5).bits());
        assert_eq!(fpr_sub(from_f64(-0.0), from_f64(3.5)).bits(), from_f64(-3.5).bits());
    }

    #[test]
    fn ordering_and_max_match_native_behavior() {
        let vals = [-17.5, -0.0, 0.0, 0.25, 0.5, 1.0, 9.0];
        for x in vals {
            for y in vals {
                let sx = from_f64(x);
                let sy = from_f64(y);
                assert_eq!(fpr_lt(sx, sy), x < y, "lt {x} {y}");
                let expected = if x == 0.0 && y == 0.0 { 0.0 } else { x.max(y) };
                assert_eq!(
                    f64_of(fpr_max(sx, sy)).to_bits(),
                    expected.to_bits(),
                    "max {x} {y}"
                );
            }
        }
    }

    #[test]
    fn exp_small_matches_ref_backend() {
        let samples = [
            -f64_of(FPR_LOG2),
            -0.625,
            -0.5,
            -0.25,
            -0.125,
            -0.0625,
            0.0,
            0.0625,
            0.125,
            0.25,
            0.5,
            0.625,
            f64_of(FPR_LOG2),
        ];

        for x in samples {
            let soft = fpr_exp_small(from_f64(x));
            let reference = ref_f64::fpr_exp_small(ref_f64::fpr(x));
            assert_eq!(soft.bits(), reference.v.to_bits(), "exp_small {x}");
        }
    }
}
