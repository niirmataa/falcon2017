//! Reference floating-point backend based on `f64`.

#[derive(Clone, Copy, Debug, Default, PartialEq, PartialOrd)]
pub(crate) struct Fpr {
    pub(crate) v: f64,
}

impl Fpr {
    pub(crate) const fn new(v: f64) -> Self {
        Self { v }
    }
}

pub(crate) const FPR_LOG2: Fpr = Fpr::new(0.693_147_180_559_945_3);
pub(crate) const FPR_P55: Fpr = Fpr::new(36_028_797_018_963_968.0);
pub(crate) const FPR_P63: Fpr = Fpr::new(9_223_372_036_854_776_000.0);
pub(crate) const FPR_P64: Fpr = Fpr::new(18_446_744_073_709_552_000.0);

pub(crate) const FPR_W1R: Fpr = Fpr::new(0.5);
pub(crate) const FPR_W1I: Fpr = Fpr::new(0.866_025_403_784_438_6);
pub(crate) const FPR_W2R: Fpr = Fpr::new(-0.5);
pub(crate) const FPR_W2I: Fpr = Fpr::new(0.866_025_403_784_438_6);
pub(crate) const FPR_W4R: Fpr = Fpr::new(-0.5);
pub(crate) const FPR_W4I: Fpr = Fpr::new(-0.866_025_403_784_438_6);
pub(crate) const FPR_W5R: Fpr = Fpr::new(0.5);
pub(crate) const FPR_W5I: Fpr = Fpr::new(-0.866_025_403_784_438_6);
pub(crate) const FPR_IW1I: Fpr = Fpr::new(1.154_700_538_379_251_5);

pub(crate) fn fpr(v: f64) -> Fpr {
    Fpr::new(v)
}

pub(crate) fn fpr_of(i: i64) -> Fpr {
    Fpr::new(i as f64)
}

pub(crate) fn fpr_scaled(i: i64, sc: i32) -> Fpr {
    Fpr::new((i as f64) * 2.0f64.powi(sc))
}

pub(crate) fn fpr_inverse_of(i: i64) -> Fpr {
    Fpr::new(1.0 / (i as f64))
}

pub(crate) fn fpr_rint(x: Fpr) -> i64 {
    x.v.round_ties_even() as i64
}

pub(crate) fn fpr_floor(x: Fpr) -> i64 {
    x.v.floor() as i64
}

pub(crate) fn fpr_add(x: Fpr, y: Fpr) -> Fpr {
    Fpr::new(x.v + y.v)
}

pub(crate) fn fpr_sub(x: Fpr, y: Fpr) -> Fpr {
    Fpr::new(x.v - y.v)
}

pub(crate) fn fpr_neg(x: Fpr) -> Fpr {
    Fpr::new(-x.v)
}

pub(crate) fn fpr_half(x: Fpr) -> Fpr {
    Fpr::new(x.v * 0.5)
}

pub(crate) fn fpr_double(x: Fpr) -> Fpr {
    Fpr::new(x.v + x.v)
}

pub(crate) fn fpr_mul(x: Fpr, y: Fpr) -> Fpr {
    Fpr::new(x.v * y.v)
}

pub(crate) fn fpr_sqr(x: Fpr) -> Fpr {
    Fpr::new(x.v * x.v)
}

pub(crate) fn fpr_inv(x: Fpr) -> Fpr {
    Fpr::new(1.0 / x.v)
}

pub(crate) fn fpr_div(x: Fpr, y: Fpr) -> Fpr {
    Fpr::new(x.v / y.v)
}

pub(crate) fn fpr_sqrt(x: Fpr) -> Fpr {
    Fpr::new(x.v.sqrt())
}

pub(crate) fn fpr_max(x: Fpr, y: Fpr) -> Fpr {
    Fpr::new(x.v.max(y.v))
}

pub(crate) fn fpr_lt(x: Fpr, y: Fpr) -> bool {
    x.v < y.v
}

pub(crate) fn fpr_exp_small(x: Fpr) -> Fpr {
    const FPR_P1: f64 = 1.666_666_666_666_660_2e-1;
    const FPR_P2: f64 = -2.777_777_777_701_559_3e-3;
    const FPR_P3: f64 = 6.613_756_321_437_934e-5;
    const FPR_P4: f64 = -1.653_390_220_546_525_2e-6;
    const FPR_P5: f64 = 4.138_136_797_057_238_5e-8;

    let mut s = x.v * 0.5;
    let t = s * s;
    let c = s - t * (FPR_P1 + t * (FPR_P2 + t * (FPR_P3 + t * (FPR_P4 + t * FPR_P5))));
    s = 1.0 - ((s * c) / (c - 2.0) - s);
    Fpr::new(s * s)
}

pub(crate) fn fpr_gauss(sigma: Fpr, a: u32, b: u32) -> (Fpr, Fpr) {
    let r = sigma.v * (-2.0 * (((a as f64) + 1.0) * 2.0f64.powi(-32)).ln()).sqrt();
    let phi = (((b as f64) + 1.0) * 2.0f64.powi(-32)) * core::f64::consts::TAU;
    (Fpr::new(r * phi.cos()), Fpr::new(r * phi.sin()))
}

#[cfg(test)]
mod tests {
    use super::{
        fpr, fpr_add, fpr_div, fpr_double, fpr_exp_small, fpr_floor, fpr_gauss, fpr_half, fpr_inv,
        fpr_inverse_of, fpr_lt, fpr_max, fpr_mul, fpr_neg, fpr_of, fpr_rint, fpr_scaled, fpr_sqr,
        fpr_sqrt, fpr_sub, FPR_IW1I, FPR_LOG2, FPR_P55, FPR_P63, FPR_P64, FPR_W1I, FPR_W1R,
        FPR_W2I, FPR_W2R, FPR_W4I, FPR_W4R, FPR_W5I, FPR_W5R,
    };

    fn assert_close(actual: f64, expected: f64, eps: f64) {
        let diff = (actual - expected).abs();
        assert!(
            diff <= eps,
            "actual={actual:?}, expected={expected:?}, diff={diff:?}, eps={eps:?}"
        );
    }

    #[test]
    fn scalar_constants_match_reference_values() {
        assert_close(FPR_LOG2.v, 0.693_147_180_559_945_3, 0.0);
        assert_eq!(FPR_P55.v, 2.0f64.powi(55));
        assert_eq!(FPR_P63.v, 2.0f64.powi(63));
        assert_eq!(FPR_P64.v, 2.0f64.powi(64));
        assert_eq!(FPR_W1R.v, 0.5);
        assert_eq!(FPR_W2R.v, -0.5);
        assert_eq!(FPR_W4R.v, -0.5);
        assert_eq!(FPR_W5R.v, 0.5);
        assert_close(FPR_W1I.v, 3.0f64.sqrt() * 0.5, 1e-15);
        assert_close(FPR_W2I.v, 3.0f64.sqrt() * 0.5, 1e-15);
        assert_close(FPR_W4I.v, -3.0f64.sqrt() * 0.5, 1e-15);
        assert_close(FPR_W5I.v, -3.0f64.sqrt() * 0.5, 1e-15);
        assert_close(FPR_IW1I.v, 2.0 / 3.0f64.sqrt(), 1e-15);
    }

    #[test]
    fn arithmetic_matches_reference_formulas() {
        let x = fpr(7.5);
        let y = fpr(-2.25);

        assert_eq!(fpr_of(-17).v, -17.0);
        assert_eq!(fpr_scaled(3, 4).v, 48.0);
        assert_eq!(fpr_scaled(3, -1).v, 1.5);
        assert_eq!(fpr_inverse_of(8).v, 0.125);
        assert_eq!(fpr_add(x, y).v, 5.25);
        assert_eq!(fpr_sub(x, y).v, 9.75);
        assert_eq!(fpr_neg(y).v, 2.25);
        assert_eq!(fpr_half(x).v, 3.75);
        assert_eq!(fpr_double(y).v, -4.5);
        assert_eq!(fpr_mul(x, y).v, -16.875);
        assert_eq!(fpr_sqr(y).v, 5.0625);
        assert_eq!(fpr_inv(fpr(4.0)).v, 0.25);
        assert_eq!(fpr_div(x, fpr(2.5)).v, 3.0);
        assert_eq!(fpr_sqrt(fpr(81.0)).v, 9.0);
        assert_eq!(fpr_max(x, y).v, 7.5);
        assert!(fpr_lt(y, x));
        assert!(!fpr_lt(x, y));
    }

    #[test]
    fn rounding_matches_llrint_and_floor_semantics() {
        assert_eq!(fpr_rint(fpr(2.5)), 2);
        assert_eq!(fpr_rint(fpr(3.5)), 4);
        assert_eq!(fpr_rint(fpr(-2.5)), -2);
        assert_eq!(fpr_rint(fpr(-3.5)), -4);
        assert_eq!(fpr_rint(fpr(3.49)), 3);
        assert_eq!(fpr_rint(fpr(-3.49)), -3);
        assert_eq!(fpr_floor(fpr(3.99)), 3);
        assert_eq!(fpr_floor(fpr(-3.01)), -4);
    }

    #[test]
    fn exp_small_matches_reference_range() {
        for x in [-FPR_LOG2.v, -0.5, -0.125, 0.0, 0.125, 0.5, FPR_LOG2.v] {
            assert_close(fpr_exp_small(fpr(x)).v, x.exp(), 1e-15);
        }
    }

    #[test]
    fn gauss_matches_box_muller_quarter_turn_case() {
        let sigma = fpr(2.0);
        let a = (1u32 << 31) - 1;
        let b = (1u32 << 30) - 1;
        let (re, im) = fpr_gauss(sigma, a, b);
        let expected_im = sigma.v * (2.0 * core::f64::consts::LN_2).sqrt();

        assert!(re.v.abs() <= 1e-12);
        assert_close(im.v, expected_im, 1e-12);
    }
}
