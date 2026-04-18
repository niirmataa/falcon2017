//! Strict signing sampler following the Falcon/Extra `SAMPLER_CDF=1`
//! and `CT_BEREXP=1` path.

use crate::math::fpr::ref_f64::{
    fpr_div, fpr_exp_small, fpr_floor, fpr_inv, fpr_mul, fpr_neg, fpr_of, fpr_rint, fpr_sqr,
    fpr_sub, Fpr, FPR_LOG2, FPR_P55,
};
use crate::rng::prng::Prng;

#[derive(Clone, Copy)]
struct Z128 {
    hi: u64,
    lo: u64,
}

const CDF: [Z128; 27] = [
    Z128 {
        hi: 12_311_384_997_445_461_060,
        lo: 1_164_166_488_924_346_079,
    },
    Z128 {
        hi: 6_896_949_616_398_116_699,
        lo: 12_764_548_512_970_285_063,
    },
    Z128 {
        hi: 3_175_666_228_297_764_653,
        lo: 3_821_523_381_717_377_694,
    },
    Z128 {
        hi: 1_183_806_766_059_182_243,
        lo: 9_659_191_409_195_894_253,
    },
    Z128 {
        hi: 353_476_207_714_659_138,
        lo: 11_568_890_547_115_288_740,
    },
    Z128 {
        hi: 83_907_343_225_073_545,
        lo: 8_467_089_641_975_205_687,
    },
    Z128 {
        hi: 15_749_660_485_982_248,
        lo: 2_564_667_606_477_951_368,
    },
    Z128 {
        hi: 2_328_616_999_791_799,
        lo: 9_676_146_345_336_721_991,
    },
    Z128 {
        hi: 270_433_320_942_720,
        lo: 2_935_538_500_327_714_828,
    },
    Z128 {
        hi: 24_618_334_939_657,
        lo: 15_160_816_743_013_190_466,
    },
    Z128 {
        hi: 1_753_979_576_256,
        lo: 10_774_725_962_424_838_880,
    },
    Z128 {
        hi: 97_691_228_987,
        lo: 260_573_317_676_966_082,
    },
    Z128 {
        hi: 4_249_834_528,
        lo: 17_953_183_039_089_978_228,
    },
    Z128 {
        hi: 144_306_182,
        lo: 18_293_121_091_792_460_987,
    },
    Z128 {
        hi: 3_822_728,
        lo: 5_847_176_767_326_442_802,
    },
    Z128 {
        hi: 78_971,
        lo: 1_092_095_764_737_208_072,
    },
    Z128 {
        hi: 1_271,
        lo: 15_793_321_684_841_757_645,
    },
    Z128 {
        hi: 15,
        lo: 17_810_511_485_592_413_461,
    },
    Z128 {
        hi: 0,
        lo: 2_881_005_946_479_451_579,
    },
    Z128 {
        hi: 0,
        lo: 21_959_492_827_510_209,
    },
    Z128 {
        hi: 0,
        lo: 130_403_777_780_196,
    },
    Z128 {
        hi: 0,
        lo: 603_269_596_717,
    },
    Z128 {
        hi: 0,
        lo: 2_173_991_748,
    },
    Z128 {
        hi: 0,
        lo: 6_102_497,
    },
    Z128 { hi: 0, lo: 13_343 },
    Z128 { hi: 0, lo: 23 },
    Z128 { hi: 0, lo: 0 },
];

fn gaussian0_sampler_ct(prng: &mut Prng) -> i32 {
    let hi = prng.get_u64();
    let lo = prng.get_u64();
    for (z, cdf) in CDF.iter().enumerate() {
        if hi > cdf.hi || (hi == cdf.hi && lo >= cdf.lo) {
            return z as i32;
        }
    }
    unreachable!("CDF terminator must be reached");
}

fn ber_exp_ct(prng: &mut Prng, x: Fpr) -> bool {
    let s = fpr_floor(fpr_div(x, FPR_LOG2));
    let r = fpr_sub(x, fpr_mul(fpr_of(s), FPR_LOG2));

    let mut sw = s as u32;
    sw ^= (sw ^ 63) & 0u32.wrapping_sub((63u32.wrapping_sub(sw)) >> 31);

    let z = fpr_rint(fpr_mul(fpr_exp_small(fpr_neg(r)), FPR_P55)) as u64;

    let mut w = prng.get_u64();
    w ^= (w >> sw) << sw;
    let mut b = 1 - (((w | w.wrapping_neg()) >> 63) as i32);

    let mut w = prng.get_u64();
    w &= (1u64 << 55) - 1;
    b &= ((w.wrapping_sub(z)) >> 63) as i32;
    b != 0
}

pub(crate) fn sample_binary_ct(prng: &mut Prng, mu: Fpr, sigma: Fpr) -> i32 {
    let s = fpr_floor(mu);
    let r = fpr_sub(mu, fpr_of(s));
    let dss = fpr_inv(fpr_mul(fpr_sqr(sigma), fpr_of(2)));

    loop {
        let z0 = gaussian0_sampler_ct(prng);
        let b = i32::from(prng.get_u8() & 1);
        let z = b + ((b << 1) - 1) * z0;
        let zb = z - b;

        let mut x = fpr_mul(fpr_sqr(fpr_sub(fpr_of(i64::from(z)), r)), dss);
        x = fpr_sub(x, fpr_div(fpr_of(i64::from(zb * zb)), fpr_of(8)));
        if ber_exp_ct(prng, x) {
            return s as i32 + z;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ber_exp_ct, gaussian0_sampler_ct, sample_binary_ct};
    use crate::math::fpr::ref_f64::fpr;
    use crate::rng::prng::{Prng, PRNG_CHACHA20};
    use crate::rng::shake256::ShakeContext;

    fn prng_from_seed(seed: &[u8]) -> Prng {
        let mut shake = ShakeContext::shake256();
        shake.inject(seed);
        shake.flip();
        Prng::new(&mut shake, PRNG_CHACHA20).expect("portable PRNG available")
    }

    #[test]
    fn gaussian0_sampler_ct_uses_constant_rng_budget() {
        let mut prng = prng_from_seed(b"falcon2017-step25-gaussian");
        let before = prng.ptr;
        let sample = gaussian0_sampler_ct(&mut prng);
        let after = prng.ptr;

        assert_eq!(after.wrapping_sub(before), 16);
        assert_eq!(sample, 1);
    }

    #[test]
    fn ber_exp_ct_uses_constant_rng_budget() {
        let mut prng = prng_from_seed(b"falcon2017-step25-berexp");
        let before = prng.ptr;
        let keep = ber_exp_ct(&mut prng, fpr(0.4375));
        let after = prng.ptr;

        assert_eq!(after.wrapping_sub(before), 16);
        assert!(!keep);
    }

    #[test]
    fn strict_sampler_regression_sequence_is_stable() {
        let mut prng = prng_from_seed(b"falcon2017-step25-sampler-sequence");
        let mu = fpr(1.375);
        let sigma = fpr(1.8205);

        let got = [
            sample_binary_ct(&mut prng, mu, sigma),
            sample_binary_ct(&mut prng, mu, sigma),
            sample_binary_ct(&mut prng, mu, sigma),
            sample_binary_ct(&mut prng, mu, sigma),
            sample_binary_ct(&mut prng, mu, sigma),
            sample_binary_ct(&mut prng, mu, sigma),
        ];

        assert_eq!(got, [0, 0, 2, 1, 4, -1]);
    }
}
