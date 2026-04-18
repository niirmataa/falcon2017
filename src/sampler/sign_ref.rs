//! Reference signing sampler.

use crate::math::fpr::ref_f64::{
    fpr_div, fpr_exp_small, fpr_floor, fpr_inv, fpr_mul, fpr_neg, fpr_of, fpr_rint, fpr_sqr,
    fpr_sub, Fpr, FPR_LOG2, FPR_P63,
};
use crate::rng::prng::Prng;

#[derive(Clone, Copy)]
struct Z128 {
    hi: u64,
    lo: u64,
}

const CDF8: [u8; 6] = [170, 95, 44, 16, 4, 1];

const CDFS: [Z128; 6] = [
    Z128 {
        hi: 15_768_066_815_414_256_656,
        lo: 2_878_715_985_279_770_247,
    },
    Z128 {
        hi: 13_178_414_795_510_471_601,
        lo: 2_650_718_273_802_340_096,
    },
    Z128 {
        hi: 1_313_815_201_007_480_117,
        lo: 632_549_813_042_453_946,
    },
    Z128 {
        hi: 7_906_626_931_797_828_486,
        lo: 889_294_877_069_012_273,
    },
    Z128 {
        hi: 16_702_932_880_114_533_024,
        lo: 10_156_928_267_985_658_938,
    },
    Z128 {
        hi: 3_033_535_791_909_276_021,
        lo: 9_305_891_721_635_116_763,
    },
];

const CDF0: [Z128; 22] = [
    Z128 {
        hi: 4_031_913_084_411_455_523,
        lo: 10_918_864_678_521_243_583,
    },
    Z128 {
        hi: 596_125_951_946_700_678,
        lo: 5_229_758_529_120_913_067,
    },
    Z128 {
        hi: 69_230_930_161_336_360,
        lo: 13_628_093_135_512_931_395,
    },
    Z128 {
        hi: 6_302_293_744_552_402,
        lo: 7_352_830_732_370_919_967,
    },
    Z128 {
        hi: 449_018_771_521_685,
        lo: 9_764_979_398_035_562_428,
    },
    Z128 {
        hi: 25_008_954_620_675,
        lo: 11_366_537_104_174_662_165,
    },
    Z128 {
        hi: 1_087_957_639_417,
        lo: 2_775_583_653_356_073_882,
    },
    Z128 {
        hi: 36_942_382_845,
        lo: 16_012_748_850_353_453_704,
    },
    Z128 {
        hi: 978_618_449,
        lo: 2_690_982_465_095_676_317,
    },
    Z128 {
        hi: 20_216_591,
        lo: 2_875_354_667_081_992_134,
    },
    Z128 {
        hi: 325_595,
        lo: 3_253_399_177_098_153_241,
    },
    Z128 {
        hi: 4_087,
        lo: 3_145_154_105_398_596_933,
    },
    Z128 {
        hi: 39,
        lo: 18_114_503_424_067_091_158,
    },
    Z128 {
        hi: 0,
        lo: 5_621_630_163_842_613_476,
    },
    Z128 {
        hi: 0,
        lo: 33_383_367_111_730_198,
    },
    Z128 {
        hi: 0,
        lo: 154_437_016_759_436,
    },
    Z128 {
        hi: 0,
        lo: 556_541_887_369,
    },
    Z128 {
        hi: 0,
        lo: 1_562_239_343,
    },
    Z128 {
        hi: 0,
        lo: 3_415_730,
    },
    Z128 { hi: 0, lo: 5_817 },
    Z128 { hi: 0, lo: 8 },
    Z128 { hi: 0, lo: 0 },
];

fn gaussian0_sampler(prng: &mut Prng) -> i32 {
    let msb = prng.get_u8();
    if msb != 0 {
        for (z, &cdf8) in CDF8.iter().enumerate() {
            if msb > cdf8 {
                return z as i32;
            }
            if msb == cdf8 {
                let hi = prng.get_u64();
                let lo = prng.get_u64();
                let cdf = CDFS[z];
                if hi > cdf.hi || (hi == cdf.hi && lo >= cdf.lo) {
                    return z as i32;
                }
                return z as i32 + 1;
            }
        }
    }

    let hi = prng.get_u64();
    let lo = prng.get_u64();
    for (z, cdf) in CDF0.iter().enumerate() {
        if hi > cdf.hi || (hi == cdf.hi && lo >= cdf.lo) {
            return z as i32 + CDF8.len() as i32;
        }
    }
    unreachable!("CDF terminator must be reached");
}

fn ber_exp(prng: &mut Prng, x: Fpr) -> bool {
    let s = fpr_floor(fpr_div(x, FPR_LOG2));
    let r = fpr_sub(x, fpr_mul(fpr_of(s), FPR_LOG2));

    let mut sw = s as u32;
    sw ^= (sw ^ 63) & 0u32.wrapping_sub((63u32.wrapping_sub(sw)) >> 31);

    let z = (((fpr_rint(fpr_mul(fpr_exp_small(fpr_neg(r)), FPR_P63)) as u64) << 1).wrapping_sub(1))
        >> sw;

    let mut i = 64usize;
    loop {
        i -= 8;
        let w = u64::from(prng.get_u8()).wrapping_sub((z >> i) & 0xFF);
        if w != 0 || i == 0 {
            return (w >> 63) != 0;
        }
    }
}

pub(crate) fn sample_binary(prng: &mut Prng, mu: Fpr, sigma: Fpr) -> i32 {
    let s = fpr_floor(mu);
    let r = fpr_sub(mu, fpr_of(s));
    let dss = fpr_inv(fpr_mul(fpr_sqr(sigma), fpr_of(2)));

    loop {
        let mut z = gaussian0_sampler(prng);
        let b = i32::from(prng.get_u8() & 1);
        z = b + ((b << 1) - 1) * z;

        let zb = z - b;
        let mut x = fpr_mul(fpr_sqr(fpr_sub(fpr_of(i64::from(z)), r)), dss);
        x = fpr_sub(x, fpr_div(fpr_of(i64::from(zb * zb)), fpr_of(8)));
        if ber_exp(prng, x) {
            return s as i32 + z;
        }
    }
}
