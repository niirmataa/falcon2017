//! DGS_PROD_V1 static-CDF runtime primitives.
//!
//! This is the production-sampler runtime core defined in
//! `docs/dgs_prod_v1.md`. It is intentionally not wired into Falcon signing
//! yet: table generation, independent checking, and distribution certificates
//! must come first.

// This module is deliberately staged before certified production tables exist.
#![allow(dead_code)]

use crate::rng::prng::Prng;

pub(crate) const DEN_BITS: usize = 256;
pub(crate) const THRESHOLD_BITS: usize = 256;
pub(crate) const THRESHOLD_WORDS: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct U256(pub(crate) [u64; THRESHOLD_WORDS]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StaticCdfTable<const L: usize> {
    thresholds: [U256; L],
}

impl U256 {
    pub(crate) const fn from_le_words(words: [u64; THRESHOLD_WORDS]) -> Self {
        Self(words)
    }

    pub(crate) fn from_prng(prng: &mut Prng) -> Self {
        Self([
            prng.get_u64(),
            prng.get_u64(),
            prng.get_u64(),
            prng.get_u64(),
        ])
    }

    fn is_zero(self) -> bool {
        let mut acc = 0u64;
        for word in self.0 {
            acc |= word;
        }
        acc == 0
    }

    fn ct_lt(self, rhs: Self) -> bool {
        let mut borrow = 0u64;
        for index in 0..THRESHOLD_WORDS {
            let (tmp, b0) = self.0[index].overflowing_sub(rhs.0[index]);
            let (_, b1) = tmp.overflowing_sub(borrow);
            borrow = u64::from(b0) | u64::from(b1);
        }
        borrow != 0
    }

    fn ct_le(self, rhs: Self) -> bool {
        !rhs.ct_lt(self)
    }
}

impl<const L: usize> StaticCdfTable<L> {
    pub(crate) const fn new(thresholds: [U256; L]) -> Self {
        Self { thresholds }
    }

    pub(crate) const fn len(&self) -> usize {
        L
    }

    pub(crate) const fn bucket_count(&self) -> usize {
        L + 1
    }

    pub(crate) fn validate_public_shape(&self) -> bool {
        let mut ok = L > 0;
        let mut prev = U256::default();
        for threshold in self.thresholds {
            ok &= !threshold.is_zero();
            ok &= prev.ct_lt(threshold);
            prev = threshold;
        }
        ok
    }

    pub(crate) fn sample_index(&self, draw: U256) -> usize {
        let mut answer = L;
        let mut found = false;
        for (index, threshold) in self.thresholds.iter().enumerate() {
            let take = draw.ct_lt(*threshold) & !found;
            answer = ct_select_usize(answer, index, take);
            found |= take;
        }
        answer
    }

    pub(crate) fn sample_index_from_prng(&self, prng: &mut Prng) -> usize {
        self.sample_index(U256::from_prng(prng))
    }
}

fn ct_select_usize(a: usize, b: usize, take_b: bool) -> usize {
    let mask = 0usize.wrapping_sub(usize::from(take_b));
    a ^ ((a ^ b) & mask)
}

#[cfg(test)]
mod tests {
    use super::{StaticCdfTable, U256, DEN_BITS, THRESHOLD_BITS, THRESHOLD_WORDS};
    use crate::rng::prng::{Prng, PRNG_CHACHA20};
    use crate::rng::shake256::ShakeContext;

    const Q1: U256 = U256::from_le_words([0, 0, 0, 1u64 << 62]);
    const Q2: U256 = U256::from_le_words([0, 0, 0, 1u64 << 63]);
    const Q3: U256 = U256::from_le_words([0, 0, 0, (1u64 << 63) | (1u64 << 62)]);
    const TOY_TABLE: StaticCdfTable<3> = StaticCdfTable::new([Q1, Q2, Q3]);

    fn prng_from_seed(seed: &[u8]) -> Prng {
        let mut shake = ShakeContext::shake256();
        shake.inject(seed);
        shake.flip();
        Prng::new(&mut shake, PRNG_CHACHA20).expect("portable PRNG available")
    }

    #[test]
    fn constants_match_profile() {
        assert_eq!(DEN_BITS, 256);
        assert_eq!(THRESHOLD_BITS, 256);
        assert_eq!(THRESHOLD_WORDS, 4);
    }

    #[test]
    fn u256_comparison_uses_little_endian_words() {
        let lo = U256::from_le_words([u64::MAX, 0, 0, 0]);
        let hi = U256::from_le_words([0, 1, 0, 0]);
        assert!(lo.ct_lt(hi));
        assert!(!hi.ct_lt(lo));
        assert!(lo.ct_le(lo));
        assert!(lo.ct_le(hi));
    }

    #[test]
    fn public_shape_rejects_zero_first_threshold() {
        let bad = StaticCdfTable::new([U256::default(), Q2, Q3]);
        assert!(!bad.validate_public_shape());
        assert!(TOY_TABLE.validate_public_shape());
    }

    #[test]
    fn public_shape_rejects_non_increasing_thresholds() {
        let bad = StaticCdfTable::new([Q2, Q1, Q3]);
        assert!(!bad.validate_public_shape());

        let repeated = StaticCdfTable::new([Q1, Q1, Q3]);
        assert!(!repeated.validate_public_shape());
    }

    #[test]
    fn sample_index_uses_implicit_last_bucket() {
        assert_eq!(TOY_TABLE.len(), 3);
        assert_eq!(TOY_TABLE.bucket_count(), 4);
        assert_eq!(TOY_TABLE.sample_index(U256::from_le_words([0, 0, 0, 0])), 0);
        assert_eq!(TOY_TABLE.sample_index(Q1), 1);
        assert_eq!(TOY_TABLE.sample_index(Q2), 2);
        assert_eq!(TOY_TABLE.sample_index(Q3), 3);
        assert_eq!(TOY_TABLE.sample_index(U256::from_le_words([u64::MAX; 4])), 3);
    }

    #[test]
    fn sample_index_from_prng_consumes_32_bytes() {
        let mut prng = prng_from_seed(b"falcon2017-dgs-prod-v1-u256-draw");
        let before = prng.ptr;
        let _ = TOY_TABLE.sample_index_from_prng(&mut prng);
        let after = prng.ptr;
        assert_eq!(after.wrapping_sub(before), 32);
    }

    #[test]
    fn production_source_keeps_runtime_shape_simple() {
        let src = include_str!("dgs_prod_v1.rs");
        let production = src.split("#[cfg(test)]").next().expect("production slice");
        assert!(!production.contains(concat!("if", " ")));
        assert!(!production.contains(concat!("while", " ")));
        assert!(!production.contains(concat!("loop", " ")));
        assert!(!production.contains(concat!("match", " ")));
        assert!(!production.contains(concat!("return", " ")));
        assert!(production.contains("sample_index"));
        assert!(production.contains("sample_index_from_prng"));
    }
}
