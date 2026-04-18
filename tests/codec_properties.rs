#[path = "../src/compression.rs"]
mod compression;
#[path = "../src/error.rs"]
mod error;
#[path = "../src/encoding/public_key.rs"]
pub mod encoding_public_key;
#[path = "../src/encoding/ring12289.rs"]
pub mod encoding_ring12289;
#[path = "../src/encoding/ring18433.rs"]
pub mod encoding_ring18433;
#[path = "../src/encoding/secret_key.rs"]
pub mod encoding_secret_key;
#[path = "../src/encoding/signature.rs"]
pub mod encoding_signature;
#[path = "../src/encoding/smallvec.rs"]
pub mod encoding_smallvec;

mod encoding {
    pub(crate) fn binary_len(logn: u32) -> usize {
        1usize << logn
    }

    pub(crate) fn ternary_len(logn: u32) -> usize {
        3usize << (logn - 1)
    }

    pub(crate) use crate::encoding_public_key as public_key;
    pub(crate) use crate::encoding_ring12289 as ring12289;
    pub(crate) use crate::encoding_ring18433 as ring18433;
    pub(crate) use crate::encoding_secret_key as secret_key;
    pub(crate) use crate::encoding_signature as signature;
    pub(crate) use crate::encoding_smallvec as smallvec;
}

use compression::Compression;
use proptest::prelude::*;

fn compression_strategy() -> impl Strategy<Value = Compression> {
    prop_oneof![Just(Compression::None), Just(Compression::Static)]
}

fn binary_ring_case() -> impl Strategy<Value = (u32, Vec<u16>)> {
    (1u32..=10).prop_flat_map(|logn| {
        let n = 1usize << logn;
        (
            Just(logn),
            prop::collection::vec(0u16..(encoding::ring12289::MODULUS as u16), n),
        )
    })
}

fn ternary_ring_case() -> impl Strategy<Value = (u32, Vec<u16>)> {
    (2u32..=9).prop_flat_map(|logn| {
        let n = 3usize << (logn - 1);
        (
            Just(logn),
            prop::collection::vec(0u16..(encoding::ring18433::MODULUS as u16), n),
        )
    })
}

fn binary_smallvec_case() -> impl Strategy<Value = (Compression, u32, Vec<i16>)> {
    (compression_strategy(), 1u32..=10).prop_flat_map(|(compression, logn)| {
        let n = 1usize << logn;
        (
            Just(compression),
            Just(logn),
            prop::collection::vec(-2047i16..2048i16, n),
        )
    })
}

fn ternary_smallvec_case() -> impl Strategy<Value = (Compression, u32, Vec<i16>)> {
    (compression_strategy(), 2u32..=9).prop_flat_map(|(compression, logn)| {
        let n = 3usize << (logn - 1);
        (
            Just(compression),
            Just(logn),
            prop::collection::vec(-2047i16..2048i16, n),
        )
    })
}

fn binary_secret_key_case(
) -> impl Strategy<Value = (Compression, u32, Vec<i8>, Vec<i8>, Vec<i16>, Vec<i16>)> {
    (compression_strategy(), 1u32..=10).prop_flat_map(|(compression, logn)| {
        let n = 1usize << logn;
        (
            Just(compression),
            Just(logn),
            prop::collection::vec(-63i8..64i8, n),
            prop::collection::vec(-63i8..64i8, n),
            prop::collection::vec(-1023i16..1024i16, n),
            prop::collection::vec(-1023i16..1024i16, n),
        )
    })
}

fn ternary_secret_key_case(
) -> impl Strategy<Value = (Compression, u32, Vec<i8>, Vec<i8>, Vec<i16>, Vec<i16>)> {
    (compression_strategy(), 2u32..=9).prop_flat_map(|(compression, logn)| {
        let n = 3usize << (logn - 1);
        (
            Just(compression),
            Just(logn),
            prop::collection::vec(-63i8..64i8, n),
            prop::collection::vec(-63i8..64i8, n),
            prop::collection::vec(-1023i16..1024i16, n),
            prop::collection::vec(-1023i16..1024i16, n),
        )
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn ring12289_roundtrips((logn, values) in binary_ring_case()) {
        let encoded = encoding::ring12289::encode(&values, logn).expect("encode");
        let decoded = encoding::ring12289::decode(&encoded, logn).expect("decode");
        prop_assert_eq!(&*decoded, values.as_slice());

        let mut trailing = encoded.into_vec();
        trailing.push(0);
        prop_assert!(encoding::ring12289::decode(&trailing, logn).is_err());
    }

    #[test]
    fn ring18433_roundtrips((logn, values) in ternary_ring_case()) {
        let encoded = encoding::ring18433::encode(&values, logn).expect("encode");
        let decoded = encoding::ring18433::decode(&encoded, logn).expect("decode");
        prop_assert_eq!(&*decoded, values.as_slice());

        let mut trailing = encoded.into_vec();
        trailing.push(0);
        prop_assert!(encoding::ring18433::decode(&trailing, logn).is_err());
    }

    #[test]
    fn smallvec_binary_roundtrips((compression, logn, values) in binary_smallvec_case()) {
        let encoded = encoding::smallvec::encode(compression, 12289, &values, logn).expect("encode");
        let (decoded, used) = encoding::smallvec::decode(compression, 12289, &encoded, logn).expect("decode");
        prop_assert_eq!(used, encoded.len());
        prop_assert_eq!(&*decoded, values.as_slice());
    }

    #[test]
    fn smallvec_ternary_roundtrips((compression, logn, values) in ternary_smallvec_case()) {
        let encoded = encoding::smallvec::encode(compression, 18433, &values, logn).expect("encode");
        let (decoded, used) = encoding::smallvec::decode(compression, 18433, &encoded, logn).expect("decode");
        prop_assert_eq!(used, encoded.len());
        prop_assert_eq!(&*decoded, values.as_slice());
    }

    #[test]
    fn public_key_binary_roundtrips((logn, h) in binary_ring_case()) {
        let encoded = encoding::public_key::encode(false, logn, &h).expect("encode");
        let decoded = encoding::public_key::decode(&encoded).expect("decode");
        prop_assert!(!decoded.ternary);
        prop_assert_eq!(decoded.logn, logn);
        prop_assert_eq!(&*decoded.h, h.as_slice());
    }

    #[test]
    fn public_key_ternary_roundtrips((logn, h) in ternary_ring_case()) {
        let encoded = encoding::public_key::encode(true, logn, &h).expect("encode");
        let decoded = encoding::public_key::decode(&encoded).expect("decode");
        prop_assert!(decoded.ternary);
        prop_assert_eq!(decoded.logn, logn);
        prop_assert_eq!(&*decoded.h, h.as_slice());
    }

    #[test]
    fn signature_binary_roundtrips((compression, logn, s2) in binary_smallvec_case()) {
        let encoded = encoding::signature::encode(false, compression, logn, &s2).expect("encode");
        let decoded = encoding::signature::decode(&encoded).expect("decode");
        prop_assert!(!decoded.ternary);
        prop_assert_eq!(decoded.compression, compression);
        prop_assert_eq!(decoded.logn, logn);
        prop_assert_eq!(&*decoded.s2, s2.as_slice());
    }

    #[test]
    fn signature_ternary_roundtrips((compression, logn, s2) in ternary_smallvec_case()) {
        let encoded = encoding::signature::encode(true, compression, logn, &s2).expect("encode");
        let decoded = encoding::signature::decode(&encoded).expect("decode");
        prop_assert!(decoded.ternary);
        prop_assert_eq!(decoded.compression, compression);
        prop_assert_eq!(decoded.logn, logn);
        prop_assert_eq!(&*decoded.s2, s2.as_slice());
    }

    #[test]
    fn secret_key_binary_roundtrips(
        (compression, logn, f, g, big_f, big_g) in binary_secret_key_case()
    ) {
        let encoded = encoding::secret_key::encode(false, compression, logn, &f, &g, &big_f, &big_g)
            .expect("encode");
        let decoded = encoding::secret_key::decode(&encoded).expect("decode");
        let expected_f = f.iter().map(|&x| i16::from(x)).collect::<Vec<_>>();
        let expected_g = g.iter().map(|&x| i16::from(x)).collect::<Vec<_>>();
        prop_assert!(!decoded.ternary);
        prop_assert_eq!(decoded.compression, compression);
        prop_assert_eq!(decoded.logn, logn);
        prop_assert_eq!(&*decoded.f, expected_f.as_slice());
        prop_assert_eq!(&*decoded.g, expected_g.as_slice());
        prop_assert_eq!(&*decoded.big_f, big_f.as_slice());
        prop_assert_eq!(&*decoded.big_g, big_g.as_slice());
    }

    #[test]
    fn secret_key_ternary_roundtrips(
        (compression, logn, f, g, big_f, big_g) in ternary_secret_key_case()
    ) {
        let encoded = encoding::secret_key::encode(true, compression, logn, &f, &g, &big_f, &big_g)
            .expect("encode");
        let decoded = encoding::secret_key::decode(&encoded).expect("decode");
        let expected_f = f.iter().map(|&x| i16::from(x)).collect::<Vec<_>>();
        let expected_g = g.iter().map(|&x| i16::from(x)).collect::<Vec<_>>();
        prop_assert!(decoded.ternary);
        prop_assert_eq!(decoded.compression, compression);
        prop_assert_eq!(decoded.logn, logn);
        prop_assert_eq!(&*decoded.f, expected_f.as_slice());
        prop_assert_eq!(&*decoded.g, expected_g.as_slice());
        prop_assert_eq!(&*decoded.big_f, big_f.as_slice());
        prop_assert_eq!(&*decoded.big_g, big_g.as_slice());
    }
}
