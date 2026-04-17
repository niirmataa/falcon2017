//! Encoding and decoding helpers for Falcon 2017 / Extra.

pub mod public_key;
pub mod ring12289;
pub mod ring18433;
pub mod secret_key;
pub mod signature;
pub mod smallvec;

pub(crate) fn binary_len(logn: u32) -> usize {
    1usize << logn
}

pub(crate) fn ternary_len(logn: u32) -> usize {
    3usize << (logn - 1)
}

#[cfg(test)]
mod tests {
    use super::{public_key, ring12289, ring18433, secret_key, signature, smallvec};
    use crate::compression::Compression;

    fn sample_binary_ring(logn: u32) -> Vec<u16> {
        let n = 1usize << logn;
        (0..n).map(|i| ((i * 97 + 13) % 12289) as u16).collect()
    }

    fn sample_ternary_ring(logn: u32) -> Vec<u16> {
        let n = 3usize << (logn - 1);
        (0..n).map(|i| ((i * 131 + 9) % 18433) as u16).collect()
    }

    fn sample_binary_small(logn: u32) -> Vec<i16> {
        let n = 1usize << logn;
        (0..n)
            .map(|i| (((i * 37 + 11) % 4097) as i32 - 2048) as i16)
            .collect()
    }

    #[test]
    fn ring12289_roundtrip_matches_reference_layout() {
        let values = sample_binary_ring(9);
        let enc = ring12289::encode(&values, 9).expect("encode");
        let dec = ring12289::decode(&enc, 9).expect("decode");
        assert_eq!(&*dec, values.as_slice());
    }

    #[test]
    fn ring18433_roundtrip_matches_reference_layout() {
        let values = sample_ternary_ring(9);
        let enc = ring18433::encode(&values, 9).expect("encode");
        let dec = ring18433::decode(&enc, 9).expect("decode");
        assert_eq!(&*dec, values.as_slice());
    }

    #[test]
    fn smallvec_none_roundtrip_binary() {
        let values = sample_binary_small(9);
        let enc = smallvec::encode(Compression::None, 12289, &values, 9).expect("encode");
        let (dec, used) = smallvec::decode(Compression::None, 12289, &enc, 9).expect("decode");
        assert_eq!(used, enc.len());
        assert_eq!(&*dec, values.as_slice());
    }

    #[test]
    fn smallvec_static_roundtrip_binary() {
        let values = sample_binary_small(9);
        let enc = smallvec::encode(Compression::Static, 12289, &values, 9).expect("encode");
        let (dec, used) = smallvec::decode(Compression::Static, 12289, &enc, 9).expect("decode");
        assert_eq!(used, enc.len());
        assert_eq!(&*dec, values.as_slice());
    }

    #[test]
    fn public_key_roundtrip_binary() {
        let h = sample_binary_ring(9);
        let enc = public_key::encode(false, 9, &h).expect("encode");
        let dec = public_key::decode(&enc).expect("decode");
        assert!(!dec.ternary);
        assert_eq!(dec.logn, 9);
        assert_eq!(&*dec.h, h.as_slice());
    }

    #[test]
    fn signature_roundtrip_binary_static() {
        let s2 = sample_binary_small(9);
        let enc = signature::encode(false, Compression::Static, 9, &s2).expect("encode");
        let dec = signature::decode(&enc).expect("decode");
        assert!(!dec.ternary);
        assert_eq!(dec.logn, 9);
        assert_eq!(dec.compression, Compression::Static);
        assert_eq!(&*dec.s2, s2.as_slice());
    }

    #[test]
    fn secret_key_header_roundtrip_binary_static() {
        let header = secret_key::header(false, Compression::Static, 9).expect("header");
        let parsed = secret_key::parse_header(header).expect("parse");
        assert!(!parsed.ternary);
        assert_eq!(parsed.logn, 9);
        assert_eq!(parsed.compression, Compression::Static);
    }

    #[test]
    fn ring12289_rejects_nonzero_padding_bits() {
        let mut bad = vec![0u8; ring12289::encoded_len(1)];
        *bad.last_mut().expect("non-empty") = 0x01;
        assert!(ring12289::decode(&bad, 1).is_err());
    }

    #[test]
    fn ring18433_rejects_out_of_range_element() {
        let bad = [0x90u8, 0x02u8, 0x00, 0x00, 0x00, 0x00];
        assert!(ring18433::decode(&bad, 1).is_err());
    }

    #[test]
    fn smallvec_none_rejects_out_of_range_value() {
        let bad = [0x1b, 0x58];
        assert!(smallvec::decode(Compression::None, 12289, &bad, 0).is_err());
    }

    #[test]
    fn smallvec_static_rejects_nonzero_trailing_bits() {
        let bad = [0x05, 0x81];
        assert!(smallvec::decode(Compression::Static, 12289, &bad, 0).is_err());
    }

    #[test]
    fn public_key_rejects_reserved_header_bits() {
        let bad = [0x10u8, 0x00, 0x00];
        assert!(public_key::decode(&bad).is_err());
    }

    #[test]
    fn secret_key_header_rejects_reserved_compression_bits() {
        assert!(secret_key::parse_header(0b0111_1001).is_err());
    }

    #[test]
    fn signature_rejects_extra_trailing_bytes() {
        let sig = signature::encode(false, Compression::None, 1, &[1, -1]).expect("encode");
        let mut owned = sig.into_vec();
        owned.push(0);
        assert!(signature::decode(&owned).is_err());
    }
}
