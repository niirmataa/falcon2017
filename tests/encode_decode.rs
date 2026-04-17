use falcon2017::compression::Compression;
use falcon2017::encoding::{public_key, ring12289, ring18433, secret_key, signature, smallvec};

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
