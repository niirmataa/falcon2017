use falcon2017::compression::Compression;
use falcon2017::encoding::{public_key, ring12289, ring18433, secret_key, signature, smallvec};

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
