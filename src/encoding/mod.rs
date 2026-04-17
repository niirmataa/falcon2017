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
