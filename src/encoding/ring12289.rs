//! Encoding for ring elements modulo 12289.

use crate::encoding::binary_len;
use crate::error::{Error, Result};

pub const MODULUS: u32 = 12289;
pub const BITS_PER_ELEMENT: usize = 14;

pub fn encoded_len(logn: u32) -> usize {
    ((binary_len(logn) * BITS_PER_ELEMENT) + 7) >> 3
}

pub fn encode(values: &[u16], logn: u32) -> Result<Box<[u8]>> {
    let n = binary_len(logn);
    if values.len() != n || values.iter().any(|&w| u32::from(w) >= MODULUS) {
        return Err(Error::InvalidEncoding);
    }

    let mut out = Vec::with_capacity(encoded_len(logn));
    let mut acc = 0u32;
    let mut acc_len = 0usize;
    for &value in values {
        acc = (acc << BITS_PER_ELEMENT) | u32::from(value);
        acc_len += BITS_PER_ELEMENT;
        while acc_len >= 8 {
            acc_len -= 8;
            out.push((acc >> acc_len) as u8);
            acc &= (1u32 << acc_len) - 1;
        }
    }
    if acc_len > 0 {
        out.push((acc << (8 - acc_len)) as u8);
    }
    Ok(out.into_boxed_slice())
}

pub fn decode(data: &[u8], logn: u32) -> Result<Box<[u16]>> {
    let n = binary_len(logn);
    let need = encoded_len(logn);
    if data.len() < need {
        return Err(Error::InvalidEncoding);
    }

    let mut out = Vec::with_capacity(n);
    let mut acc = 0u32;
    let mut acc_len = 0usize;
    let mut used = 0usize;
    while out.len() < n {
        if used >= data.len() {
            return Err(Error::InvalidEncoding);
        }
        acc = (acc << 8) | u32::from(data[used]);
        used += 1;
        acc_len += 8;
        if acc_len >= BITS_PER_ELEMENT {
            acc_len -= BITS_PER_ELEMENT;
            let w = acc >> acc_len;
            if w >= MODULUS {
                return Err(Error::InvalidEncoding);
            }
            out.push(w as u16);
            acc &= (1u32 << acc_len) - 1;
        }
    }
    if acc != 0 {
        return Err(Error::InvalidEncoding);
    }
    Ok(out.into_boxed_slice())
}
