//! Signature wire format helpers.

use crate::compression::Compression;
use crate::encoding::smallvec;
use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedSignature {
    pub ternary: bool,
    pub compression: Compression,
    pub logn: u32,
    pub s2: Box<[i16]>,
}

pub fn header(ternary: bool, compression: Compression, logn: u32) -> Result<u8> {
    validate_logn(ternary, logn)?;
    let comp = match compression {
        Compression::None => 0u8,
        Compression::Static => 1u8,
    };
    Ok(((ternary as u8) << 7) | (comp << 5) | (logn as u8))
}

pub fn encode(ternary: bool, compression: Compression, logn: u32, s2: &[i16]) -> Result<Box<[u8]>> {
    let head = header(ternary, compression, logn)?;
    let q = if ternary { 18433 } else { 12289 };
    let body = smallvec::encode(compression, q, s2, logn)?;
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(head);
    out.extend_from_slice(&body);
    Ok(out.into_boxed_slice())
}

pub fn decode(bytes: &[u8]) -> Result<DecodedSignature> {
    if bytes.len() <= 1 {
        return Err(Error::InvalidEncoding);
    }
    let fb = bytes[0];
    if (fb & 0x10) != 0 {
        return Err(Error::InvalidEncoding);
    }
    let logn = u32::from(fb & 0x0F);
    let ternary = (fb >> 7) != 0;
    validate_logn(ternary, logn)?;
    let compression = match (fb >> 5) & 0x03 {
        0 => Compression::None,
        1 => Compression::Static,
        _ => return Err(Error::InvalidEncoding),
    };
    let q = if ternary { 18433 } else { 12289 };
    let (s2, consumed) = smallvec::decode(compression, q, &bytes[1..], logn)?;
    if consumed != (bytes.len() - 1) {
        return Err(Error::InvalidEncoding);
    }
    Ok(DecodedSignature {
        ternary,
        compression,
        logn,
        s2,
    })
}

fn validate_logn(ternary: bool, logn: u32) -> Result<()> {
    let ok = if ternary {
        (2..=9).contains(&logn)
    } else {
        (1..=10).contains(&logn)
    };
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidEncoding)
    }
}
