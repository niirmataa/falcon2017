//! Secret-key wire format helpers.

use crate::compression::Compression;
use crate::encoding::smallvec;
use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretKeyHeader {
    pub ternary: bool,
    pub compression: Compression,
    pub logn: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DecodedSecretKey {
    pub ternary: bool,
    pub compression: Compression,
    pub logn: u32,
    pub f: Box<[i16]>,
    pub g: Box<[i16]>,
    pub big_f: Box<[i16]>,
    pub big_g: Box<[i16]>,
}

pub fn header(ternary: bool, compression: Compression, logn: u32) -> Result<u8> {
    validate_logn(ternary, logn)?;
    let comp = match compression {
        Compression::None => 0u8,
        Compression::Static => 1u8,
    };
    Ok(((ternary as u8) << 7) | (comp << 5) | (logn as u8))
}

pub fn parse_header(byte: u8) -> Result<SecretKeyHeader> {
    let logn = u32::from(byte & 0x0F);
    let ternary = (byte >> 7) != 0;
    validate_logn(ternary, logn)?;
    if (byte & 0x10) != 0 {
        return Err(Error::InvalidEncoding);
    }
    let compression = match (byte >> 5) & 0x03 {
        0 => Compression::None,
        1 => Compression::Static,
        _ => return Err(Error::InvalidEncoding),
    };
    Ok(SecretKeyHeader {
        ternary,
        compression,
        logn,
    })
}

pub fn encode(
    ternary: bool,
    compression: Compression,
    logn: u32,
    f: &[i8],
    g: &[i8],
    big_f: &[i8],
    big_g: &[i8],
) -> Result<Box<[u8]>> {
    validate_logn(ternary, logn)?;
    let n = vector_len(ternary, logn)?;
    if f.len() != n || g.len() != n || big_f.len() != n || big_g.len() != n {
        return Err(Error::InvalidEncoding);
    }

    let mut out = Vec::new();
    out.push(header(ternary, compression, logn)?);
    let q = modulus(ternary);
    for poly in [f, g, big_f, big_g] {
        let tmp = poly.iter().map(|&x| i16::from(x)).collect::<Vec<_>>();
        let enc = smallvec::encode(compression, q, &tmp, logn)?;
        out.extend_from_slice(&enc);
    }
    Ok(out.into_boxed_slice())
}

pub fn decode(bytes: &[u8]) -> Result<DecodedSecretKey> {
    if bytes.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    let parsed = parse_header(bytes[0])?;
    let q = modulus(parsed.ternary);
    let mut offset = 1usize;

    let (f, used_f) = smallvec::decode(parsed.compression, q, &bytes[offset..], parsed.logn)?;
    offset += used_f;
    let (g, used_g) = smallvec::decode(parsed.compression, q, &bytes[offset..], parsed.logn)?;
    offset += used_g;
    let (big_f, used_big_f) =
        smallvec::decode(parsed.compression, q, &bytes[offset..], parsed.logn)?;
    offset += used_big_f;
    let (big_g, used_big_g) =
        smallvec::decode(parsed.compression, q, &bytes[offset..], parsed.logn)?;
    offset += used_big_g;

    if offset != bytes.len() {
        return Err(Error::InvalidEncoding);
    }

    Ok(DecodedSecretKey {
        ternary: parsed.ternary,
        compression: parsed.compression,
        logn: parsed.logn,
        f,
        g,
        big_f,
        big_g,
    })
}

fn modulus(ternary: bool) -> u32 {
    if ternary {
        18_433
    } else {
        12_289
    }
}

fn vector_len(ternary: bool, logn: u32) -> Result<usize> {
    validate_logn(ternary, logn)?;
    Ok(if ternary {
        3usize << (logn - 1)
    } else {
        1usize << logn
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
