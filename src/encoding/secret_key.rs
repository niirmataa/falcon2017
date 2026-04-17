//! Secret-key wire format helpers.

use crate::compression::Compression;
use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretKeyHeader {
    pub ternary: bool,
    pub compression: Compression,
    pub logn: u32,
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
