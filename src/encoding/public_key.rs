//! Public-key wire format helpers.

use crate::encoding::{ring12289, ring18433};
use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedPublicKey {
    pub ternary: bool,
    pub logn: u32,
    pub h: Box<[u16]>,
}

pub fn header(ternary: bool, logn: u32) -> Result<u8> {
    validate_logn(ternary, logn)?;
    Ok(((ternary as u8) << 7) | (logn as u8))
}

pub fn encode(ternary: bool, logn: u32, h: &[u16]) -> Result<Box<[u8]>> {
    let head = header(ternary, logn)?;
    let body = if ternary {
        ring18433::encode(h, logn)?
    } else {
        ring12289::encode(h, logn)?
    };
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(head);
    out.extend_from_slice(&body);
    Ok(out.into_boxed_slice())
}

pub fn decode(bytes: &[u8]) -> Result<DecodedPublicKey> {
    if bytes.len() <= 1 {
        return Err(Error::InvalidEncoding);
    }
    let fb = bytes[0];
    let logn = u32::from(fb & 0x0F);
    let ternary = (fb >> 7) != 0;
    validate_logn(ternary, logn)?;
    if ((fb >> 4) & 0x07) != 0 {
        return Err(Error::InvalidEncoding);
    }
    let h = if ternary {
        ring18433::decode(&bytes[1..], logn)?
    } else {
        ring12289::decode(&bytes[1..], logn)?
    };
    Ok(DecodedPublicKey { ternary, logn, h })
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
