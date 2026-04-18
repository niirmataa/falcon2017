//! Encoding for Falcon small vectors.

use crate::compression::Compression;
use crate::encoding::{binary_len, ternary_len};
use crate::error::{Error, Result};

fn vector_len(q: u32, logn: u32) -> Result<usize> {
    match q {
        12289 => Ok(binary_len(logn)),
        18433 => Ok(ternary_len(logn)),
        _ => Err(Error::InvalidParameter),
    }
}

fn coding_bits(q: u32) -> Result<usize> {
    match q {
        12289 => Ok(7),
        18433 => Ok(8),
        _ => Err(Error::InvalidParameter),
    }
}

pub fn encoded_len_none(q: u32, logn: u32) -> Result<usize> {
    Ok(vector_len(q, logn)? << 1)
}

pub fn encode(comp: Compression, q: u32, values: &[i16], logn: u32) -> Result<Box<[u8]>> {
    let n = vector_len(q, logn)?;
    if values.len() != n {
        return Err(Error::InvalidEncoding);
    }

    match comp {
        Compression::None => {
            let mut out = Vec::with_capacity(n << 1);
            for &value in values {
                let word = value as u16;
                out.push((word >> 8) as u8);
                out.push(word as u8);
            }
            Ok(out.into_boxed_slice())
        }
        Compression::Static => {
            let j = coding_bits(q)?;
            let mask = (1u32 << j) - 1;
            let mut out = Vec::new();
            let mut acc = 0u32;
            let mut acc_len = 0usize;

            for &value in values {
                let mut w = i32::from(value);
                let mut lo = 0u32;
                if w < 0 {
                    w = -w;
                    lo = 1u32 << j;
                }
                lo |= (w as u32) & mask;
                let mut ne = (w as u32) >> j;
                acc = (acc << (j + 1)) | lo;
                acc_len += j + 1;
                while acc_len >= 8 {
                    acc_len -= 8;
                    out.push((acc >> acc_len) as u8);
                }
                while ne == 0 || ne != u32::MAX {
                    acc <<= 1;
                    acc += ((ne as i32 - 1) >> 31) as u32 & 1;
                    if acc_len + 1 == 8 {
                        out.push(acc as u8);
                        acc_len = 0;
                    } else {
                        acc_len += 1;
                    }
                    if ne == 0 {
                        break;
                    }
                    ne -= 1;
                }
            }
            if acc_len > 0 {
                out.push((acc << (8 - acc_len)) as u8);
            }
            Ok(out.into_boxed_slice())
        }
    }
}

pub fn decode(comp: Compression, q: u32, data: &[u8], logn: u32) -> Result<(Box<[i16]>, usize)> {
    let n = vector_len(q, logn)?;
    let mut out = vec![0i16; n];
    let used = decode_into(comp, q, data, logn, &mut out)?;
    Ok((out.into_boxed_slice(), used))
}

pub fn decode_into(
    comp: Compression,
    q: u32,
    data: &[u8],
    logn: u32,
    out: &mut [i16],
) -> Result<usize> {
    let n = vector_len(q, logn)?;
    if out.len() != n {
        return Err(Error::InvalidEncoding);
    }
    match comp {
        Compression::None => {
            let need = n << 1;
            if data.len() < need {
                return Err(Error::InvalidEncoding);
            }

            let hq = q >> 1;
            let tq = hq + q + 1;
            for (dst, chunk) in out.iter_mut().zip(data[..need].chunks_exact(2)) {
                let mut w = (u32::from(chunk[0]) << 8) | u32::from(chunk[1]);
                w |= 0u32.wrapping_sub(w & 0x8000);
                w = w.wrapping_add(q);
                if (((hq.wrapping_sub(w)) & (w.wrapping_sub(tq))) >> 31) == 0 {
                    return Err(Error::InvalidEncoding);
                }
                *dst = (i64::from(w) - i64::from(q)) as i16;
            }
            Ok(need)
        }
        Compression::Static => {
            let j = coding_bits(q)?;
            let mask = (1u32 << j) - 1;
            let mut v = 0usize;
            let mut db = 0u32;
            let mut db_len = 0usize;
            let mut filled = 0usize;

            while filled < n {
                while db_len <= j {
                    if v >= data.len() {
                        return Err(Error::InvalidEncoding);
                    }
                    db = (db << 8) | u32::from(data[v]);
                    v += 1;
                    db_len += 8;
                }
                let sign = (db >> (db_len - 1)) & 1;
                db_len -= j + 1;
                let mut lo = (db >> db_len) & mask;

                let mut ne = 0u32;
                loop {
                    if db_len == 0 {
                        if v >= data.len() {
                            return Err(Error::InvalidEncoding);
                        }
                        db = u32::from(data[v]);
                        v += 1;
                        db_len = 8;
                    }
                    db_len -= 1;
                    let bit = (db >> db_len) & 1;
                    if bit != 0 {
                        break;
                    }
                    ne += 1;
                    if ne > 255 {
                        return Err(Error::InvalidEncoding);
                    }
                }

                lo += ne << j;
                let value = if sign != 0 { -(lo as i16) } else { lo as i16 };
                out[filled] = value;
                filled += 1;
            }

            if (db & ((1u32 << db_len) - 1)) != 0 {
                return Err(Error::InvalidEncoding);
            }
            Ok(v)
        }
    }
}
