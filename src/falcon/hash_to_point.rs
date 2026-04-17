//! Hash-to-point helpers.

use crate::math::ntt::QB;
use crate::rng::shake256::ShakeContext;

pub(crate) fn hash_to_point_binary(sc: &mut ShakeContext, logn: u32) -> Box<[u16]> {
    let mut out = vec![0u16; 1usize << logn];
    hash_to_point(sc, QB, &mut out, logn);
    out.into_boxed_slice()
}

pub(crate) fn hash_message_to_point_binary(nonce: &[u8], message: &[u8], logn: u32) -> Box<[u16]> {
    let mut sc = ShakeContext::shake256();
    sc.inject(nonce);
    sc.inject(message);
    sc.flip();
    hash_to_point_binary(&mut sc, logn)
}

pub(crate) fn hash_to_point(sc: &mut ShakeContext, q: u32, out: &mut [u16], logn: u32) {
    let expected = if q == QB {
        1usize << logn
    } else {
        3usize << (logn - 1)
    };
    assert_eq!(out.len(), expected);

    let lim = 65_536u32 - (65_536u32 % q);
    let mut filled = 0usize;
    while filled < expected {
        let mut buf = [0u8; 2];
        sc.extract(&mut buf);
        let w = (u32::from(buf[0]) << 8) | u32::from(buf[1]);
        if w < lim {
            out[filled] = (w % q) as u16;
            filled += 1;
        }
    }
}

pub(crate) fn is_short_binary(s1: &[i16], s2: &[i16], logn: u32) -> bool {
    let n = 1usize << logn;
    if s1.len() != n || s2.len() != n {
        return false;
    }

    let mut s = 0u32;
    let mut ng = 0u32;
    for u in 0..n {
        let z1 = i32::from(s1[u]);
        s = s.wrapping_add((z1 * z1) as u32);
        ng |= s;
        let z2 = i32::from(s2[u]);
        s = s.wrapping_add((z2 * z2) as u32);
        ng |= s;
    }
    s |= 0u32.wrapping_sub(ng >> 31);
    s < ((7085u32 * QB) >> (10 - logn))
}

#[cfg(test)]
mod tests {
    use super::{hash_message_to_point_binary, is_short_binary};

    #[test]
    fn hash_message_to_point_binary_is_deterministic() {
        let a = hash_message_to_point_binary(b"nonce", b"message", 4);
        let b = hash_message_to_point_binary(b"nonce", b"message", 4);
        let c = hash_message_to_point_binary(b"nonce", b"message!", 4);

        assert_eq!(&*a, &*b);
        assert_ne!(&*a, &*c);
    }

    #[test]
    fn is_short_binary_matches_reference_bound_shape() {
        let zero = vec![0i16; 16];
        assert!(is_short_binary(&zero, &zero, 4));

        let mut large = vec![0i16; 16];
        large[0] = 3000;
        assert!(!is_short_binary(&large, &zero, 4));
    }
}
