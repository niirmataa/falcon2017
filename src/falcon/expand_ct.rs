//! Expanded-key generation for the strict constant-time backend.

use crate::error::{Error, Result};
use crate::falcon::sign_ref::prepare_signing_key_bits_ref;
use crate::math::fpr::soft::Fpr;
use crate::params::is_public_logn;
use crate::types::{ExpandedSecretKeyCt, ExpandedSecretKeyCtInner, SecretKey};

const fn ffldl_treesize(logn: u32) -> usize {
    ((logn + 1) as usize) << logn
}

fn soft_slice_from_bits(bits: &[u64]) -> Box<[Fpr]> {
    bits.iter()
        .copied()
        .map(Fpr::from_bits)
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

fn expand_ct_inner<const LOGN: u32>(secret: &SecretKey<LOGN>) -> ExpandedSecretKeyCtInner<LOGN> {
    let n = 1usize << LOGN;
    let tree_len = ffldl_treesize(LOGN);
    // Preserve the historical Falcon/Extra LDL/ffLDL semantics exactly, but
    // store the expanded key in the integer-backed `FprSoft` representation.
    let prepared = prepare_signing_key_bits_ref(secret);
    let expected_len = 4 * n + tree_len;
    assert_eq!(prepared.len(), expected_len);

    let (b00, rest) = prepared.split_at(n);
    let (b01, rest) = rest.split_at(n);
    let (b10, rest) = rest.split_at(n);
    let (b11, tree) = rest.split_at(n);

    ExpandedSecretKeyCtInner {
        b00: soft_slice_from_bits(b00),
        b01: soft_slice_from_bits(b01),
        b10: soft_slice_from_bits(b10),
        b11: soft_slice_from_bits(b11),
        tree: soft_slice_from_bits(tree),
    }
}

pub(crate) fn expand_ct_strict<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
) -> Result<ExpandedSecretKeyCt<LOGN>> {
    if !is_public_logn(LOGN) {
        return Err(Error::InvalidParameter);
    }

    Ok(ExpandedSecretKeyCt {
        inner: expand_ct_inner(secret),
    })
}

#[cfg(test)]
pub(crate) fn debug_expand_ct_inner<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
) -> ExpandedSecretKeyCtInner<LOGN> {
    expand_ct_inner(secret)
}

#[cfg(test)]
mod tests {
    use super::debug_expand_ct_inner;
    use crate::falcon::sign_ref::prepare_signing_key_bits_ref;
    use crate::types::SecretKey;

    const REF_SECRET_KEY_NONE: [u8; 129] = [
        4, 0, 10, 0, 11, 255, 245, 0, 24, 255, 237, 255, 252, 255, 235, 0, 27, 255, 230, 0, 6, 255,
        239, 255, 255, 0, 39, 0, 5, 0, 18, 255, 244, 0, 24, 0, 25, 255, 252, 255, 241, 0, 6, 0, 14,
        0, 28, 255, 253, 0, 20, 0, 27, 0, 53, 0, 17, 0, 1, 255, 215, 255, 218, 0, 31, 255, 242, 0,
        51, 255, 225, 255, 195, 0, 13, 0, 26, 0, 55, 0, 43, 255, 232, 255, 248, 255, 255, 0, 33, 0,
        3, 0, 34, 255, 232, 0, 51, 0, 55, 0, 20, 255, 231, 0, 61, 0, 52, 255, 255, 255, 214, 255,
        255, 0, 49, 255, 242, 0, 36, 255, 229, 0, 10, 0, 5, 0, 3, 255, 192,
    ];

    fn flatten_bits<const LOGN: u32>(
        expanded: &crate::types::ExpandedSecretKeyCtInner<LOGN>,
    ) -> Vec<u64> {
        let n = 1usize << LOGN;
        let tree_len = super::ffldl_treesize(LOGN);
        let mut out = Vec::with_capacity(4 * n + tree_len);
        out.extend(expanded.b00.iter().map(|x| x.bits()));
        out.extend(expanded.b01.iter().map(|x| x.bits()));
        out.extend(expanded.b10.iter().map(|x| x.bits()));
        out.extend(expanded.b11.iter().map(|x| x.bits()));
        out.extend(expanded.tree.iter().map(|x| x.bits()));
        out
    }

    #[test]
    fn expanded_ct_matches_reference_preparation_bits() {
        let secret = SecretKey::<4>::from_bytes(&REF_SECRET_KEY_NONE).expect("reference bytes");
        let expanded = debug_expand_ct_inner(&secret);

        assert_eq!(
            flatten_bits(&expanded),
            prepare_signing_key_bits_ref(&secret)
        );
    }
}
