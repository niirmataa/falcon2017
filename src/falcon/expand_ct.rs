//! Expanded-key generation for the strict constant-time backend.

use crate::error::{Error, Result};
use crate::falcon::sign_ref::prepare_signing_key_bits_ref_into;
use crate::falcon::workspace::ExpandCtWorkspace;
use crate::math::fpr::soft::Fpr;
use crate::params::is_public_logn;
use crate::types::{ExpandedSecretKeyCt, ExpandedSecretKeyCtInner, SecretKey};
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

const fn ffldl_treesize(logn: u32) -> usize {
    ((logn + 1) as usize) << logn
}

fn alloc_soft_slice(len: usize) -> Box<[Fpr]> {
    vec![Fpr::from_bits(0); len].into_boxed_slice()
}

fn copy_bits_to_soft(dst: &mut [Fpr], bits: &[u64]) {
    assert_eq!(dst.len(), bits.len());
    for (dst, bits) in dst.iter_mut().zip(bits.iter().copied()) {
        *dst = Fpr::from_bits(bits);
    }
}

fn expand_ct_inner_with_bits<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
    prepared_bits: &mut [u64],
) -> ExpandedSecretKeyCtInner<LOGN> {
    let n = 1usize << LOGN;
    let tree_len = ffldl_treesize(LOGN);
    let expected_len = 4 * n + tree_len;
    assert_eq!(prepared_bits.len(), expected_len);
    // Preserve the historical Falcon/Extra LDL/ffLDL semantics exactly, but
    // store the expanded key in the integer-backed `FprSoft` representation.
    prepare_signing_key_bits_ref_into(secret, prepared_bits);

    let (b00, rest) = prepared_bits.split_at(n);
    let (b01, rest) = rest.split_at(n);
    let (b10, rest) = rest.split_at(n);
    let (b11, tree) = rest.split_at(n);

    let mut expanded = ExpandedSecretKeyCtInner {
        b00: alloc_soft_slice(n),
        b01: alloc_soft_slice(n),
        b10: alloc_soft_slice(n),
        b11: alloc_soft_slice(n),
        tree: alloc_soft_slice(tree_len),
    };

    copy_bits_to_soft(&mut expanded.b00, b00);
    copy_bits_to_soft(&mut expanded.b01, b01);
    copy_bits_to_soft(&mut expanded.b10, b10);
    copy_bits_to_soft(&mut expanded.b11, b11);
    copy_bits_to_soft(&mut expanded.tree, tree);

    #[cfg(feature = "zeroize")]
    prepared_bits.zeroize();

    expanded
}

#[cfg(test)]
fn expand_ct_inner<const LOGN: u32>(secret: &SecretKey<LOGN>) -> ExpandedSecretKeyCtInner<LOGN> {
    let mut prepared_bits = vec![0u64; 4 * (1usize << LOGN) + ffldl_treesize(LOGN)];
    expand_ct_inner_with_bits(secret, &mut prepared_bits)
}

pub(crate) fn expand_ct_strict<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
) -> Result<ExpandedSecretKeyCt<LOGN>> {
    let mut ws = ExpandCtWorkspace::<LOGN>::new();
    expand_ct_strict_in(secret, &mut ws)
}

pub(crate) fn expand_ct_strict_in<const LOGN: u32>(
    secret: &SecretKey<LOGN>,
    ws: &mut ExpandCtWorkspace<LOGN>,
) -> Result<ExpandedSecretKeyCt<LOGN>> {
    if !is_public_logn(LOGN) {
        return Err(Error::InvalidParameter);
    }

    Ok(ExpandedSecretKeyCt {
        inner: expand_ct_inner_with_bits(secret, &mut ws.prepared_bits),
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
