//! Workspace types for advanced allocation control.

use crate::math::fpr::ref_f64::Fpr;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

const fn ffldl_treesize(logn: u32) -> usize {
    ((logn + 1) as usize) << logn
}

const fn expanded_ref_key_len(logn: u32) -> usize {
    let n = 1usize << logn;
    4 * n + ffldl_treesize(logn)
}

/// Preallocated scratch space for advanced reference key generation.
pub struct KeygenWorkspace<const LOGN: u32> {
    pub(crate) f: Vec<i16>,
    pub(crate) g: Vec<i16>,
    pub(crate) ortho_rt1: Vec<Fpr>,
    pub(crate) ortho_rt2: Vec<Fpr>,
    pub(crate) ortho_rt3: Vec<Fpr>,
    pub(crate) t: Vec<u16>,
    pub(crate) h: Vec<u16>,
}

impl<const LOGN: u32> KeygenWorkspace<LOGN> {
    pub fn new() -> Self {
        let n = 1usize << LOGN;
        Self {
            f: vec![0; n],
            g: vec![0; n],
            ortho_rt1: vec![Fpr::new(0.0); n],
            ortho_rt2: vec![Fpr::new(0.0); n],
            ortho_rt3: vec![Fpr::new(0.0); n >> 1],
            t: vec![0; n],
            h: vec![0; n],
        }
    }
}

impl<const LOGN: u32> Default for KeygenWorkspace<LOGN> {
    fn default() -> Self {
        Self::new()
    }
}

/// Preallocated scratch space for advanced reference signing.
pub struct SignRefWorkspace<const LOGN: u32> {
    pub(crate) hm: Vec<u16>,
    pub(crate) s1: Vec<i16>,
    pub(crate) s2: Vec<i16>,
    pub(crate) prepared: Vec<Fpr>,
    pub(crate) prepare_tmp: Vec<Fpr>,
    pub(crate) sign_tmp: Vec<Fpr>,
    pub(crate) seed: [u8; 32],
    pub(crate) nonce: Vec<u8>,
}

impl<const LOGN: u32> SignRefWorkspace<LOGN> {
    pub fn new() -> Self {
        let n = 1usize << LOGN;
        Self {
            hm: vec![0; n],
            s1: vec![0; n],
            s2: vec![0; n],
            prepared: vec![Fpr::new(0.0); expanded_ref_key_len(LOGN)],
            prepare_tmp: vec![Fpr::new(0.0); 4 * n],
            sign_tmp: vec![Fpr::new(0.0); 6 * n],
            seed: [0; 32],
            nonce: Vec::with_capacity(40),
        }
    }
}

impl<const LOGN: u32> Default for SignRefWorkspace<LOGN> {
    fn default() -> Self {
        Self::new()
    }
}

/// Preallocated scratch space for advanced reference verification.
pub struct VerifyWorkspace<const LOGN: u32> {
    pub(crate) decoded_h: Vec<u16>,
    pub(crate) h_ntt: Vec<u16>,
    pub(crate) c0: Vec<u16>,
    pub(crate) x: Vec<u16>,
    pub(crate) s1: Vec<i16>,
    pub(crate) s2: Vec<i16>,
}

impl<const LOGN: u32> VerifyWorkspace<LOGN> {
    pub fn new() -> Self {
        let n = 1usize << LOGN;
        Self {
            decoded_h: vec![0; n],
            h_ntt: vec![0; n],
            c0: vec![0; n],
            x: vec![0; n],
            s1: vec![0; n],
            s2: vec![0; n],
        }
    }
}

impl<const LOGN: u32> Default for VerifyWorkspace<LOGN> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "zeroize")]
fn zeroize_fpr(buf: &mut [Fpr]) {
    for value in buf {
        *value = Fpr::new(0.0);
    }
}

#[cfg(feature = "zeroize")]
impl<const LOGN: u32> Drop for KeygenWorkspace<LOGN> {
    fn drop(&mut self) {
        self.f.as_mut_slice().zeroize();
        self.g.as_mut_slice().zeroize();
        zeroize_fpr(&mut self.ortho_rt1);
        zeroize_fpr(&mut self.ortho_rt2);
        zeroize_fpr(&mut self.ortho_rt3);
        self.t.as_mut_slice().zeroize();
        self.h.as_mut_slice().zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<const LOGN: u32> Drop for SignRefWorkspace<LOGN> {
    fn drop(&mut self) {
        self.hm.as_mut_slice().zeroize();
        self.s1.as_mut_slice().zeroize();
        self.s2.as_mut_slice().zeroize();
        zeroize_fpr(&mut self.prepared);
        zeroize_fpr(&mut self.prepare_tmp);
        zeroize_fpr(&mut self.sign_tmp);
        self.seed.zeroize();
        self.nonce.as_mut_slice().zeroize();
    }
}
