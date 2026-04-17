//! Public API types.

use crate::params::{FALCON1024_LOGN, FALCON512_LOGN};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Marker type for the Falcon-512 parameter set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Falcon512;

/// Marker type for the Falcon-1024 parameter set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Falcon1024;

/// Public alias for a Falcon-512 keypair.
pub type Falcon512Keypair = Keypair<FALCON512_LOGN>;

/// Public alias for a Falcon-1024 keypair.
pub type Falcon1024Keypair = Keypair<FALCON1024_LOGN>;

/// Public Falcon keypair type.
pub struct Keypair<const LOGN: u32> {
    pub public: PublicKey<LOGN>,
    pub secret: SecretKey<LOGN>,
}

/// Encoded Falcon public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey<const LOGN: u32> {
    pub(crate) bytes: Box<[u8]>,
}

/// Decoded and prepared public-key state used by verification.
#[derive(Debug)]
#[allow(dead_code)]
pub struct PreparedPublicKey<const LOGN: u32> {
    inner: PreparedPublicKeyInner<LOGN>,
}

/// Encoded Falcon secret key with opaque in-memory representation.
#[allow(dead_code)]
pub struct SecretKey<const LOGN: u32> {
    inner: SecretKeyInner<LOGN>,
}

/// Expanded secret key for the strict constant-time backend.
#[allow(dead_code)]
pub struct ExpandedSecretKeyCt<const LOGN: u32> {
    inner: ExpandedSecretKeyCtInner<LOGN>,
}

/// Detached Falcon signature with explicit nonce and body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetachedSignature<const LOGN: u32> {
    nonce: Nonce,
    body: Box<[u8]>,
}

/// Explicit Falcon nonce type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce(Box<[u8]>);

#[derive(Debug)]
#[allow(dead_code)]
struct PreparedPublicKeyInner<const LOGN: u32> {
    bytes: Box<[u8]>,
}

struct SecretKeyInner<const LOGN: u32> {
    f: Box<[i8]>,
    g: Box<[i8]>,
    big_f: Box<[i8]>,
    big_g: Box<[i8]>,
}

struct ExpandedSecretKeyCtInner<const LOGN: u32> {
    storage: Box<[u8]>,
}

#[cfg(feature = "zeroize")]
impl<const LOGN: u32> Drop for SecretKeyInner<LOGN> {
    fn drop(&mut self) {
        self.f.as_mut().zeroize();
        self.g.as_mut().zeroize();
        self.big_f.as_mut().zeroize();
        self.big_g.as_mut().zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<const LOGN: u32> Drop for ExpandedSecretKeyCtInner<LOGN> {
    fn drop(&mut self) {
        self.storage.as_mut().zeroize();
    }
}
