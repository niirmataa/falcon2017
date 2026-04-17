//! Public API types.

use crate::compression::Compression;
use crate::error::{Error, Result};
use crate::params::{FALCON1024_LOGN, FALCON512_LOGN};
use rand_core::{CryptoRng, RngCore};

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
    pub(crate) inner: PreparedPublicKeyInner<LOGN>,
}

/// Encoded Falcon secret key with opaque in-memory representation.
#[allow(dead_code)]
pub struct SecretKey<const LOGN: u32> {
    pub(crate) inner: SecretKeyInner<LOGN>,
}

/// Expanded secret key for the strict constant-time backend.
#[allow(dead_code)]
pub struct ExpandedSecretKeyCt<const LOGN: u32> {
    pub(crate) inner: ExpandedSecretKeyCtInner<LOGN>,
}

/// Detached Falcon signature with explicit nonce and body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetachedSignature<const LOGN: u32> {
    pub(crate) nonce: Nonce,
    pub(crate) body: Box<[u8]>,
}

/// Explicit Falcon nonce type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce(pub(crate) Box<[u8]>);

/// Stateful streaming verifier.
#[derive(Clone, Debug)]
pub struct Verifier<const LOGN: u32> {
    nonce: Nonce,
    message_len: usize,
    prepared_len: usize,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct PreparedPublicKeyInner<const LOGN: u32> {
    pub(crate) bytes: Box<[u8]>,
}

pub(crate) struct SecretKeyInner<const LOGN: u32> {
    pub(crate) f: Box<[i8]>,
    pub(crate) g: Box<[i8]>,
    pub(crate) big_f: Box<[i8]>,
    pub(crate) big_g: Box<[i8]>,
}

pub(crate) struct ExpandedSecretKeyCtInner<const LOGN: u32> {
    pub(crate) storage: Box<[u8]>,
}

impl Falcon512 {
    pub fn keygen(rng: &mut (impl RngCore + CryptoRng)) -> Result<Falcon512Keypair> {
        let _ = rng;
        Err(Error::Internal)
    }

    #[cfg(feature = "deterministic-tests")]
    pub fn keygen_from_seed(seed: &[u8]) -> Result<Falcon512Keypair> {
        let _ = seed;
        Err(Error::Internal)
    }
}

impl Falcon1024 {
    pub fn keygen(rng: &mut (impl RngCore + CryptoRng)) -> Result<Falcon1024Keypair> {
        let _ = rng;
        Err(Error::Internal)
    }

    #[cfg(feature = "deterministic-tests")]
    pub fn keygen_from_seed(seed: &[u8]) -> Result<Falcon1024Keypair> {
        let _ = seed;
        Err(Error::Internal)
    }
}

impl<const LOGN: u32> SecretKey<LOGN> {
    pub fn to_bytes(&self, comp: Compression) -> Box<[u8]> {
        let _ = comp;
        let _ = self;
        Vec::new().into_boxed_slice()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let _ = bytes;
        Err(Error::Internal)
    }

    pub fn derive_public(&self) -> Result<PublicKey<LOGN>> {
        let _ = self;
        Err(Error::Internal)
    }

    pub fn sign_ref(
        &self,
        msg: &[u8],
        comp: Compression,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DetachedSignature<LOGN>> {
        let _ = (self, msg, comp, rng);
        Err(Error::Internal)
    }

    pub fn sign_ref_with_external_nonce(
        &self,
        msg: &[u8],
        nonce: Nonce,
        comp: Compression,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DetachedSignature<LOGN>> {
        let _ = (self, msg, nonce, comp, rng);
        Err(Error::Internal)
    }

    pub fn expand_ct_strict(&self) -> Result<ExpandedSecretKeyCt<LOGN>> {
        let _ = self;
        Err(Error::Internal)
    }
}

impl<const LOGN: u32> ExpandedSecretKeyCt<LOGN> {
    pub fn sign_ct_strict(
        &self,
        msg: &[u8],
        comp: Compression,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DetachedSignature<LOGN>> {
        let _ = (self, msg, comp, rng);
        Err(Error::Internal)
    }

    pub fn sign_ct_strict_with_external_nonce(
        &self,
        msg: &[u8],
        nonce: Nonce,
        comp: Compression,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DetachedSignature<LOGN>> {
        let _ = (self, msg, nonce, comp, rng);
        Err(Error::Internal)
    }
}

impl<const LOGN: u32> PublicKey<LOGN> {
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let _ = bytes;
        Err(Error::Internal)
    }

    pub fn prepare(&self) -> Result<PreparedPublicKey<LOGN>> {
        let _ = self;
        Err(Error::Internal)
    }

    pub fn verify_detached(&self, msg: &[u8], sig: &DetachedSignature<LOGN>) -> Result<()> {
        let _ = (self, msg, sig);
        Err(Error::Internal)
    }
}

impl<const LOGN: u32> PreparedPublicKey<LOGN> {
    pub fn verify_detached(&self, msg: &[u8], sig: &DetachedSignature<LOGN>) -> Result<()> {
        let _ = (self, msg, sig);
        Err(Error::Internal)
    }

    pub fn verifier(&self, nonce: &Nonce) -> Verifier<LOGN> {
        Verifier {
            nonce: nonce.clone(),
            message_len: 0,
            prepared_len: self.inner.bytes.len(),
        }
    }
}

impl<const LOGN: u32> Verifier<LOGN> {
    pub fn update(&mut self, chunk: &[u8]) {
        self.message_len = self.message_len.saturating_add(chunk.len());
    }

    pub fn finalize(self, sig_body: &[u8]) -> Result<()> {
        let _ = (self.nonce, self.message_len, self.prepared_len, sig_body);
        Err(Error::Internal)
    }
}

impl Nonce {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec().into_boxed_slice())
    }
}

impl<const LOGN: u32> DetachedSignature<LOGN> {
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }
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
