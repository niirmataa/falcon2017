//! Public API types.

use crate::compression::Compression;
use crate::encoding::secret_key;
use crate::error::{Error, Result};
use crate::falcon::expand_ct;
use crate::falcon::keygen;
use crate::falcon::sign_ct_strict as sign_ct_strict_backend;
use crate::falcon::sign_ref;
use crate::falcon::verify;
use crate::falcon::workspace::{KeygenWorkspace, SignRefWorkspace, VerifyWorkspace};
use crate::math::fpr::soft::Fpr as SoftFpr;
use crate::params::{FALCON1024_LOGN, FALCON512_LOGN};
use crate::rng::shake256::ShakeContext;
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
    pub(crate) hash: ShakeContext,
    pub(crate) h_ntt: Box<[u16]>,
}

#[derive(Debug)]
pub(crate) struct PreparedPublicKeyInner<const LOGN: u32> {
    pub(crate) h_ntt: Box<[u16]>,
}

pub(crate) struct SecretKeyInner<const LOGN: u32> {
    pub(crate) f: Box<[i8]>,
    pub(crate) g: Box<[i8]>,
    pub(crate) big_f: Box<[i8]>,
    pub(crate) big_g: Box<[i8]>,
}

pub(crate) struct ExpandedSecretKeyCtInner<const LOGN: u32> {
    pub(crate) b00: Box<[SoftFpr]>,
    pub(crate) b01: Box<[SoftFpr]>,
    pub(crate) b10: Box<[SoftFpr]>,
    pub(crate) b11: Box<[SoftFpr]>,
    pub(crate) tree: Box<[SoftFpr]>,
}

impl Falcon512 {
    pub fn keygen(rng: &mut (impl RngCore + CryptoRng)) -> Result<Falcon512Keypair> {
        keygen::keygen_with_rng::<FALCON512_LOGN>(rng)
    }

    pub fn keygen_in(
        rng: &mut (impl RngCore + CryptoRng),
        ws: &mut KeygenWorkspace<FALCON512_LOGN>,
    ) -> Result<Falcon512Keypair> {
        keygen::keygen_with_rng_in::<FALCON512_LOGN>(rng, ws)
    }

    #[cfg(feature = "deterministic-tests")]
    pub fn keygen_from_seed(seed: &[u8]) -> Result<Falcon512Keypair> {
        keygen::keygen_from_seed_material::<FALCON512_LOGN>(seed)
    }

    #[cfg(feature = "deterministic-tests")]
    pub fn keygen_from_seed_in(
        seed: &[u8],
        ws: &mut KeygenWorkspace<FALCON512_LOGN>,
    ) -> Result<Falcon512Keypair> {
        keygen::keygen_from_seed_material_in::<FALCON512_LOGN>(seed, ws)
    }
}

impl Falcon1024 {
    pub fn keygen(rng: &mut (impl RngCore + CryptoRng)) -> Result<Falcon1024Keypair> {
        keygen::keygen_with_rng::<FALCON1024_LOGN>(rng)
    }

    pub fn keygen_in(
        rng: &mut (impl RngCore + CryptoRng),
        ws: &mut KeygenWorkspace<FALCON1024_LOGN>,
    ) -> Result<Falcon1024Keypair> {
        keygen::keygen_with_rng_in::<FALCON1024_LOGN>(rng, ws)
    }

    #[cfg(feature = "deterministic-tests")]
    pub fn keygen_from_seed(seed: &[u8]) -> Result<Falcon1024Keypair> {
        keygen::keygen_from_seed_material::<FALCON1024_LOGN>(seed)
    }

    #[cfg(feature = "deterministic-tests")]
    pub fn keygen_from_seed_in(
        seed: &[u8],
        ws: &mut KeygenWorkspace<FALCON1024_LOGN>,
    ) -> Result<Falcon1024Keypair> {
        keygen::keygen_from_seed_material_in::<FALCON1024_LOGN>(seed, ws)
    }
}

impl<const LOGN: u32> SecretKey<LOGN> {
    pub fn to_bytes(&self, comp: Compression) -> Box<[u8]> {
        secret_key::encode(
            false,
            comp,
            LOGN,
            &self.inner.f,
            &self.inner.g,
            &self.inner.big_f,
            &self.inner.big_g,
        )
        .expect("SecretKey always holds a baseline-compatible binary key")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let decoded = secret_key::decode(bytes)?;
        if decoded.ternary || decoded.logn != LOGN {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self {
            inner: SecretKeyInner {
                f: poly_i8_from_i16(&decoded.f)?,
                g: poly_i8_from_i16(&decoded.g)?,
                big_f: poly_i8_from_i16(&decoded.big_f)?,
                big_g: poly_i8_from_i16(&decoded.big_g)?,
            },
        })
    }

    pub fn derive_public(&self) -> Result<PublicKey<LOGN>> {
        keygen::derive_public_from_secret(self)
    }

    pub fn sign_ref(
        &self,
        msg: &[u8],
        comp: Compression,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DetachedSignature<LOGN>> {
        sign_ref::sign_ref(self, msg, comp, rng)
    }

    pub fn sign_ref_in(
        &self,
        msg: &[u8],
        comp: Compression,
        rng: &mut (impl RngCore + CryptoRng),
        ws: &mut SignRefWorkspace<LOGN>,
    ) -> Result<DetachedSignature<LOGN>> {
        sign_ref::sign_ref_in(self, msg, comp, rng, ws)
    }

    pub fn sign_ref_with_external_nonce(
        &self,
        msg: &[u8],
        nonce: Nonce,
        comp: Compression,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DetachedSignature<LOGN>> {
        sign_ref::sign_ref_with_external_nonce(self, msg, nonce, comp, rng)
    }

    pub fn sign_ref_with_external_nonce_in(
        &self,
        msg: &[u8],
        nonce: Nonce,
        comp: Compression,
        rng: &mut (impl RngCore + CryptoRng),
        ws: &mut SignRefWorkspace<LOGN>,
    ) -> Result<DetachedSignature<LOGN>> {
        sign_ref::sign_ref_with_external_nonce_in(self, msg, nonce, comp, rng, ws)
    }

    pub fn expand_ct_strict(&self) -> Result<ExpandedSecretKeyCt<LOGN>> {
        expand_ct::expand_ct_strict(self)
    }
}

fn poly_i8_from_i16(values: &[i16]) -> Result<Box<[i8]>> {
    let mut out = Vec::with_capacity(values.len());
    for &value in values {
        let value = i8::try_from(value).map_err(|_| Error::InvalidEncoding)?;
        out.push(value);
    }
    Ok(out.into_boxed_slice())
}

impl<const LOGN: u32> ExpandedSecretKeyCt<LOGN> {
    pub fn sign_ct_strict(
        &self,
        msg: &[u8],
        comp: Compression,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DetachedSignature<LOGN>> {
        sign_ct_strict_backend::sign_ct_strict(self, msg, comp, rng)
    }

    pub fn sign_ct_strict_with_external_nonce(
        &self,
        msg: &[u8],
        nonce: Nonce,
        comp: Compression,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<DetachedSignature<LOGN>> {
        sign_ct_strict_backend::sign_ct_strict_with_external_nonce(self, msg, nonce, comp, rng)
    }
}

impl<const LOGN: u32> PublicKey<LOGN> {
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        verify::public_key_from_bytes(bytes)
    }

    pub fn prepare(&self) -> Result<PreparedPublicKey<LOGN>> {
        verify::prepare_public_key(self)
    }

    pub fn verify_detached(&self, msg: &[u8], sig: &DetachedSignature<LOGN>) -> Result<()> {
        verify::verify_detached(self, msg, sig)
    }

    pub fn verify_detached_in(
        &self,
        msg: &[u8],
        sig: &DetachedSignature<LOGN>,
        ws: &mut VerifyWorkspace<LOGN>,
    ) -> Result<()> {
        verify::verify_detached_in(self, msg, sig, ws)
    }
}

impl<const LOGN: u32> PreparedPublicKey<LOGN> {
    pub fn verify_detached(&self, msg: &[u8], sig: &DetachedSignature<LOGN>) -> Result<()> {
        verify::verify_prepared_detached(self, msg, sig)
    }

    pub fn verify_detached_in(
        &self,
        msg: &[u8],
        sig: &DetachedSignature<LOGN>,
        ws: &mut VerifyWorkspace<LOGN>,
    ) -> Result<()> {
        verify::verify_prepared_detached_in(self, msg, sig, ws)
    }

    pub fn verifier(&self, nonce: &Nonce) -> Verifier<LOGN> {
        verify::start_verifier(self, nonce)
    }
}

impl<const LOGN: u32> Verifier<LOGN> {
    pub fn update(&mut self, chunk: &[u8]) {
        self.hash.inject(chunk);
    }

    pub fn finalize(self, sig_body: &[u8]) -> Result<()> {
        verify::finalize_verifier(self, sig_body)
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
fn zeroize_soft_fpr(buf: &mut [SoftFpr]) {
    for value in buf {
        *value = SoftFpr::from_bits(0);
    }
}

#[cfg(feature = "zeroize")]
impl<const LOGN: u32> Drop for ExpandedSecretKeyCtInner<LOGN> {
    fn drop(&mut self) {
        zeroize_soft_fpr(self.b00.as_mut());
        zeroize_soft_fpr(self.b01.as_mut());
        zeroize_soft_fpr(self.b10.as_mut());
        zeroize_soft_fpr(self.b11.as_mut());
        zeroize_soft_fpr(self.tree.as_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::SecretKey;
    use crate::compression::Compression;

    const REF_SECRET_KEY_NONE: [u8; 129] = [
        4, 0, 10, 0, 11, 255, 245, 0, 24, 255, 237, 255, 252, 255, 235, 0, 27, 255, 230, 0, 6, 255,
        239, 255, 255, 0, 39, 0, 5, 0, 18, 255, 244, 0, 24, 0, 25, 255, 252, 255, 241, 0, 6, 0, 14,
        0, 28, 255, 253, 0, 20, 0, 27, 0, 53, 0, 17, 0, 1, 255, 215, 255, 218, 0, 31, 255, 242, 0,
        51, 255, 225, 255, 195, 0, 13, 0, 26, 0, 55, 0, 43, 255, 232, 255, 248, 255, 255, 0, 33, 0,
        3, 0, 34, 255, 232, 0, 51, 0, 55, 0, 20, 255, 231, 0, 61, 0, 52, 255, 255, 255, 214, 255,
        255, 0, 49, 255, 242, 0, 36, 255, 229, 0, 10, 0, 5, 0, 3, 255, 192,
    ];

    #[test]
    fn secret_key_from_bytes_matches_reference_none_encoding() {
        let sk = SecretKey::<4>::from_bytes(&REF_SECRET_KEY_NONE).expect("reference bytes");

        assert_eq!(
            &*sk.inner.f,
            &[10, 11, -11, 24, -19, -4, -21, 27, -26, 6, -17, -1, 39, 5, 18, -12]
        );
        assert_eq!(
            &*sk.inner.g,
            &[24, 25, -4, -15, 6, 14, 28, -3, 20, 27, 53, 17, 1, -41, -38, 31]
        );
        assert_eq!(
            &*sk.inner.big_f,
            &[-14, 51, -31, -61, 13, 26, 55, 43, -24, -8, -1, 33, 3, 34, -24, 51]
        );
        assert_eq!(
            &*sk.inner.big_g,
            &[55, 20, -25, 61, 52, -1, -42, -1, 49, -14, 36, -27, 10, 5, 3, -64]
        );
        assert_eq!(&*sk.to_bytes(Compression::None), &REF_SECRET_KEY_NONE);
    }

    #[test]
    fn secret_key_static_roundtrip_preserves_reference_key() {
        let sk = SecretKey::<4>::from_bytes(&REF_SECRET_KEY_NONE).expect("reference bytes");
        let encoded = sk.to_bytes(Compression::Static);
        let decoded = SecretKey::<4>::from_bytes(&encoded).expect("static roundtrip");

        assert_eq!(&*decoded.inner.f, &*sk.inner.f);
        assert_eq!(&*decoded.inner.g, &*sk.inner.g);
        assert_eq!(&*decoded.inner.big_f, &*sk.inner.big_f);
        assert_eq!(&*decoded.inner.big_g, &*sk.inner.big_g);
    }
}
