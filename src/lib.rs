//! Falcon 2017 / Extra Rust port.

mod compression;
mod encoding;
mod error;
mod falcon;
#[cfg(feature = "hazmat")]
pub mod hazmat;
mod math;
mod params;
mod rng;
mod sampler;
mod types;

pub use compression::Compression;
pub use error::{Error, Result};
pub use types::{
    DetachedSignature, ExpandedSecretKeyCt, Falcon1024, Falcon1024Keypair, Falcon512,
    Falcon512Keypair, Keypair, Nonce, PreparedPublicKey, PublicKey, SecretKey, Verifier,
};
