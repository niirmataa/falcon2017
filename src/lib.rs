//! Falcon 2017 / Extra Rust port.

pub mod compression;
pub mod encoding;
pub mod error;
pub mod falcon;
pub mod hazmat;
pub mod math;
pub mod params;
pub mod rng;
pub mod sampler;
pub mod types;

pub use compression::Compression;
pub use error::{Error, Result};
pub use types::{
    DetachedSignature, ExpandedSecretKeyCt, Falcon1024, Falcon1024Keypair, Falcon512,
    Falcon512Keypair, Keypair, Nonce, PreparedPublicKey, PublicKey, SecretKey, Verifier,
};
