//! Public error types.

use core::fmt;

/// Result type used by the public Falcon API.
pub type Result<T> = core::result::Result<T, Error>;

/// Public error surface for the Falcon 2017 / Extra API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidEncoding,
    InvalidSignature,
    InvalidParameter,
    Randomness,
    Internal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEncoding => "invalid Falcon encoding",
            Self::InvalidSignature => "invalid Falcon signature",
            Self::InvalidParameter => "invalid Falcon parameter",
            Self::Randomness => "randomness source failure",
            Self::Internal => "internal Falcon error",
        };
        f.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
