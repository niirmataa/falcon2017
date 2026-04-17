//! Compression mode definitions.

/// Compression modes supported by the Falcon 2017 / Extra wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    None,
    Static,
}
