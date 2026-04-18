#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../src/compression.rs"]
mod compression;
#[path = "../../src/error.rs"]
mod error;
#[path = "../../src/encoding/smallvec.rs"]
pub mod encoding_smallvec;
#[path = "../../src/encoding/signature.rs"]
pub mod encoding_signature;

mod encoding {
    pub(crate) fn binary_len(logn: u32) -> usize {
        1usize << logn
    }

    pub(crate) fn ternary_len(logn: u32) -> usize {
        3usize << (logn - 1)
    }

    pub(crate) use crate::encoding_signature as signature;
    pub(crate) use crate::encoding_smallvec as smallvec;
}

fuzz_target!(|data: &[u8]| {
    let decoded = encoding::signature::decode(data);
    if let Ok(decoded) = decoded {
        let _ = encoding::signature::encode(
            decoded.ternary,
            decoded.compression,
            decoded.logn,
            &decoded.s2,
        );
    }
});
