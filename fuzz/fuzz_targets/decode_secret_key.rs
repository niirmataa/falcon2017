#![no_main]

use core::convert::TryFrom;
use libfuzzer_sys::fuzz_target;

#[path = "../../src/compression.rs"]
mod compression;
#[path = "../../src/error.rs"]
mod error;
#[path = "../../src/encoding/secret_key.rs"]
pub mod encoding_secret_key;
#[path = "../../src/encoding/smallvec.rs"]
pub mod encoding_smallvec;

mod encoding {
    pub(crate) fn binary_len(logn: u32) -> usize {
        1usize << logn
    }

    pub(crate) fn ternary_len(logn: u32) -> usize {
        3usize << (logn - 1)
    }

    pub(crate) use crate::encoding_secret_key as secret_key;
    pub(crate) use crate::encoding_smallvec as smallvec;
}

fuzz_target!(|data: &[u8]| {
    let decoded = encoding::secret_key::decode(data);
    if let Ok(decoded) = decoded {
        let f = decoded
            .f
            .iter()
            .copied()
            .map(i8::try_from)
            .collect::<Result<Vec<_>, _>>();
        let g = decoded
            .g
            .iter()
            .copied()
            .map(i8::try_from)
            .collect::<Result<Vec<_>, _>>();
        if let (Ok(f), Ok(g)) = (f, g) {
            let _ = encoding::secret_key::encode(
                decoded.ternary,
                decoded.compression,
                decoded.logn,
                &f,
                &g,
                &decoded.big_f,
                &decoded.big_g,
            );
        }
    }
});
