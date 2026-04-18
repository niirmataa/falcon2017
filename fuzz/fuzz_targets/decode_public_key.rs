#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../src/error.rs"]
mod error;
#[path = "../../src/encoding/public_key.rs"]
pub mod encoding_public_key;
#[path = "../../src/encoding/ring12289.rs"]
pub mod encoding_ring12289;
#[path = "../../src/encoding/ring18433.rs"]
pub mod encoding_ring18433;

mod encoding {
    pub(crate) fn binary_len(logn: u32) -> usize {
        1usize << logn
    }

    pub(crate) fn ternary_len(logn: u32) -> usize {
        3usize << (logn - 1)
    }

    pub(crate) use crate::encoding_public_key as public_key;
    pub(crate) use crate::encoding_ring12289 as ring12289;
    pub(crate) use crate::encoding_ring18433 as ring18433;
}

fuzz_target!(|data: &[u8]| {
    let decoded = encoding::public_key::decode(data);
    if let Ok(decoded) = decoded {
        let _ = encoding::public_key::encode(decoded.ternary, decoded.logn, &decoded.h);
    }
});
