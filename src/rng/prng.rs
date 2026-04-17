//! Portable PRNG ported from the Falcon 2017 baseline.

use crate::rng::shake256::ShakeContext;

pub const PRNG_CHACHA20: i32 = 1;
pub const PRNG_CHACHA20_SSE2: i32 = 2;
pub const PRNG_AES_X86NI: i32 = 3;

const PRNG_BUFFER_SIZE: usize = 4096;
const PRNG_STATE_SIZE: usize = 56;
const CHACHA_CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[derive(Clone, Debug)]
pub struct Prng {
    pub(crate) buf: [u8; PRNG_BUFFER_SIZE],
    pub(crate) ptr: usize,
    pub(crate) state: [u8; PRNG_STATE_SIZE],
    pub(crate) prng_type: i32,
}

impl Prng {
    pub fn new(src: &mut ShakeContext, prng_type: i32) -> Option<Self> {
        let used_type = if prng_type == 0 {
            PRNG_CHACHA20
        } else {
            prng_type
        };

        if used_type != PRNG_CHACHA20 {
            return None;
        }

        let mut prng = Self {
            buf: [0; PRNG_BUFFER_SIZE],
            ptr: 0,
            state: [0; PRNG_STATE_SIZE],
            prng_type: used_type,
        };
        src.extract(&mut prng.state);
        prng.refill();
        Some(prng)
    }

    pub fn prng_type(&self) -> i32 {
        self.prng_type
    }

    pub fn refill(&mut self) {
        match self.prng_type {
            PRNG_CHACHA20 => refill_chacha20(self),
            _ => unreachable!("unsupported PRNG type"),
        }
        self.ptr = 0;
    }

    pub fn get_bytes(&mut self, mut dst: &mut [u8]) {
        while !dst.is_empty() {
            let clen = (self.buf.len() - self.ptr).min(dst.len());
            dst[..clen].copy_from_slice(&self.buf[self.ptr..self.ptr + clen]);
            dst = &mut dst[clen..];
            self.ptr += clen;
            if self.ptr == self.buf.len() {
                self.refill();
            }
        }
    }

    pub fn get_u64(&mut self) -> u64 {
        let mut u = self.ptr;
        if u >= self.buf.len() - 9 {
            self.refill();
            u = 0;
        }
        self.ptr = u + 8;
        read_u64_le(&self.buf[u..u + 8])
    }

    pub fn get_u8(&mut self) -> u8 {
        let v = self.buf[self.ptr];
        self.ptr += 1;
        if self.ptr == self.buf.len() {
            self.refill();
        }
        v
    }
}

fn refill_chacha20(prng: &mut Prng) {
    let mut cc = read_u64_le(&prng.state[48..56]);
    for offset in (0..prng.buf.len()).step_by(64) {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&CHACHA_CONSTANTS);
        for (idx, word) in state[4..16].iter_mut().enumerate() {
            let start = idx * 4;
            *word = read_u32_le(&prng.state[start..start + 4]);
        }
        state[14] ^= cc as u32;
        state[15] ^= (cc >> 32) as u32;

        for _ in 0..10 {
            quarter_round(&mut state, 0, 4, 8, 12);
            quarter_round(&mut state, 1, 5, 9, 13);
            quarter_round(&mut state, 2, 6, 10, 14);
            quarter_round(&mut state, 3, 7, 11, 15);
            quarter_round(&mut state, 0, 5, 10, 15);
            quarter_round(&mut state, 1, 6, 11, 12);
            quarter_round(&mut state, 2, 7, 8, 13);
            quarter_round(&mut state, 3, 4, 9, 14);
        }

        for idx in 0..4 {
            state[idx] = state[idx].wrapping_add(CHACHA_CONSTANTS[idx]);
        }
        for idx in 4..14 {
            let start = (idx - 4) * 4;
            state[idx] = state[idx].wrapping_add(read_u32_le(&prng.state[start..start + 4]));
        }
        state[14] = state[14]
            .wrapping_add(read_u32_le(&prng.state[40..44]))
            .wrapping_add(cc as u32);
        state[15] = state[15]
            .wrapping_add(read_u32_le(&prng.state[44..48]))
            .wrapping_add((cc >> 32) as u32);
        cc = cc.wrapping_add(1);

        for (idx, word) in state.iter().enumerate() {
            let start = offset + (idx * 4);
            prng.buf[start..start + 4].copy_from_slice(&word.to_le_bytes());
        }
    }
    prng.state[48..56].copy_from_slice(&cc.to_le_bytes());
}

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[inline]
fn read_u32_le(src: &[u8]) -> u32 {
    u32::from_le_bytes(src[..4].try_into().expect("read_u32_le needs 4 bytes"))
}

#[inline]
fn read_u64_le(src: &[u8]) -> u64 {
    u64::from_le_bytes(src[..8].try_into().expect("read_u64_le needs 8 bytes"))
}
