//! SHAKE state and sponge operations ported from `shake.h` / `shake.c`.

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub const SHAKE128_CAPACITY: usize = 256;
pub const SHAKE256_CAPACITY: usize = 512;

const SHAKE_STATE_BYTES: usize = 200;
const SHAKE_LANES: usize = 25;
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

#[derive(Clone, Debug)]
pub struct ShakeContext {
    dbuf: [u8; SHAKE_STATE_BYTES],
    dptr: usize,
    rate: usize,
    a: [u64; SHAKE_LANES],
}

impl ShakeContext {
    pub fn new(capacity: usize) -> Self {
        let mut context = Self {
            dbuf: [0; SHAKE_STATE_BYTES],
            dptr: 0,
            rate: 0,
            a: [0; SHAKE_LANES],
        };
        context.init(capacity);
        context
    }

    pub fn shake128() -> Self {
        Self::new(SHAKE128_CAPACITY)
    }

    pub fn shake256() -> Self {
        Self::new(SHAKE256_CAPACITY)
    }

    pub fn init(&mut self, capacity: usize) {
        debug_assert!(capacity.is_multiple_of(64));
        debug_assert!((64..=1600).contains(&capacity));

        self.rate = SHAKE_STATE_BYTES - (capacity >> 3);
        self.dptr = 0;
        self.a = [0; SHAKE_LANES];
        self.a[1] = u64::MAX;
        self.a[2] = u64::MAX;
        self.a[8] = u64::MAX;
        self.a[12] = u64::MAX;
        self.a[17] = u64::MAX;
        self.a[20] = u64::MAX;
    }

    pub fn inject(&mut self, mut data: &[u8]) {
        let rate = self.rate;
        let mut dptr = self.dptr;
        while !data.is_empty() {
            let clen = (rate - dptr).min(data.len());
            self.dbuf[dptr..dptr + clen].copy_from_slice(&data[..clen]);
            dptr += clen;
            data = &data[clen..];
            if dptr == rate {
                xor_block(&mut self.a, &self.dbuf, rate);
                process_block(&mut self.a);
                dptr = 0;
            }
        }
        self.dptr = dptr;
    }

    pub fn flip(&mut self) {
        if (self.dptr + 1) == self.rate {
            self.dbuf[self.dptr] = 0x9f;
            self.dptr += 1;
        } else {
            self.dbuf[self.dptr] = 0x1f;
            self.dptr += 1;
            self.dbuf[self.dptr..self.rate - 1].fill(0);
            self.dbuf[self.rate - 1] = 0x80;
            self.dptr = self.rate;
        }
        xor_block(&mut self.a, &self.dbuf, self.rate);
    }

    pub fn extract(&mut self, mut out: &mut [u8]) {
        let rate = self.rate;
        let mut dptr = self.dptr;
        while !out.is_empty() {
            if dptr == rate {
                process_block(&mut self.a);
                enc64le(&mut self.dbuf[0..8], self.a[0]);
                enc64le(&mut self.dbuf[8..16], !self.a[1]);
                enc64le(&mut self.dbuf[16..24], !self.a[2]);
                enc64le(&mut self.dbuf[24..32], self.a[3]);
                enc64le(&mut self.dbuf[32..40], self.a[4]);
                enc64le(&mut self.dbuf[40..48], self.a[5]);
                enc64le(&mut self.dbuf[48..56], self.a[6]);
                enc64le(&mut self.dbuf[56..64], self.a[7]);
                enc64le(&mut self.dbuf[64..72], !self.a[8]);
                enc64le(&mut self.dbuf[72..80], self.a[9]);
                enc64le(&mut self.dbuf[80..88], self.a[10]);
                enc64le(&mut self.dbuf[88..96], self.a[11]);
                enc64le(&mut self.dbuf[96..104], !self.a[12]);
                enc64le(&mut self.dbuf[104..112], self.a[13]);
                enc64le(&mut self.dbuf[112..120], self.a[14]);
                enc64le(&mut self.dbuf[120..128], self.a[15]);
                enc64le(&mut self.dbuf[128..136], self.a[16]);
                enc64le(&mut self.dbuf[136..144], !self.a[17]);
                enc64le(&mut self.dbuf[144..152], self.a[18]);
                enc64le(&mut self.dbuf[152..160], self.a[19]);
                enc64le(&mut self.dbuf[160..168], !self.a[20]);
                enc64le(&mut self.dbuf[168..176], self.a[21]);
                enc64le(&mut self.dbuf[176..184], self.a[22]);
                enc64le(&mut self.dbuf[184..192], self.a[23]);
                enc64le(&mut self.dbuf[192..200], self.a[24]);
                dptr = 0;
            }
            let clen = (rate - dptr).min(out.len());
            out[..clen].copy_from_slice(&self.dbuf[dptr..dptr + clen]);
            dptr += clen;
            out = &mut out[clen..];
        }
        self.dptr = dptr;
    }

    pub fn digest(capacity: usize, input: &[u8], out: &mut [u8]) {
        let mut context = Self::new(capacity);
        context.inject(input);
        context.flip();
        context.extract(out);
    }
}

#[cfg(feature = "zeroize")]
impl Drop for ShakeContext {
    fn drop(&mut self) {
        self.dbuf.zeroize();
        self.dptr.zeroize();
        self.rate.zeroize();
        self.a.zeroize();
    }
}

#[inline]
fn dec64le(data: &[u8]) -> u64 {
    u64::from_le_bytes(data[..8].try_into().expect("dec64le needs 8 bytes"))
}

#[inline]
fn enc64le(out: &mut [u8], x: u64) {
    out[..8].copy_from_slice(&x.to_le_bytes());
}

fn xor_block(a: &mut [u64; SHAKE_LANES], data: &[u8], rate: usize) {
    for u in (0..rate).step_by(8) {
        a[u >> 3] ^= dec64le(&data[u..u + 8]);
    }
}

fn process_block(a: &mut [u64; SHAKE_LANES]) {
    for j in (0..24).step_by(2) {
        let mut tt0 = a[1] ^ a[6];
        let tt1 = a[11] ^ a[16];
        tt0 ^= a[21] ^ tt1;
        tt0 = tt0.rotate_left(1);
        let mut tt2 = a[4] ^ a[9];
        let tt3 = a[14] ^ a[19];
        tt0 ^= a[24];
        tt2 ^= tt3;
        let t0 = tt0 ^ tt2;

        let mut tt0 = a[2] ^ a[7];
        let tt1 = a[12] ^ a[17];
        tt0 ^= a[22] ^ tt1;
        tt0 = tt0.rotate_left(1);
        let mut tt2 = a[0] ^ a[5];
        let tt3 = a[10] ^ a[15];
        tt0 ^= a[20];
        tt2 ^= tt3;
        let t1 = tt0 ^ tt2;

        let mut tt0 = a[3] ^ a[8];
        let tt1 = a[13] ^ a[18];
        tt0 ^= a[23] ^ tt1;
        tt0 = tt0.rotate_left(1);
        let mut tt2 = a[1] ^ a[6];
        let tt3 = a[11] ^ a[16];
        tt0 ^= a[21];
        tt2 ^= tt3;
        let t2 = tt0 ^ tt2;

        let mut tt0 = a[4] ^ a[9];
        let tt1 = a[14] ^ a[19];
        tt0 ^= a[24] ^ tt1;
        tt0 = tt0.rotate_left(1);
        let mut tt2 = a[2] ^ a[7];
        let tt3 = a[12] ^ a[17];
        tt0 ^= a[22];
        tt2 ^= tt3;
        let t3 = tt0 ^ tt2;

        let mut tt0 = a[0] ^ a[5];
        let tt1 = a[10] ^ a[15];
        tt0 ^= a[20] ^ tt1;
        tt0 = tt0.rotate_left(1);
        let mut tt2 = a[3] ^ a[8];
        let tt3 = a[13] ^ a[18];
        tt0 ^= a[23];
        tt2 ^= tt3;
        let t4 = tt0 ^ tt2;

        a[0] ^= t0;
        a[5] ^= t0;
        a[10] ^= t0;
        a[15] ^= t0;
        a[20] ^= t0;
        a[1] ^= t1;
        a[6] ^= t1;
        a[11] ^= t1;
        a[16] ^= t1;
        a[21] ^= t1;
        a[2] ^= t2;
        a[7] ^= t2;
        a[12] ^= t2;
        a[17] ^= t2;
        a[22] ^= t2;
        a[3] ^= t3;
        a[8] ^= t3;
        a[13] ^= t3;
        a[18] ^= t3;
        a[23] ^= t3;
        a[4] ^= t4;
        a[9] ^= t4;
        a[14] ^= t4;
        a[19] ^= t4;
        a[24] ^= t4;
        a[5] = a[5].rotate_left(36);
        a[10] = a[10].rotate_left(3);
        a[15] = a[15].rotate_left(41);
        a[20] = a[20].rotate_left(18);
        a[1] = a[1].rotate_left(1);
        a[6] = a[6].rotate_left(44);
        a[11] = a[11].rotate_left(10);
        a[16] = a[16].rotate_left(45);
        a[21] = a[21].rotate_left(2);
        a[2] = a[2].rotate_left(62);
        a[7] = a[7].rotate_left(6);
        a[12] = a[12].rotate_left(43);
        a[17] = a[17].rotate_left(15);
        a[22] = a[22].rotate_left(61);
        a[3] = a[3].rotate_left(28);
        a[8] = a[8].rotate_left(55);
        a[13] = a[13].rotate_left(25);
        a[18] = a[18].rotate_left(21);
        a[23] = a[23].rotate_left(56);
        a[4] = a[4].rotate_left(27);
        a[9] = a[9].rotate_left(20);
        a[14] = a[14].rotate_left(39);
        a[19] = a[19].rotate_left(8);
        a[24] = a[24].rotate_left(14);

        let mut bnn = !a[12];
        let mut kt = a[6] | a[12];
        let c0 = a[0] ^ kt;
        kt = bnn | a[18];
        let c1 = a[6] ^ kt;
        kt = a[18] & a[24];
        let c2 = a[12] ^ kt;
        kt = a[24] | a[0];
        let c3 = a[18] ^ kt;
        kt = a[0] & a[6];
        let c4 = a[24] ^ kt;
        a[0] = c0;
        a[6] = c1;
        a[12] = c2;
        a[18] = c3;
        a[24] = c4;

        bnn = !a[22];
        kt = a[9] | a[10];
        let c0 = a[3] ^ kt;
        kt = a[10] & a[16];
        let c1 = a[9] ^ kt;
        kt = a[16] | bnn;
        let c2 = a[10] ^ kt;
        kt = a[22] | a[3];
        let c3 = a[16] ^ kt;
        kt = a[3] & a[9];
        let c4 = a[22] ^ kt;
        a[3] = c0;
        a[9] = c1;
        a[10] = c2;
        a[16] = c3;
        a[22] = c4;

        bnn = !a[19];
        kt = a[7] | a[13];
        let c0 = a[1] ^ kt;
        kt = a[13] & a[19];
        let c1 = a[7] ^ kt;
        kt = bnn & a[20];
        let c2 = a[13] ^ kt;
        kt = a[20] | a[1];
        let c3 = bnn ^ kt;
        kt = a[1] & a[7];
        let c4 = a[20] ^ kt;
        a[1] = c0;
        a[7] = c1;
        a[13] = c2;
        a[19] = c3;
        a[20] = c4;

        bnn = !a[17];
        kt = a[5] & a[11];
        let c0 = a[4] ^ kt;
        kt = a[11] | a[17];
        let c1 = a[5] ^ kt;
        kt = bnn | a[23];
        let c2 = a[11] ^ kt;
        kt = a[23] & a[4];
        let c3 = bnn ^ kt;
        kt = a[4] | a[5];
        let c4 = a[23] ^ kt;
        a[4] = c0;
        a[5] = c1;
        a[11] = c2;
        a[17] = c3;
        a[23] = c4;

        bnn = !a[8];
        kt = bnn & a[14];
        let c0 = a[2] ^ kt;
        kt = a[14] | a[15];
        let c1 = bnn ^ kt;
        kt = a[15] & a[21];
        let c2 = a[14] ^ kt;
        kt = a[21] | a[2];
        let c3 = a[15] ^ kt;
        kt = a[2] & a[8];
        let c4 = a[21] ^ kt;
        a[2] = c0;
        a[8] = c1;
        a[14] = c2;
        a[15] = c3;
        a[21] = c4;
        a[0] ^= ROUND_CONSTANTS[j];

        let mut tt0 = a[6] ^ a[9];
        let tt1 = a[7] ^ a[5];
        tt0 ^= a[8] ^ tt1;
        tt0 = tt0.rotate_left(1);
        let mut tt2 = a[24] ^ a[22];
        let tt3 = a[20] ^ a[23];
        tt0 ^= a[21];
        tt2 ^= tt3;
        let t0 = tt0 ^ tt2;

        let mut tt0 = a[12] ^ a[10];
        let tt1 = a[13] ^ a[11];
        tt0 ^= a[14] ^ tt1;
        tt0 = tt0.rotate_left(1);
        let mut tt2 = a[0] ^ a[3];
        let tt3 = a[1] ^ a[4];
        tt0 ^= a[2];
        tt2 ^= tt3;
        let t1 = tt0 ^ tt2;

        let mut tt0 = a[18] ^ a[16];
        let tt1 = a[19] ^ a[17];
        tt0 ^= a[15] ^ tt1;
        tt0 = tt0.rotate_left(1);
        let mut tt2 = a[6] ^ a[9];
        let tt3 = a[7] ^ a[5];
        tt0 ^= a[8];
        tt2 ^= tt3;
        let t2 = tt0 ^ tt2;

        let mut tt0 = a[24] ^ a[22];
        let tt1 = a[20] ^ a[23];
        tt0 ^= a[21] ^ tt1;
        tt0 = tt0.rotate_left(1);
        let mut tt2 = a[12] ^ a[10];
        let tt3 = a[13] ^ a[11];
        tt0 ^= a[14];
        tt2 ^= tt3;
        let t3 = tt0 ^ tt2;

        let mut tt0 = a[0] ^ a[3];
        let tt1 = a[1] ^ a[4];
        tt0 ^= a[2] ^ tt1;
        tt0 = tt0.rotate_left(1);
        let mut tt2 = a[18] ^ a[16];
        let tt3 = a[19] ^ a[17];
        tt0 ^= a[15];
        tt2 ^= tt3;
        let t4 = tt0 ^ tt2;

        a[0] ^= t0;
        a[3] ^= t0;
        a[1] ^= t0;
        a[4] ^= t0;
        a[2] ^= t0;
        a[6] ^= t1;
        a[9] ^= t1;
        a[7] ^= t1;
        a[5] ^= t1;
        a[8] ^= t1;
        a[12] ^= t2;
        a[10] ^= t2;
        a[13] ^= t2;
        a[11] ^= t2;
        a[14] ^= t2;
        a[18] ^= t3;
        a[16] ^= t3;
        a[19] ^= t3;
        a[17] ^= t3;
        a[15] ^= t3;
        a[24] ^= t4;
        a[22] ^= t4;
        a[20] ^= t4;
        a[23] ^= t4;
        a[21] ^= t4;
        a[3] = a[3].rotate_left(36);
        a[1] = a[1].rotate_left(3);
        a[4] = a[4].rotate_left(41);
        a[2] = a[2].rotate_left(18);
        a[6] = a[6].rotate_left(1);
        a[9] = a[9].rotate_left(44);
        a[7] = a[7].rotate_left(10);
        a[5] = a[5].rotate_left(45);
        a[8] = a[8].rotate_left(2);
        a[12] = a[12].rotate_left(62);
        a[10] = a[10].rotate_left(6);
        a[13] = a[13].rotate_left(43);
        a[11] = a[11].rotate_left(15);
        a[14] = a[14].rotate_left(61);
        a[18] = a[18].rotate_left(28);
        a[16] = a[16].rotate_left(55);
        a[19] = a[19].rotate_left(25);
        a[17] = a[17].rotate_left(21);
        a[15] = a[15].rotate_left(56);
        a[24] = a[24].rotate_left(27);
        a[22] = a[22].rotate_left(20);
        a[20] = a[20].rotate_left(39);
        a[23] = a[23].rotate_left(8);
        a[21] = a[21].rotate_left(14);

        bnn = !a[13];
        kt = a[9] | a[13];
        let c0 = a[0] ^ kt;
        kt = bnn | a[17];
        let c1 = a[9] ^ kt;
        kt = a[17] & a[21];
        let c2 = a[13] ^ kt;
        kt = a[21] | a[0];
        let c3 = a[17] ^ kt;
        kt = a[0] & a[9];
        let c4 = a[21] ^ kt;
        a[0] = c0;
        a[9] = c1;
        a[13] = c2;
        a[17] = c3;
        a[21] = c4;

        bnn = !a[14];
        kt = a[22] | a[1];
        let c0 = a[18] ^ kt;
        kt = a[1] & a[5];
        let c1 = a[22] ^ kt;
        kt = a[5] | bnn;
        let c2 = a[1] ^ kt;
        kt = a[14] | a[18];
        let c3 = a[5] ^ kt;
        kt = a[18] & a[22];
        let c4 = a[14] ^ kt;
        a[18] = c0;
        a[22] = c1;
        a[1] = c2;
        a[5] = c3;
        a[14] = c4;

        bnn = !a[23];
        kt = a[10] | a[19];
        let c0 = a[6] ^ kt;
        kt = a[19] & a[23];
        let c1 = a[10] ^ kt;
        kt = bnn & a[2];
        let c2 = a[19] ^ kt;
        kt = a[2] | a[6];
        let c3 = bnn ^ kt;
        kt = a[6] & a[10];
        let c4 = a[2] ^ kt;
        a[6] = c0;
        a[10] = c1;
        a[19] = c2;
        a[23] = c3;
        a[2] = c4;

        bnn = !a[11];
        kt = a[3] & a[7];
        let c0 = a[24] ^ kt;
        kt = a[7] | a[11];
        let c1 = a[3] ^ kt;
        kt = bnn | a[15];
        let c2 = a[7] ^ kt;
        kt = a[15] & a[24];
        let c3 = bnn ^ kt;
        kt = a[24] | a[3];
        let c4 = a[15] ^ kt;
        a[24] = c0;
        a[3] = c1;
        a[7] = c2;
        a[11] = c3;
        a[15] = c4;

        bnn = !a[16];
        kt = bnn & a[20];
        let c0 = a[12] ^ kt;
        kt = a[20] | a[4];
        let c1 = bnn ^ kt;
        kt = a[4] & a[8];
        let c2 = a[20] ^ kt;
        kt = a[8] | a[12];
        let c3 = a[4] ^ kt;
        kt = a[12] & a[16];
        let c4 = a[8] ^ kt;
        a[12] = c0;
        a[16] = c1;
        a[20] = c2;
        a[4] = c3;
        a[8] = c4;
        a[0] ^= ROUND_CONSTANTS[j + 1];

        let t = a[5];
        a[5] = a[18];
        a[18] = a[11];
        a[11] = a[10];
        a[10] = a[6];
        a[6] = a[22];
        a[22] = a[20];
        a[20] = a[12];
        a[12] = a[19];
        a[19] = a[15];
        a[15] = a[24];
        a[24] = a[8];
        a[8] = t;

        let t = a[1];
        a[1] = a[9];
        a[9] = a[14];
        a[14] = a[2];
        a[2] = a[13];
        a[13] = a[23];
        a[23] = a[4];
        a[4] = a[21];
        a[21] = a[16];
        a[16] = a[3];
        a[3] = a[17];
        a[17] = a[7];
        a[7] = t;
    }
}

#[cfg(test)]
mod tests {
    use super::{ShakeContext, SHAKE128_CAPACITY, SHAKE256_CAPACITY};

    fn hex_to_bytes(src: &str) -> Vec<u8> {
        let filtered: String = src.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(filtered.len() % 2, 0, "hex string must have even length");
        filtered
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).expect("valid hex");
                let lo = (pair[1] as char).to_digit(16).expect("valid hex");
                ((hi << 4) | lo) as u8
            })
            .collect()
    }

    fn test_shake_kat(capacity: usize, src: &[u8], hex_out: &str) {
        let expected = hex_to_bytes(hex_out);
        let mut tmp = vec![0u8; expected.len()];

        let mut shake = ShakeContext::new(capacity);
        shake.inject(src);
        shake.flip();
        shake.extract(&mut tmp);
        assert_eq!(tmp, expected, "SHAKE KAT 1");

        let mut tmp = vec![0u8; expected.len()];
        let mut shake = ShakeContext::new(capacity);
        for byte in src {
            shake.inject(&[*byte]);
        }
        shake.flip();
        for out in &mut tmp {
            let mut one = [0u8; 1];
            shake.extract(&mut one);
            *out = one[0];
        }
        assert_eq!(tmp, expected, "SHAKE KAT 2");
    }

    #[test]
    fn shake128_kats_match_reference() {
        test_shake_kat(
            SHAKE128_CAPACITY,
            b"",
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
        );
        test_shake_kat(
            SHAKE128_CAPACITY,
            b"The quick brown fox jumps over the lazy dog",
            "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e",
        );
        test_shake_kat(
            SHAKE128_CAPACITY,
            b"The quick brown fox jumps over the lazy dof",
            "853f4538be0db9621a6cea659a06c1107b1f83f02b13d18297bd39d7411cf10c",
        );
    }

    #[test]
    fn shake256_kats_match_reference() {
        test_shake_kat(
            SHAKE256_CAPACITY,
            b"",
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
             d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
        );
        test_shake_kat(
            SHAKE256_CAPACITY,
            &hex_to_bytes(
                "dc5a100fa16df1583c79722a0d72833d3bf22c109b8889dbd35213c6bfce2058\
                 13edae3242695cfd9f59b9a1c203c1b72ef1a5423147cb990b5316a852666758\
                 94e2644c3f9578cebe451a09e58c53788fe77a9e850943f8a275f830354b0593\
                 a762bac55e984db3e0661eca3cb83f67a6fb348e6177f7dee2df40c4322602f0\
                 94953905681be3954fe44c4c902c8f6bba565a788b38f13411ba76ce0f9f6756\
                 a2a2687424c5435a51e62df7a8934b6e141f74c6ccf539e3782d22b5955d3baf\
                 1ab2cf7b5c3f74ec2f9447344e937957fd7f0bdfec56d5d25f61cde18c0986e2\
                 44ecf780d6307e313117256948d4230ebb9ea62bb302cfe80d7dfebabc4a51d7\
                 687967ed5b416a139e974c005fff507a96",
            ),
            "2bac5716803a9cda8f9e84365ab0a681327b5ba34fdedfb1c12e6e807f45284b",
        );
        test_shake_kat(
            SHAKE256_CAPACITY,
            &hex_to_bytes("8d8001e2c096f1b88e7c9224a086efd4797fbf74a8033a2d422a2b6b8f6747e4"),
            "2e975f6a8a14f0704d51b13667d8195c219f71e6345696c49fa4b9d08e9225d3\
             d39393425152c97e71dd24601c11abcfa0f12f53c680bd3ae757b8134a9c10d4\
             29615869217fdd5885c4db174985703a6d6de94a667eac3023443a8337ae1bc6\
             01b76d7d38ec3c34463105f0d3949d78e562a039e4469548b609395de5a4fd43\
             c46ca9fd6ee29ada5efc07d84d553249450dab4a49c483ded250c9338f85cd93\
             7ae66bb436f3b4026e859fda1ca571432f3bfc09e7c03ca4d183b741111ca0483\
             d0edabc03feb23b17ee48e844ba2408d9dcfd0139d2e8c7310125aee801c61ab\
             7900d1efc47c078281766f361c5e6111346235e1dc38325666c",
        );
    }

    #[test]
    fn shake256_digest_matches_streaming_split() {
        let input = b"split-output";
        let mut one_shot = [0u8; 300];
        ShakeContext::digest(SHAKE256_CAPACITY, input, &mut one_shot);

        let mut split = [0u8; 300];
        let mut shake = ShakeContext::shake256();
        shake.inject(input);
        shake.flip();
        shake.extract(&mut split[..1]);
        shake.extract(&mut split[1..136]);
        shake.extract(&mut split[136..137]);
        shake.extract(&mut split[137..]);

        assert_eq!(split, one_shot);
    }
}
