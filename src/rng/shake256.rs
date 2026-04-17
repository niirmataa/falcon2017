//! SHAKE state and sponge operations ported from `shake.h` / `shake.c`.

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
