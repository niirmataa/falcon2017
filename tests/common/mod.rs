use rand_core::{CryptoRng, RngCore};

pub mod c_reference;

pub const C_TEST_FALCON: &str = include_str!("../../references/falcon-2017-extra/test_falcon.c");

pub fn hex_to_bytes(src: &str) -> Vec<u8> {
    let mut digits = Vec::with_capacity(src.len());
    for byte in src.bytes() {
        if !byte.is_ascii_whitespace() {
            digits.push(byte);
        }
    }
    assert_eq!(
        digits.len() % 2,
        0,
        "hex string must have an even number of digits"
    );

    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        out.push((hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]));
    }
    out
}

pub fn extract_c_string(src: &str, name: &str) -> String {
    let needle = format!("static const char *{name} = \"");
    let start = src.find(&needle).expect("C string start");
    let rest = &src[start + needle.len()..];
    let end = rest.find("\";").expect("C string end");
    rest[..end].to_string()
}

pub fn extract_c_i16_array(src: &str, name: &str) -> Vec<i16> {
    let needle = format!("static const int16_t {name}[] = {{");
    let start = src.find(&needle).expect("C array start");
    let rest = &src[start + needle.len()..];
    let end = rest.find("};").expect("C array end");
    rest[..end]
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| entry.parse::<i16>().expect("valid int16 entry"))
        .collect()
}

pub fn extract_c_kat_table(src: &str, name: &str) -> Vec<(String, String, String)> {
    let needle = format!("static const char *const {name}[] = {{");
    let start = src.find(&needle).expect("C KAT table start");
    let rest = &src[start + needle.len()..];
    let end = rest.find("NULL").expect("C KAT table terminator");
    let body = &rest[..end];

    let mut strings = Vec::new();
    let mut remaining = body;
    while let Some(open) = remaining.find('"') {
        let tail = &remaining[open + 1..];
        let close = tail.find('"').expect("quoted string end");
        strings.push(tail[..close].to_string());
        remaining = &tail[close + 1..];
    }

    assert_eq!(strings.len() % 3, 0, "KAT table must contain triples");
    strings
        .chunks_exact(3)
        .map(|chunk| (chunk[0].clone(), chunk[1].clone(), chunk[2].clone()))
        .collect()
}

pub fn negacyclic_mul(lhs: &[i16], rhs: &[i16]) -> Vec<i64> {
    let n = lhs.len();
    assert_eq!(rhs.len(), n);
    let mut out = vec![0i64; n];
    for (i, &a) in lhs.iter().enumerate() {
        for (j, &b) in rhs.iter().enumerate() {
            let idx = i + j;
            let term = i64::from(a) * i64::from(b);
            if idx < n {
                out[idx] += term;
            } else {
                out[idx - n] -= term;
            }
        }
    }
    out
}

pub struct FixedSeedRng {
    seed: [u8; 32],
    offset: usize,
}

impl FixedSeedRng {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed, offset: 0 }
    }
}

impl RngCore for FixedSeedRng {
    fn next_u32(&mut self) -> u32 {
        let mut tmp = [0u8; 4];
        self.fill_bytes(&mut tmp);
        u32::from_le_bytes(tmp)
    }

    fn next_u64(&mut self) -> u64 {
        let mut tmp = [0u8; 8];
        self.fill_bytes(&mut tmp);
        u64::from_le_bytes(tmp)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).expect("fixed seed rng")
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        for byte in dest {
            *byte = if self.offset < self.seed.len() {
                self.seed[self.offset]
            } else {
                0
            };
            self.offset += 1;
        }
        Ok(())
    }
}

impl CryptoRng for FixedSeedRng {}

pub struct FixedRng {
    bytes: Vec<u8>,
    pos: usize,
}

impl FixedRng {
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            pos: 0,
        }
    }

    fn next_byte(&mut self) -> u8 {
        let value = self.bytes[self.pos % self.bytes.len()];
        self.pos += 1;
        value
    }
}

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut out = [0u8; 4];
        self.fill_bytes(&mut out);
        u32::from_le_bytes(out)
    }

    fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        self.fill_bytes(&mut out);
        u64::from_le_bytes(out)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.next_byte();
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedRng {}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => 10 + (byte - b'a'),
        b'A'..=b'F' => 10 + (byte - b'A'),
        _ => panic!("invalid hex digit"),
    }
}
