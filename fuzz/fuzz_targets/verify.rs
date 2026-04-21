#![no_main]

use std::sync::OnceLock;

use falcon2017::{Compression, Falcon1024, Falcon512, Nonce, PublicKey};
use libfuzzer_sys::fuzz_target;
use rand_core::{CryptoRng, Error as RandError, RngCore};

struct BaseCase {
    pk: Vec<u8>,
    nonce: Vec<u8>,
    msg: Vec<u8>,
    sig_body: Vec<u8>,
}

struct FixedSeedRng {
    state: u64,
}

impl FixedSeedRng {
    fn new(seed: &[u8]) -> Self {
        let mut mixed = 0x6a09_e667_f3bc_c909u64;
        for &byte in seed {
            mixed ^= u64::from(byte);
            mixed = mixed.wrapping_mul(0x1000_0000_01b3);
            mixed ^= mixed >> 29;
        }
        Self { state: mixed | 1 }
    }

    fn next_word(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

impl RngCore for FixedSeedRng {
    fn next_u32(&mut self) -> u32 {
        self.next_word() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.next_word()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0usize;
        while offset < dest.len() {
            let block = self.next_u64().to_le_bytes();
            let take = (dest.len() - offset).min(block.len());
            dest[offset..offset + take].copy_from_slice(&block[..take]);
            offset += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedSeedRng {}

static BASE_512: OnceLock<BaseCase> = OnceLock::new();
static BASE_1024: OnceLock<BaseCase> = OnceLock::new();

fn base_case(logn: u32) -> &'static BaseCase {
    match logn {
        9 => BASE_512.get_or_init(|| build_base_case_512()),
        10 => BASE_1024.get_or_init(|| build_base_case_1024()),
        _ => unreachable!(),
    }
}

fn build_base_case_512() -> BaseCase {
    let mut keygen_rng = FixedSeedRng::new(b"verify-fuzz-base-keygen-512");
    let keypair = Falcon512::keygen(&mut keygen_rng).expect("build base keypair 512");
    let mut sign_rng = FixedSeedRng::new(b"verify-fuzz-base-sign-512");
    let sig = keypair
        .secret
        .sign_ref(
            b"verify-fuzz-base-message-512",
            Compression::Static,
            &mut sign_rng,
        )
        .expect("build base signature 512");

    BaseCase {
        pk: keypair.public.to_bytes().to_vec(),
        nonce: sig.nonce().as_bytes().to_vec(),
        msg: b"verify-fuzz-base-message-512".to_vec(),
        sig_body: sig.body_bytes().to_vec(),
    }
}

fn build_base_case_1024() -> BaseCase {
    let mut keygen_rng = FixedSeedRng::new(b"verify-fuzz-base-keygen-1024");
    let keypair = Falcon1024::keygen(&mut keygen_rng).expect("build base keypair 1024");
    let mut sign_rng = FixedSeedRng::new(b"verify-fuzz-base-sign-1024");
    let sig = keypair
        .secret
        .sign_ref(
            b"verify-fuzz-base-message-1024",
            Compression::Static,
            &mut sign_rng,
        )
        .expect("build base signature 1024");

    BaseCase {
        pk: keypair.public.to_bytes().to_vec(),
        nonce: sig.nonce().as_bytes().to_vec(),
        msg: b"verify-fuzz-base-message-1024".to_vec(),
        sig_body: sig.body_bytes().to_vec(),
    }
}

fn mutate_field(buf: &mut Vec<u8>, op: &[u8]) {
    if op.len() < 3 {
        return;
    }
    match op[0] & 0x03 {
        0 => {
            if !buf.is_empty() {
                let idx = usize::from(op[1]) % buf.len();
                buf[idx] ^= op[2];
            }
        }
        1 => {
            if !buf.is_empty() {
                let idx = usize::from(op[1]) % buf.len();
                buf[idx] = op[2];
            }
        }
        2 => {
            let new_len = usize::from(op[1]) % (buf.len() + 1);
            buf.truncate(new_len);
        }
        _ => {
            if buf.len() < 4096 {
                let idx = usize::from(op[1]) % (buf.len() + 1);
                buf.insert(idx, op[2]);
            }
        }
    }
}

fn split_raw_mode(data: &[u8]) -> (u32, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    if data.is_empty() {
        return (9, Vec::new(), Vec::new(), Vec::new(), Vec::new());
    }

    let logn = if (data[0] & 1) == 0 { 9 } else { 10 };
    let mut cursor = &data[1..];
    let pk = take_chunk(&mut cursor);
    let nonce = take_chunk(&mut cursor);
    let msg = take_chunk(&mut cursor);
    let sig_body = cursor.to_vec();
    (logn, pk, nonce, msg, sig_body)
}

fn take_chunk(cursor: &mut &[u8]) -> Vec<u8> {
    if cursor.len() < 2 {
        let out = cursor.to_vec();
        *cursor = &[];
        return out;
    }

    let raw_len = u16::from_le_bytes([cursor[0], cursor[1]]) as usize;
    *cursor = &cursor[2..];
    let take = raw_len % (cursor.len() + 1);
    let out = cursor[..take].to_vec();
    *cursor = &cursor[take..];
    out
}

fn mutate_valid_mode(data: &[u8]) -> (u32, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let logn = if data.first().copied().unwrap_or(0) & 1 == 0 {
        9
    } else {
        10
    };
    let base = base_case(logn);
    let mut pk = base.pk.clone();
    let mut nonce = base.nonce.clone();
    let mut msg = base.msg.clone();
    let mut sig_body = base.sig_body.clone();

    for chunk in data.get(1..).unwrap_or(&[]).chunks(4) {
        if chunk.is_empty() {
            continue;
        }
        let target = chunk[0] & 0x03;
        let op = &chunk[1..];
        match target {
            0 => mutate_field(&mut pk, op),
            1 => mutate_field(&mut nonce, op),
            2 => mutate_field(&mut msg, op),
            _ => mutate_field(&mut sig_body, op),
        }
    }

    (logn, pk, nonce, msg, sig_body)
}

fn exercise_verify(logn: u32, pk_bytes: &[u8], nonce_bytes: &[u8], msg: &[u8], sig_body: &[u8]) {
    match logn {
        9 => {
            if let Ok(public) = PublicKey::<9>::from_bytes(pk_bytes) {
                if let Ok(prepared) = public.prepare() {
                    let nonce = Nonce::from_bytes(nonce_bytes);
                    let split = msg.len() / 2;
                    let mut verifier = prepared.verifier(&nonce);
                    verifier.update(&msg[..split]);
                    verifier.update(&msg[split..]);
                    let _ = verifier.finalize(sig_body);
                }
            }
        }
        10 => {
            if let Ok(public) = PublicKey::<10>::from_bytes(pk_bytes) {
                if let Ok(prepared) = public.prepare() {
                    let nonce = Nonce::from_bytes(nonce_bytes);
                    let split = msg.len() / 2;
                    let mut verifier = prepared.verifier(&nonce);
                    verifier.update(&msg[..split]);
                    verifier.update(&msg[split..]);
                    let _ = verifier.finalize(sig_body);
                }
            }
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let (logn, pk, nonce, msg, sig_body) = if data.first().copied().unwrap_or(0) & 0x80 == 0 {
        split_raw_mode(data)
    } else {
        mutate_valid_mode(data)
    };

    exercise_verify(logn, &pk, &nonce, &msg, &sig_body);
});
