# R1 Differential Summary

- cases per logn: 512
- supported logn values: `9`, `10`
- generator command: `cargo run --features deterministic-tests --bin r1_artifacts -- all --out-dir artifacts --cases 512`
- validation command: `cargo run --features deterministic-tests --bin r1_artifacts -- check-all --out-dir artifacts --cases 512`

## Keygen

- total cases: 1024
- public-key mismatches: 0
- secret-key mismatches: 0
- derive-public mismatches: 0
- decoded public-key mismatches: 0
- decoded secret-key mismatches: 0
- decoded derive-public mismatches: 0

## Sign

- total cases: 1024
- key public-key mismatches: 0
- key secret-key mismatches: 0
- nonce mismatches: 0
- signature mismatches: 0
- Rust verify failures on Rust signatures: 0
- Rust verify failures on C signatures: 0
- C verify failures on Rust signatures: 0
- C verify failures on C signatures: 0
