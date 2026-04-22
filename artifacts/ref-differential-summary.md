# R1 Differential Summary

- keygen cases per logn: 10000
- sign cases per logn: 1000
- supported logn values: `9`, `10`
- generator command: `cargo run --features deterministic-tests --bin r1_artifacts -- all --out-dir artifacts --keygen-cases 10000 --sign-cases 1000`
- validation command: `cargo run --features deterministic-tests --bin r1_artifacts -- check-all --out-dir artifacts --keygen-cases 10000 --sign-cases 1000`

## Keygen

- total cases: 20000
- public-key mismatches: 0
- secret-key mismatches: 0
- derive-public mismatches: 0
- decoded public-key mismatches: 0
- decoded secret-key mismatches: 0
- decoded derive-public mismatches: 0

## Sign

- total cases: 2000
- key public-key mismatches: 0
- key secret-key mismatches: 0
- nonce mismatches: 0
- signature mismatches: 0
- Rust verify failures on Rust signatures: 0
- Rust verify failures on C signatures: 0
- C verify failures on Rust signatures: 0
- C verify failures on C signatures: 0
