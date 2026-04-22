# R1 Artifacts

This directory holds reproducible `R1` differential artifacts for the current
`Rust ref <-> C baseline` comparison.

Current generator command:

```bash
cargo run --features deterministic-tests --bin r1_artifacts -- all --out-dir artifacts --cases 512
```

Matching validation command:

```bash
cargo run --features deterministic-tests --bin r1_artifacts -- check-all --out-dir artifacts --cases 512
```

Current tracked artifacts:

- `ref-differential-keygen.json`
- `ref-differential-sign.json`
- `ref-differential-summary.md`
- `ct-dynamic-timing.json`
- `ct-dynamic-timing.md`

Current timing command:

```bash
cargo run --release --features deterministic-tests --bin ct_timing -- --out-dir artifacts --samples-per-class 256 --expand-batch 4 --sign-batch 4
```
