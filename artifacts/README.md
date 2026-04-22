# R1 Artifacts

This directory holds reproducible `R1` differential artifacts for the current
`Rust ref <-> C baseline` comparison.

The keygen artifact stores expected encoded-output digests and lengths instead of
full raw key material, so the tracked dossier stays small enough for normal Git
workflows while still pinning deterministic outputs.

Current generator command:

```bash
cargo run --features deterministic-tests --bin r1_artifacts -- all --out-dir artifacts --keygen-cases 10000 --sign-cases 1000
```

Matching validation command:

```bash
cargo run --features deterministic-tests --bin r1_artifacts -- check-all --out-dir artifacts --keygen-cases 10000 --sign-cases 1000
```

Current tracked artifacts:

- `ref-differential-keygen.json`
- `ref-differential-sign.json`
- `ref-differential-summary.md`
- `ct-dynamic-timing.json`
- `ct-dynamic-timing.md`

Current tracked deterministic scales:

- keygen: `10_000` cases per public `logn`
- sign: `1_000` cases per public `logn`

Current timing command:

```bash
cargo run --release --features deterministic-tests --bin ct_timing -- --out-dir artifacts --samples-per-class 256 --expand-batch 4 --sign-batch 4
```
