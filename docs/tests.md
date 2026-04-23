# Tests

This document tracks the current regression, KAT, differential, fuzzing, and audit-facing coverage for the crate.

## Current Gates

Primary green command for the current Falcon state:

- `cargo test --features std,ref-f64,ct-strict,soft-fpr`

Reference coverage already present in-tree:

- SHAKE and PRNG KATs
- NTRU vectors
- keygen/sign/verify roundtrips for Falcon512 and Falcon1024
- encode/decode, property-based codec tests, and malformed-input regressions
- differential verify and derive-public checks against the frozen C baseline
- deterministic differential campaigns covering 1024 seeded keygen cases and 1024 seeded verify cases across the public Falcon512/Falcon1024 parameter sets

## Encoding and API Robustness

Additional robustness coverage on top of the reference/KAT suite:

- `tests/codec_properties.rs` runs proptest roundtrips for `ring12289`, `ring18433`, `smallvec`, `public_key`, `signature`, and `secret_key` across supported binary/ternary `logn` ranges
- `tests/malformed_inputs.rs` mutates real Falcon512/Falcon1024 artifacts through the public API and checks truncation, reserved header bits, public-key trailing bytes, signature trailing bytes, and the `InvalidEncoding` vs `InvalidSignature` split for wrong nonce/message cases
- `src/encoding/ring12289.rs` and `src/encoding/ring18433.rs` reject trailing bytes at the low-level ring decoder boundary; this is covered by both unit tests and public malformed-input regressions

## Strict-Path Coverage

Coverage already implemented for the `ct_strict` track:

- `src/math/fpr/soft.rs` has unit tests comparing soft binary64 operations bit-for-bit with native `f64` on fixed vectors
- `src/falcon/expand_ct.rs` checks that the expanded key stored as `FprSoft` is bit-identical to the historical reference prepared key
- `src/sampler/sign_ct_strict.rs` checks fixed per-attempt PRNG budgets for the CDF/CT_BEREXP sampler path and stabilizes a short deterministic regression sequence
- `src/falcon/sign_ct_strict.rs` checks default-nonce and external-nonce signing on preserved reference material through real `verify()` roundtrips
- `tests/ct_consistency.rs` smoke-tests the public `expand_ct_strict()` and `expand_ct_strict_in()` APIs for Falcon512 and Falcon1024, verifies `sign_ct_strict()` and `sign_ct_strict_in()` roundtrips for both public parameter sets, checks determinism plus one-shot/workspace parity on fixed seeds, checks wire-header parity between `ref` and `ct_strict`, includes a timing smoke on fixed seeds, and audits that strict production modules do not directly import `ref_f64` or `libm`
- `src/sampler/sign_ct_strict.rs` also contains distribution and timing smoke tests for the strict sampler path
- `src/bin/ct_timing.rs`: dudect-like timing harness that records fixed-vs-varied timing datasets for `expand_ct_strict()` and `sign_ct_strict()` into repo-tracked artifacts
- `artifacts/ct-source-review-soft-fpr.md`: source-review note recording the current branch and memory-access assessment for `src/math/fpr/soft.rs`
- `artifacts/ct-source-review-soft-fft.md`: source-review note recording the current branch and memory-access assessment for `src/math/fft_soft.rs`
- `artifacts/ct-source-review-sampler-signing.md`: source-review note recording the current control-flow and memory-access assessment for `src/sampler/sign_ct_strict.rs` and `src/falcon/sign_ct_strict.rs`
- `artifacts/cargo-audit.md` and `artifacts/cargo-audit.json`: recorded dependency-audit result for the current lockfile
- `artifacts/fuzz/c1-gnu-asan-20260423.md` and `artifacts/fuzz/c1-gnu-asan-20260423.json`: curated GNU/Linux ASan fuzz campaign result for the decoder and verification targets

Coverage intentionally deferred to later strict steps:

- broader side-channel validation
- larger-scale statistical campaigns for the runtime integer-only strict executor
- machine-readable retry histograms
- long-run GNU/ASan fuzz evidence for strict-path related surfaces

## Deterministic Differential Campaign

When `deterministic-tests` is enabled, the campaign-level differential checks are:

- `tests/differential_keygen.rs`: 512 seeded Falcon512 keygens plus 512 seeded Falcon1024 keygens, each compared byte-for-byte against the frozen C helper for public key, secret key, decode roundtrip, and `derive_public()`
- `tests/differential_derive_public.rs`: fixed-seed derive-public regressions against the frozen C helper for Falcon512 and Falcon1024, gated with the same `deterministic-tests` feature as the other C-dependent campaigns
- `tests/differential_verify.rs`: 512 seeded Falcon512 signatures plus 512 seeded Falcon1024 signatures, with varied message lengths, varied external nonce lengths, and alternating `Compression::{None, Static}`; every Rust-produced signature must verify both in Rust and in the frozen C verifier
- `src/bin/r1_artifacts.rs`: reproducible generator/checker for `artifacts/ref-differential-keygen.json`, `artifacts/ref-differential-sign.json`, and `artifacts/ref-differential-summary.md`, with independent scales for keygen and signing campaigns; the current tracked GNU/Linux checkpoint is `10_000` keygen cases per public `logn` and `1_000` signing cases per public `logn`

## Fuzz Harnesses

In-repo libFuzzer targets now cover the three shared decoders plus a verification target:

- `fuzz/fuzz_targets/decode_signature.rs`
- `fuzz/fuzz_targets/decode_public_key.rs`
- `fuzz/fuzz_targets/decode_secret_key.rs`
- `fuzz/fuzz_targets/verify.rs`

Current practical status in Alpine WSL:

- reliable repo gate: `cargo check --manifest-path fuzz/Cargo.toml`
- true `cargo fuzz` on nightly is partially blocked by the Alpine/musl environment:
  `--sanitizer=address` fails because musl uses statically linked libc, and
  `--sanitizer=none` with `--target x86_64-unknown-linux-musl` requires a C++/libFuzzer setup that is unstable under the current Alpine toolchain
- an exploratory nightly run with `cargo fuzz run --sanitizer none --target x86_64-unknown-linux-musl decode_signature` reached real coverage/corpus growth, but the musl runtime then terminated with a non-reproducible `libFuzzer: deadly signal` on an empty-input artifact; direct fixed-input replay of that artifact does not reproduce a decoder crash

Longer fuzz campaigns should therefore run on a GNU/Linux host with sanitizer support instead of relying on the local Alpine musl setup.

The current GNU/Linux campaign runner is:

- `scripts/run_gnu_fuzz_campaign.sh --time 1800`

The current CI gate for fuzz target buildability is:

- `.github/workflows/fuzz-check.yml`

## Audit and Fuzz Direction

Near-term audit-facing goals:

- run the in-repo verification-focused fuzzer on the GNU/ASan research host
- preserve machine-readable differential artifacts for `Rust ref <-> C baseline`
- scale the dudect-like timing harness to larger Ubuntu-host sample counts and recorded review notes
- record retry histograms for the strict signer and strict sampler
- run sanitizer and Miri checks on the intended research host

Interpretation rules:

- timing smoke tests are regression guards, not proof of constant-time behavior
- the dudect-like harness is real dynamic evidence, but current repo-tracked runs are still an initial checkpoint rather than a completed dossier
- decoder fuzz harnesses are necessary hardening work, not a substitute for semantic differential testing
- the strict-path audit is not complete until fuzzing, statistical timing, and source review evidence are all recorded
