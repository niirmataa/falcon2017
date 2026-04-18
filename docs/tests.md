# Tests

This document tracks the current regression, KAT, differential, and strict-CT coverage for the crate.

## Current Gates

Primary green command for the current Falcon state:
- `cargo test --features std,ref-f64,ct-strict,soft-fpr`

Reference coverage already present in-tree:
- SHAKE and PRNG KATs,
- NTRU vectors,
- keygen/sign/verify roundtrips for Falcon512 and Falcon1024,
- encode/decode and malformed-input regressions,
- differential verify and derive-public checks against the frozen C baseline,
- deterministic differential campaigns covering 1024 seeded keygen cases and 1024 seeded
  verify cases across the public Falcon512/Falcon1024 parameter sets.

## Strict CT Coverage

Coverage already implemented for the `ct_strict` track:
- `src/math/fpr/soft.rs` has unit tests comparing soft binary64 operations bit-for-bit with native
  `f64` on fixed vectors,
- `src/falcon/expand_ct.rs` checks that the expanded key stored as `FprSoft` is bit-identical to
  the historical reference prepared key,
- `src/sampler/sign_ct_strict.rs` checks constant PRNG budgets for the CDF/CT_BEREXP sampler path
  and stabilizes a short deterministic regression sequence,
- `src/falcon/sign_ct_strict.rs` checks default-nonce and external-nonce signing on preserved
  reference material through real `verify()` roundtrips,
- `tests/ct_consistency.rs` smoke-tests the public `expand_ct_strict()` and
  `expand_ct_strict_in()` APIs for Falcon512 and Falcon1024, verifies `sign_ct_strict()` and
  `sign_ct_strict_in()` roundtrips for both public parameter sets, checks determinism plus
  one-shot/workspace parity on fixed seeds, checks wire-header parity between `ref` and
  `ct_strict`, includes a timing smoke on fixed seeds, and audits that strict production modules
  do not directly import `ref_f64` or `libm`,
- `fuzz/decode_signature` is a real libFuzzer harness for the shared signature decoder used by
  both `ref` and `ct_strict`; its compile gate is
  `CXX=clang++ cargo check --manifest-path fuzz/Cargo.toml`,
- `src/sampler/sign_ct_strict.rs` now also contains distribution and timing smoke tests for the
  strict sampler path.

Coverage intentionally deferred to later strict steps:
- broader side-channel validation and larger-scale statistical campaigns for the now-runtime
  integer-only `ct_strict` executor.

## Deterministic Differential Campaign

When `deterministic-tests` is enabled, the campaign-level differential checks are:
- `tests/differential_keygen.rs`: 512 seeded Falcon512 keygens plus 512 seeded Falcon1024
  keygens, each compared byte-for-byte against the frozen C helper for public key, secret key,
  decode roundtrip, and `derive_public()`,
- `tests/differential_verify.rs`: 512 seeded Falcon512 signatures plus 512 seeded Falcon1024
  signatures, with varied message lengths, varied external nonce lengths, and alternating
  `Compression::{None, Static}`; every Rust-produced signature must verify both in Rust and in
  the frozen C verifier.
