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
- differential verify and derive-public checks against the frozen C baseline.

## Strict CT Coverage

Coverage already implemented for the `ct_strict` track:
- `src/math/fpr/soft.rs` has unit tests comparing soft binary64 operations bit-for-bit with native
  `f64` on fixed vectors,
- `src/falcon/expand_ct.rs` checks that the expanded key stored as `FprSoft` is bit-identical to
  the historical reference prepared key,
- `src/sampler/sign_ct_strict.rs` checks constant PRNG budgets for the CDF/CT_BEREXP sampler path
  and stabilizes a short deterministic regression sequence,
- `src/falcon/sign_ct_strict.rs` checks default-nonce and external-nonce signing against the
  preserved Falcon/Extra C vectors from Step 17,
- `tests/ct_consistency.rs` smoke-tests the public `expand_ct_strict()` and
  `expand_ct_strict_in()` APIs for Falcon512 and Falcon1024, verifies `sign_ct_strict()` and
  `sign_ct_strict_in()` roundtrips for both public parameter sets, and checks parity with
  `sign_ref` plus one-shot/workspace parity on fixed seeds.

Coverage intentionally deferred to later strict steps:
- broader signature-format comparisons between `ref` and the future integer-only `ct_strict`
  executor beyond the current bridge parity checks,
- sampler distribution tests,
- strict decode fuzzing and timing smoke tests.
