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
- `tests/ct_consistency.rs` smoke-tests the public `expand_ct_strict()` API for Falcon512 and
  Falcon1024 and verifies rejection of non-public `logn`.

Coverage intentionally deferred to later strict steps:
- `verify(sign_ct_strict(...))` consistency tests stay blocked until `ExpandedSecretKeyCt::*`
  signing methods are implemented,
- signature-format comparisons between `ref` and `ct_strict`,
- sampler distribution tests,
- strict decode fuzzing and timing smoke tests.
