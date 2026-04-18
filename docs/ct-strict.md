# CT Strict

This document will track the strict constant-time rules and audit notes for the `ct_strict` backend.

## Strict CT

Phase C uses a separate `math/fpr/soft.rs` backend that emulates binary64 on integers.

Step 23 assumptions:
- no `f64` in the module's production code,
- no `libm`,
- binary64 constants stored as raw bit patterns,
- `of`, `scaled`, `add`, `sub`, `mul`, `div`, `sqrt`, `rint`, `floor`, and `exp_small`
  work through custom decode/round/pack logic.

Step 23 verification:
- unit tests compare operations bit-for-bit against native binary64 on fixed vectors,
- `exp_small` is compared against the `ref_f64` backend,
- full `cargo test` and `cargo test --features deterministic-tests` pass in Alpine WSL.

## Step 24

State after Step 24:
- `ExpandedSecretKeyCtInner` stores `b00`, `b01`, `b10`, `b11`, and `tree` as `FprSoft`,
- `SecretKey::expand_ct_strict()` works for the public `Falcon512` and `Falcon1024` parameter sets,
- expanded-key storage is secret-bearing and is cleared by `Drop + zeroize`,
- Falcon/Extra expanded-key semantics are frozen at this stage by a bit-identical copy of the prepared key from the `ref` backend into the `FprSoft` representation.

Current scope of Step 24:
- this is a representation and API step, not the final `C1` audit,
- `sign_ct_strict` is still a placeholder,
- fully removing the dependency on reference expansion remains open work before closing the strict signing path and the Step 29 audit.

Step 24 verification:
- a unit test in `src/falcon/expand_ct.rs` compares the expanded key bit-for-bit with the reference `prepare_signing_key_into`,
- a smoke test in `tests/ct_consistency.rs` checks public `expand_ct_strict()` for 512 and 1024 and rejects non-public `logn`,
- `cargo test --features std,ref-f64,ct-strict,soft-fpr` passes cleanly.

## Step 25

State after Step 25:
- `src/sampler/sign_ct_strict.rs` implements the `SAMPLER_CDF=1` and `CT_BEREXP=1` variant,
- `gaussian0_sampler_ct()` always consumes two `u64` blocks from the PRNG,
- `ber_exp_ct()` uses a fixed PRNG-read budget for a single rejection-sampling attempt.

Step 25 verification:
- unit tests in `src/sampler/sign_ct_strict.rs` check the fixed PRNG budget for `gaussian0_sampler_ct()` and `ber_exp_ct()`,
- a regression test stabilizes a short `sample_binary_ct()` sequence on a fixed seed,
- `cargo test --lib sampler::sign_ct_strict -- --nocapture` passes cleanly.

## Step 27

State after Step 27:
- `ExpandedSecretKeyCt::{sign_ct_strict, sign_ct_strict_with_external_nonce}` work for the public `Falcon512` and `Falcon1024` parameter sets,
- the signer uses the expanded key from Step 24 directly through an executor based on `FprSoft` and `fft_soft`, without an intermediate bridge to `ref_f64`,
- nonce and signature semantics are frozen at this stage through compatibility with the reference signer and the preserved C baseline.

Current scope of Step 27:
- this is already a runtime integer-only strict signer for binary Falcon,
- runtime execution no longer depends on the reference `ref_f64` backend,
- a separate CT workspace API has not been added yet.

Step 27 verification:
- unit tests in `src/falcon/sign_ct_strict.rs` compare default nonce and external nonce against the preserved C vectors from Step 17,
- `tests/ct_consistency.rs` checks `verify(sign_ct_strict(...))` roundtrips for 512 and 1024 and parity between `sign_ct_strict` and `sign_ref` on fixed seeds,
- `cargo test --features std,ref-f64,ct-strict,soft-fpr` and
  `cargo test --no-default-features --features ct-strict` pass cleanly.

## Step 28

State after Step 28:
- `ExpandCtWorkspace<LOGN>` and `SignCtWorkspace<LOGN>` are public strict-CT workspaces for the strict path,
- `SecretKey::expand_ct_strict_in()` reuses scratch when preparing the expanded key,
- `ExpandedSecretKeyCt::{sign_ct_strict_in, sign_ct_strict_with_external_nonce_in}` reuse scratch across calls without extra API hacks on the caller side,
- the one-shot strict-CT signer delegates to the workspace-backed path, so signature semantics stay unified.

Current scope of Step 28:
- runtime execution already stays on the soft-FFT / soft-FPR path,
- Step 28 closes the public CT surface for `*_in(...)` paths, but does not close the audit yet.

Step 28 verification:
- `tests/ct_consistency.rs` checks `expand_ct_strict_in()` against the one-shot path, verifies `sign_ct_strict_in()` roundtrips, and checks one-shot/workspace parity on the same seeds and nonces,
- full `cargo test` and `cargo test --no-default-features --features ct-strict` pass cleanly.

## Step 29

State after Step 29:
- `src/falcon/sign_ct_strict.rs`, `src/sampler/sign_ct_strict.rs`, `src/falcon/expand_ct.rs`, and `src/math/fft_soft.rs` no longer import `ref_f64` or `libm` directly,
- `gaussian0_sampler_ct()` no longer has an early exit after the CDF and consumes a fixed PRNG budget for a single attempt,
- `SignCtWorkspace<LOGN>` has its own scratch and `Drop + zeroize` for strict-path buffers,
- `src/math/fft_soft.rs` and `src/math/fft_gm_bits_table.rs` are now the active runtime path for strict signing.

Step 29 audit result:
- public strict modules have been cut off from direct `ref_f64` imports,
- the strict signer already uses the strict sampler from Step 25,
- signing math now runs without a private bridge to the reference backend, so **Gate C1.3 (`ct_strict` does not use `f64`) is closed**.

Step 29 verification:
- `tests/ct_consistency.rs` contains the source audit `strict_modules_do_not_directly_import_ref_f64_or_libm`,
- strict roundtrip tests for 512 and 1024 pass cleanly,
- `cargo test --test ct_consistency`, `cargo test sign_ct_strict`, and full `cargo test` pass in Alpine WSL.

## Step 30

State after Step 30:
- `tests/ct_consistency.rs` closes the public strict-path tests: `verify(sign_ct_strict(...))` roundtrips, `ref` vs `ct_strict` header/wire-format parity for `Compression::{None, Static}`, and timing smoke on fixed seeds,
- `src/sampler/sign_ct_strict.rs` has distribution smoke and timing smoke for the strict sampler,
- `fuzz/decode_signature` is a compilable `libFuzzer` harness for the shared signature decoder used by both `ref` and `ct_strict`.

Step 30 result:
- the test and regression audit for the strict surface and shared signature decode is closed,
- runtime strict signing now goes exclusively through the soft-FFT / soft-FPR path, without dependency on `ref_f64`.

Step 30 verification:
- `cargo test --test ct_consistency`,
- `cargo test sampler::sign_ct_strict`,
- `cargo test --no-default-features --features ct-strict`,
- `CXX=clang++ cargo check --manifest-path fuzz/Cargo.toml`,
- full `cargo test` in Alpine WSL.
