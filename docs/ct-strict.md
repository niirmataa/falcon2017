# CT Strict

This document tracks the engineering milestones for the `ct_strict` backend. The exact public claim boundary is now fixed in `SECURITY.md` and `docs/c0_claim_boundary.md`.

## Current Boundary

The repository may currently claim:

- a runtime integer-only strict-path signer exists for `Falcon512` and `Falcon1024`
- public strict modules no longer directly import `ref_f64` or `libm`
- public strict-path APIs have roundtrip, parity, sampler-budget, timing-smoke, and dudect-like timing-harness coverage
- shared decoder fuzz harnesses exist for artifacts used by both `ref` and `ct_strict`

The repository may not yet claim:

- a defensively constant-time full-signature algorithm
- a completed side-channel audit
- a completed statistical timing dossier
- completed long-run GNU/ASan fuzz evidence for the strict path

Reasons gate `C1` remains open:

- signing still retries until `is_short_binary(...)` accepts
- the strict sampler still uses acceptance / retry logic
- repeated large-sample timing checkpoints on the current VMware host are not stable enough to support stronger CT wording; one `sign_ct_strict_falcon512_none` run crossed the notice threshold and later repeats did not, while the longer `sign_ct_strict_falcon1024_none` run crossed the notice threshold
- one GNU/Linux ASan fuzz campaign is now recorded, but residual-risk wording and final release-language synthesis remain open

The exact `C0` claim boundary is fixed in `SECURITY.md` and `docs/c0_claim_boundary.md`; the stronger `C1` requirements remain in `docs/ct_threat_model.md`.

## Milestone Log

### Step 23

State after Step 23:

- `math/fpr/soft.rs` provides software emulation of binary64 on integers
- no production `f64` or `libm` is used inside that module
- binary64 constants are stored as raw bit patterns

Step 23 verification:

- unit tests compare operations bit-for-bit against native binary64 on fixed vectors
- `exp_small` is compared against the `ref_f64` backend

### Step 24

State after Step 24:

- `ExpandedSecretKeyCtInner` stores `b00`, `b01`, `b10`, `b11`, and `tree` as `FprSoft`
- `SecretKey::expand_ct_strict()` works for the public `Falcon512` and `Falcon1024` parameter sets
- expanded-key storage is secret-bearing and is cleared by `Drop + zeroize`

Step 24 verification:

- `src/falcon/expand_ct.rs` compares the expanded key bit-for-bit with the reference prepared key
- `tests/ct_consistency.rs` checks public `expand_ct_strict()` for 512 and 1024 and rejects non-public `logn`

### Step 25

State after Step 25:

- `src/sampler/sign_ct_strict.rs` implements the `SAMPLER_CDF=1` and `CT_BEREXP=1` path
- `gaussian0_sampler_ct()` consumes a fixed PRNG budget for a single attempt
- `ber_exp_ct()` consumes a fixed PRNG budget for a single attempt

Step 25 verification:

- sampler unit tests check fixed per-attempt PRNG budgets
- a deterministic regression sequence is stabilized on a fixed seed

### Step 27

State after Step 27:

- `ExpandedSecretKeyCt::{sign_ct_strict, sign_ct_strict_with_external_nonce}` work for the public parameter sets
- the signer uses the expanded key directly through an executor based on `FprSoft` and `fft_soft`
- runtime execution no longer depends on a private bridge to `ref_f64`

Step 27 verification:

- unit tests compare default-nonce and external-nonce signing on preserved reference material
- `tests/ct_consistency.rs` checks strict-path roundtrips and parity against `sign_ref` on fixed seeds

### Step 28

State after Step 28:

- `ExpandCtWorkspace<LOGN>` and `SignCtWorkspace<LOGN>` are public strict-path workspaces
- `SecretKey::expand_ct_strict_in()` reuses scratch when preparing the expanded key
- `ExpandedSecretKeyCt::{sign_ct_strict_in, sign_ct_strict_with_external_nonce_in}` reuse scratch across calls

Step 28 verification:

- `tests/ct_consistency.rs` checks one-shot / workspace parity on the same seeds and nonces
- strict-path roundtrips pass for both public parameter sets

### Step 29

State after Step 29:

- `src/falcon/sign_ct_strict.rs`, `src/sampler/sign_ct_strict.rs`, `src/falcon/expand_ct.rs`, and `src/math/fft_soft.rs` no longer import `ref_f64` or `libm` directly
- the strict signer uses the strict sampler and soft runtime path end-to-end
- `SignCtWorkspace<LOGN>` has its own scratch and `Drop + zeroize` coverage

Step 29 result:

- gate `C1.3` is closed in the narrow sense that the runtime strict path no longer directly uses `f64`

Step 29 verification:

- `tests/ct_consistency.rs` contains the source audit `strict_modules_do_not_directly_import_ref_f64_or_libm`
- strict-path roundtrip tests pass cleanly

### Step 30

State after Step 30:

- `tests/ct_consistency.rs` covers strict-path roundtrips, one-shot / workspace parity, header parity against `ref`, and timing smoke on fixed seeds
- `src/sampler/sign_ct_strict.rs` contains distribution smoke and timing smoke for the strict sampler
- `fuzz/decode_signature` is a compilable `libFuzzer` harness for the shared signature decoder

Step 30 result:

- the current engineering and regression surface for the public strict path is in place
- runtime strict signing goes exclusively through the soft-FFT / soft-FPR path
- the defensive CT audit is still open

Step 30 verification:

- `cargo test --test ct_consistency`
- `cargo test sampler::sign_ct_strict`
- `cargo test --no-default-features --features ct-strict`
- `CXX=clang++ cargo check --manifest-path fuzz/Cargo.toml`
- full `cargo test` on the supported research host

### Step 31

State after Step 31:

- `src/bin/ct_timing.rs` emits repo-tracked dudect-like timing datasets for `expand_ct_strict()` and `sign_ct_strict()`
- `artifacts/ct-dynamic-timing.json` stores machine-readable fixed-vs-varied timing batches
- `artifacts/ct-dynamic-timing.md` stores the current timing summary and t-statistic interpretation

Step 31 result:

- the repo now contains a real dynamic timing harness instead of only timing smoke tests
- the strict-path CT claim is still open; repeated pinned-CPU runs now exist, but the current VMware host does not provide a stable enough dynamic timing dossier for stronger wording

Step 31 verification:

- `cargo run --release --features deterministic-tests --bin ct_timing -- --out-dir artifacts --samples-per-class 256 --expand-batch 4 --sign-batch 4`
- repeated pinned-CPU 4096-sample checkpoints are summarized in `artifacts/ct-dynamic-timing-review.md`
