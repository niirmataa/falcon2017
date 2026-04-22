# Strict-Path Source Review: `soft_fpr`

Scope: `src/math/fpr/soft.rs`

This note records the current source-level review result for the integer-only
software-binary64 runtime used by the strict signing path.

## Review Goal

The goal of this review is narrower than a full CT proof:

- identify whether the module performs secret-dependent memory access
- inventory operand-dependent branches and loops
- decide whether the module may already be described as audit-cleared

## Memory-Access Result

Current review result:

- no secret-dependent table lookup was identified in `src/math/fpr/soft.rs`
- no secret-dependent slice indexing was identified in `src/math/fpr/soft.rs`
- the production helpers operate on scalar values and fixed constants
- the polynomial coefficients used by `fpr_exp_small()` are fixed compile-time
  constants, not secret-indexed tables

This is a positive review result for memory access, not a completed CT claim for
control flow.

## Operand-Dependent Control Flow Inventory

The module still contains operand-dependent control flow. The strongest examples
in the current implementation are:

- `round_pack()`
  - zero / overflow / normal / subnormal branches
  - rounding branches based on remainder bits
  - normalization loops while the extended significand is above or below the
    target range
- `isqrt_u128()`
  - operand-dependent loop progress and subtraction branch
- `decode()`, `normalize53()`, `cmp_abs_decoded()`
  - zero / non-zero / exponent-comparison branches
- `fpr_rint()` and `fpr_floor()`
  - sign-dependent and exponent-dependent branches
  - saturation branches for large magnitudes
- `fpr_add()`, `fpr_sub()`, `fpr_mul()`, `fpr_div()`, `fpr_sqrt()`, `fpr_lt()`
  - zero / sign / ordering branches
  - multiplication/division scaling branches
  - sqrt normalization and exact-square adjustment branch

These branches are expected for software floating-point emulation, but they
mean the module is not audit-cleared merely because it avoids `f64` and `libm`.

## Current Interpretation

Current claim supported by this review:

- `soft_fpr` is integer-only
- no secret-dependent memory indexing was identified in the reviewed source
- operand-dependent control flow remains present and documented

Current claim *not* supported by this review:

- that `soft_fpr` is already branchless
- that `soft_fpr` is already defensively constant-time by source review alone
- that `soft_fpr` closes `C1`

## Gate Effect

This review closes the specific `C1` checklist item for the source-level branch
and memory-access review of `soft_fpr`.

It does **not** close the remaining `C1` work for:

- long-run GNU/Linux fuzz evidence
- larger-sample timing evidence and review notes
- source review of `soft_fft`
- source review of the strict sampler
- source review of strict signing control flow
- dependency triage and residual-risk wording
