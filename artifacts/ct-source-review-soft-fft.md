# Strict-Path Source Review: `soft_fft`

Scope: `src/math/fft_soft.rs`

This note records the current source-level review result for the strict-path
soft-FFT layer.

## Review Goal

The goal of this review is to determine whether `soft_fft` currently shows:

- secret-dependent memory indexing
- secret-dependent retry loops
- operand-dependent branches that still need to be called out explicitly

## Memory-Access Result

Current review result:

- no secret-dependent table lookup was identified in `src/math/fft_soft.rs`
- no secret-dependent slice indexing was identified in `src/math/fft_soft.rs`
- all observed indexing is derived from public `logn`, public array lengths, and
  loop counters
- the twiddle-factor lookup in `gm_entry()` indexes `FPR_GM_TAB_BITS` with
  values derived from public FFT stage counters, not from secret coefficients

This is a positive review result for memory access.

## Control-Flow Result

Current review result:

- the top-level branches (`if logn <= 1`, `if logn > 0`, `if logn == 0`) are
  public-parameter branches
- the `while j1 < hn` loop in `ifft()` is controlled by public FFT geometry
- the remaining loops iterate over public sizes (`n`, `hn`, `qn`) and loop
  counters derived from them
- no secret-driven retry loop was identified in this module

## Current Interpretation

Current claim supported by this review:

- `soft_fft` does not currently show secret-dependent memory indexing in the
  reviewed source
- `soft_fft` control flow is currently explained by public FFT sizes and stage
  counters
- no acceptance / rejection loop was identified in this module

Current claim *not* supported by this review:

- that the whole strict signing path is therefore audit-closed
- that composition with `soft_fpr`, the strict sampler, and strict signing
  control flow is already fully reviewed
- that `soft_fft` by itself closes `C1`

## Gate Effect

This review closes the specific `C1` checklist item for the source-level branch
and memory-access review of `soft_fft`.

It does **not** close the remaining `C1` work for:

- long-run GNU/Linux fuzz evidence
- larger-sample timing evidence and review notes
- source review of the strict sampler
- source review of strict signing control flow
- dependency triage and residual-risk wording
