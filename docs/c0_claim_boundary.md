# C0 Claim Boundary for `ct_strict`

This document closes gate `C0`: the exact public wording allowed today for the
`ct_strict` backend.

`C0` is a claim-discipline gate, not a side-channel-proof gate. It exists so the
repository can say exactly what `ct_strict` is today without overstating what
remains open until `C1`.

## What may be claimed today

The repository may claim the following about `ct_strict` today:

- a runtime integer-only strict-path signer exists for public binary
  `Falcon512` and `Falcon1024`
- runtime strict signing executes through `FprSoft` and `fft_soft`, without a
  direct runtime bridge to `ref_f64`
- public strict production modules no longer directly import `ref_f64` or `libm`
- the public strict-path APIs have roundtrip, parity, workspace-parity,
  sampler-budget, timing-smoke, and dudect-like timing-harness coverage
- shared decoder fuzz harnesses exist for artifacts used by both `ref` and
  `ct_strict`
- the current strict-path implementation is a serious engineering track intended
  to preserve Falcon 2017 / Round1 Extra wire semantics while reducing leakage
  relative to the reference runtime path

## What may not be claimed today

The repository must not currently claim any of the following:

- that `ct_strict` is already a completed, audit-closed, defensively
  constant-time backend
- that all operand-dependent branches, retries, or memory-access questions have
  already been eliminated or cleared by review
- that the repo already contains a completed timing dossier or completed long-run
  GNU/ASan fuzz dossier for the strict path
- that the current timing harness or current fuzz harnesses by themselves prove a
  full side-channel claim
- that the repository is ready for high-assurance or production deployment on the
  strength of `ct_strict`

## Operand-Dependent Control-Flow Inventory

The following surfaces are the explicit reasons a stronger `ct_strict` claim is
still reserved for `C1`.

### `src/math/fpr/soft.rs`

`FprSoft` is integer-only, but it still contains operand-dependent control flow
that requires source review before any stronger CT claim:

- normalization and packing branches in `round_pack()`
- data-dependent normalization loops in `round_pack()`
- data-dependent integer-square-root progress in `isqrt_u128()`
- decode / rounding / sign / zero handling branches across the software-binary64
  helpers

These branches are part of software floating-point emulation. They are not by
this document asserted to be safe or unsafe; they are asserted to still require
review.

### `src/math/fft_soft.rs`

`fft_soft` currently appears to use only public-parameter and loop-index control
flow, such as `logn`-based branches and public-size iteration. No secret-driven
retry loop is currently identified there.

However, `fft_soft` still remains in the `C1` source-review queue because the
repository has not yet recorded a completed branch and memory-access review for
its composed use in strict signing.

### `src/sampler/sign_ct_strict.rs`

The strict sampler has a fixed PRNG budget per attempt for `gaussian0_sampler_ct`
and `ber_exp_ct`, but the top-level sampler still retries until acceptance:

- `sample_binary_ct()` loops until `ber_exp_ct(...)` accepts
- acceptance depends on the sampled candidate and operand-derived probability

This means per-attempt budget is fixed, but total attempt count is still
variable.

### `src/falcon/sign_ct_strict.rs`

The strict signer still contains a signature-level retry loop:

- `sign_ct_strict_with_external_nonce_in()` loops until
  `is_short_binary(...)` accepts the sampled pair

This preserves Falcon signing semantics, but it also means total runtime remains
acceptance-driven.

### `src/falcon/expand_ct.rs`

`expand_ct_strict` currently appears to use only public-parameter recursion and a
public normalization flag. No secret-driven retry loop is currently identified
there.

It still remains inside the `C1` review scope because the repository has not yet
published the source-level branch and memory-access review for the expanded-key
preparation path.

## Allowed Public Release Wording Before `C1`

Before `C1`, release notes, README text, discussions, and issue summaries should
stay within wording like the following:

> `ct_strict` is a candidate constant-time backend under active audit hardening.
> It uses an integer-only strict runtime path for public Falcon-512 and
> Falcon-1024 signing, preserves Falcon 2017 / Round1 Extra wire semantics on
> the current tested surface, and remains short of a completed defensive
> constant-time claim until the timing, fuzzing, and source-review dossier is
> closed.

Avoid wording like:

- "`ct_strict` is now constant-time"
- "the strict backend has been fully side-channel audited"
- "the strict backend is production-ready"
- "timing and fuzzing evidence are complete"

## Gate Result

`C0` is closed once repository-facing docs stay within the wording above and do
not overstate the strict-path evidence. `C1` remains the next gate.
