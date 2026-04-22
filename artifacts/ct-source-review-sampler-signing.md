# Strict-Path Source Review: Sampler and Signing Control Flow

Scope:

- `src/sampler/sign_ct_strict.rs`
- `src/falcon/sign_ct_strict.rs`

This note records the current source-level review result for the strict sampler
and the strict signing control flow.

## Memory-Access Result

Current review result:

- no secret-dependent table lookup was identified in the reviewed strict sampler
  and strict signing source
- `gaussian0_sampler_ct()` walks the fixed `CDF` table linearly and does not
  index it with secret-derived values
- the signing path operates on preallocated slices and workspaces with indices
  derived from public `logn` and public loop counters
- no secret-derived slice selection or secret-derived table lookup was
  identified in the reviewed files

This is a positive review result for memory access.

## Control-Flow Result

The reviewed files still contain acceptance-driven control flow.

### Strict sampler

`src/sampler/sign_ct_strict.rs` has two different layers:

- per-attempt helpers
  - `gaussian0_sampler_ct()` uses a fixed linear walk over the static `CDF`
    table and a fixed PRNG budget for one attempt
  - `ber_exp_ct()` uses a fixed PRNG budget for one attempt
- top-level sampling
  - `sample_binary_ct()` loops until `ber_exp_ct(...)` accepts a candidate

This means the sampler has a fixed budget per attempt, but the total number of
attempts remains variable.

### Strict signing

`src/falcon/sign_ct_strict.rs` still contains a signature-level retry loop:

- `sign_ct_strict_with_external_nonce_in()` loops until
  `is_short_binary(...)` accepts the sampled pair `(s1, s2)`

This preserves Falcon signing semantics, but it keeps total runtime dependent on
acceptance.

## Current Interpretation

Current claim supported by this review:

- no secret-dependent memory indexing was identified in the reviewed strict
  sampler and strict signing source
- the remaining variable-time surfaces are now explicit and documented
- the repository can point to concrete retry sites instead of using vague CT
  wording

Current claim *not* supported by this review:

- that the sampler is branchless
- that strict signing is retry-free
- that `ct_strict` is already a completed defensively constant-time backend
- that this review closes `C1`

## Gate Effect

This review closes the specific `C1` checklist items for:

- source-level branch and memory-access review of the strict sampler
- source-level branch and memory-access review of strict signing control flow

It does **not** close the remaining `C1` work for:

- long-run GNU/Linux fuzz evidence
- larger-sample timing evidence and review notes
- dependency triage and residual-risk wording
- the final `C1` dossier write-up
