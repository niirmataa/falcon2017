# Hardening Plan

This document is the execution checklist for the repository's near-term security work.

The goal is simple:

- strong fuzzing on a GNU/Linux sanitizer-capable host
- a hard audit trail for the strict signing path
- disciplined closure of `R1`, `C0`, and `C1`

`SECURITY.md` defines the current claim boundary. This file defines the work sequence needed to tighten that boundary.

## Gate Tracker

### Foundation

- [x] historical C baseline is kept in-repo under `references/falcon-2017-extra/`
- [x] Rust `ref` and `ct_strict` paths are split into separate implementation tracks
- [x] public decoder fuzz targets exist for key and signature artifacts
- [x] in-repo verification fuzz target exists under `fuzz/fuzz_targets/verify.rs`
- [x] deterministic differential seed campaigns exist
- [x] strict-path runtime no longer directly imports `ref_f64` or `libm`
- [x] Ubuntu toolchain is available with `cargo`, `nightly`, `cargo-fuzz`, `cargo-audit`, `cc`, and `clang`

### `R1`: Reference-Equivalence Gate

- [x] baseline scope is written down in `docs/baseline_definition.md`
- [x] current `ref` claim boundary is written down in `docs/ref_security_claim.md`
- [x] define the exact artifact set required for `Rust ref <-> C baseline` comparison
- [x] generate machine-readable differential outputs for keygen, signing, encoding, and verification
- [x] pin fixed seeds, fixed messages, and expected outputs in repo-tracked artifacts
- [x] add a repo command that regenerates and validates the `R1` artifact set
- [x] review and document every remaining semantic mismatch or nondeterministic allowance
- [x] mark `R1` closed only after the artifact set is reproducible on the GNU/Linux host

### `C0`: Exact `ct_strict` Claim Boundary

- [x] current `ct_strict` engineering status is documented in `docs/ct-strict.md`
- [x] threat-model requirements are documented in `docs/ct_threat_model.md`
- [x] enumerate all operand-dependent branches and retries in soft FPR, soft FFT, sampler, and signing
- [x] separate "engineering evidence" from "security claim" in any remaining docs or release text
- [x] record which properties are claimed today for `expand_ct_strict` and `sign_ct_strict`
- [x] record which properties are explicitly not claimed today
- [x] add a short release-facing note describing the exact public wording allowed before `C1`
- [x] mark `C0` closed only when no public document overstates the strict-path claim

### `C1`: Strict-Path Audit-Candidate Dossier

- [ ] run the in-repo verification-focused fuzzer on the GNU/Linux ASan host
- [ ] run long decoder fuzzing with saved corpora and minimized crash artifacts
- [ ] run long verification fuzzing with saved corpora and minimized crash artifacts
- [x] add dudect-like timing harnesses for `expand_ct_strict` and `sign_ct_strict`
- [ ] capture timing datasets and review notes in repo-tracked artifacts
- [x] perform source-level branch and memory-access review for soft FPR
- [x] perform source-level branch and memory-access review for soft FFT
- [x] perform source-level branch and memory-access review for the strict sampler
- [x] perform source-level branch and memory-access review for strict signing control flow
- [x] run `cargo audit` and record the clean or triaged result
- [ ] define the residual-risk statement that remains true even if `C1` closes
- [ ] mark `C1` closed only after fuzz, timing, source review, and release notes all exist

## Active Work Queue

Work should proceed in this order:

1. GNU/Linux decoder and verification fuzzing
2. larger-sample dudect-like timing campaigns and review notes
3. residual-risk statement for `C1`
4. final `C1` dossier write-up after fuzz and timing artifacts settle

This order matters. Fuzzing and timing evidence should not be postponed behind architecture cleanup or Hawk work.

## Hard Commit Train

The next commits should be small, reviewable, and sequenced.

1. `fuzz: record GNU/Linux decoder and verification campaigns`
2. `timing: scale strict-path dudect-like evidence`
3. `docs: close C1 audit-candidate dossier`

If any commit grows beyond one concrete proof point, split it again.

## Recent Hardening Commits

`C0` is now treated as closed by the documentation set in `SECURITY.md`, `README.md`, `docs/c0_claim_boundary.md`, `docs/ct-strict.md`, and `docs/api.md`.

These are the recent commits that already moved the repo in the right direction:

- `6b0e2ec` `close C1.3 strict runtime path`
- `0594485` `fix secret key big-F/G representation`
- `3dd29c4` `add differential seed campaigns`
- `8e69731` `tighten malformed decoding regressions`
- `c575401` `add codec property tests`
- `8fe1405` `expand fuzz harness coverage`
- `ebb055d` `translate repo docs to English`

## Non-Goals Until Gates Close

Do not treat these as current priorities:

- Hawk integration
- generalized Falcon/Hawk shared core work
- broad API expansion beyond the scoped Falcon 2017 / Extra surface
- claiming full-signature defensive constant time for `ct_strict`
- treating workspace-backed APIs as allocation-free
