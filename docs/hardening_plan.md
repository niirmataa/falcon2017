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
- [x] deterministic differential seed campaigns exist
- [x] strict-path runtime no longer directly imports `ref_f64` or `libm`
- [x] Ubuntu toolchain is available with `cargo`, `nightly`, `cargo-fuzz`, `cargo-audit`, `cc`, and `clang`

### `R1`: Reference-Equivalence Gate

- [x] baseline scope is written down in `docs/baseline_definition.md`
- [x] current `ref` claim boundary is written down in `docs/ref_security_claim.md`
- [ ] define the exact artifact set required for `Rust ref <-> C baseline` comparison
- [ ] generate machine-readable differential outputs for keygen, signing, encoding, and verification
- [ ] pin fixed seeds, fixed messages, and expected outputs in repo-tracked artifacts
- [ ] add a repo command that regenerates and validates the `R1` artifact set
- [ ] review and document every remaining semantic mismatch or nondeterministic allowance
- [ ] mark `R1` closed only after the artifact set is reproducible on the GNU/Linux host

### `C0`: Exact `ct_strict` Claim Boundary

- [x] current `ct_strict` engineering status is documented in `docs/ct-strict.md`
- [x] threat-model requirements are documented in `docs/ct_threat_model.md`
- [ ] enumerate all operand-dependent branches and retries in soft FPR, soft FFT, sampler, and signing
- [ ] separate "engineering evidence" from "security claim" in any remaining docs or release text
- [ ] record which properties are claimed today for `expand_ct_strict` and `sign_ct_strict`
- [ ] record which properties are explicitly not claimed today
- [ ] add a short release-facing note describing the exact public wording allowed before `C1`
- [ ] mark `C0` closed only when no public document overstates the strict-path claim

### `C1`: Strict-Path Audit-Candidate Dossier

- [ ] add a verification-focused fuzzer on the GNU/Linux ASan host
- [ ] run long decoder fuzzing with saved corpora and minimized crash artifacts
- [ ] run long verification fuzzing with saved corpora and minimized crash artifacts
- [ ] add dudect-like timing harnesses for `expand_ct_strict` and `sign_ct_strict`
- [ ] capture timing datasets and review notes in repo-tracked artifacts
- [ ] perform source-level branch and memory-access review for soft FPR
- [ ] perform source-level branch and memory-access review for soft FFT
- [ ] perform source-level branch and memory-access review for the strict sampler
- [ ] perform source-level branch and memory-access review for strict signing control flow
- [ ] run `cargo audit` and record the clean or triaged result
- [ ] define the residual-risk statement that remains true even if `C1` closes
- [ ] mark `C1` closed only after fuzz, timing, source review, and release notes all exist

## Active Work Queue

Work should proceed in this order:

1. `R1` reproducible artifacts
2. GNU/Linux decoder and verification fuzzing
3. dudect-like timing harnesses
4. source review dossier for strict-path internals
5. final claim-language cleanup for `C0` and `C1`

This order matters. Fuzzing and timing evidence should not be postponed behind architecture cleanup or Hawk work.

## Hard Commit Train

The next commits should be small, reviewable, and sequenced.

1. `audit: add hardening plan and gate tracker`
2. `differential: define reproducible R1 artifact set`
3. `differential: add Rust-C artifact generator and checker`
4. `fuzz: add verify_detached libFuzzer harness`
5. `fuzz: add GNU/Linux corpus and crash-artifact workflow`
6. `timing: add dudect-like strict-path harnesses`
7. `audit: record soft-fpr branch and memory-access review`
8. `audit: record soft-fft branch and memory-access review`
9. `audit: record strict sampler and signing control-flow review`
10. `audit: record cargo-audit status and dependency triage`
11. `docs: close R1 with reproducible differential dossier`
12. `docs: close C0 claim wording`
13. `docs: close C1 audit-candidate dossier`

If any commit grows beyond one concrete proof point, split it again.

## Recent Hardening Commits

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
