# Security Claim Boundary

This repository is a research-oriented Rust implementation of Falcon 2017 /
Round1 Extra, with two distinct implementation tracks:

- `ref`: semantic fidelity to the historical C baseline
- `ct_strict`: an implementation-hardening track intended to preserve scheme
  semantics while improving resistance to timing and microarchitectural leakage

This file defines the strongest security language currently supported by the
evidence in the repository.

## What may be claimed today

The repository may claim the following:

- the Rust `ref` backend is strongly tested against the frozen Falcon 2017 /
  Round1 Extra baseline in `references/falcon-2017-extra/`
- the Rust implementation preserves the historical wire formats within the
  currently supported public scope
- the public scope is intentionally narrow: binary Falcon only, `logn = 9` and
  `logn = 10`
- the `ct_strict` backend is a serious strict-path engineering effort with
  software FPR support, soft-FFT support, workspace-backed execution, and
  dedicated tests

## What may not be claimed yet

The repository must not currently claim:

- that the `ref` backend has completed a full formal equivalence closure
- that Falcon 2017 security has been reproven here from first principles
- that `ct_strict` is already a completed, audit-closed, defensively
  constant-time implementation
- that the repository is production-ready for high-assurance deployment

## Current gates

The repository is organized around three evidence gates:

- `R1`: closed reference-equivalence checkpoint for the `ref` backend
- `C0`: closed exact public wording for the `ct_strict` claim boundary
- `C1`: open strict-path audit-candidate dossier

These gates are elaborated in:

- `docs/ref_equivalence.md`
- `docs/ref_security_claim.md`
- `docs/ct_threat_model.md`
- `docs/ct_equivalence.md`
- `docs/c0_claim_boundary.md`
- `docs/hardening_plan.md`

## Reference-path interpretation

The `ref` backend is judged against the frozen historical baseline, not against
later Falcon revisions. The intended claim is:

> the Rust `ref` backend preserves the semantics and parameter choices of
> Falcon 2017 / Round1 Extra closely enough that its security should be
> interpreted as the historical scheme's security claim, not as a new variant
> invented by this repository.

That claim remains conditional on the closure criteria in
`docs/ref_equivalence.md` and `docs/ref_security_claim.md`.

## Strict-path interpretation

The intended long-term claim for `ct_strict` is:

> the backend preserves Falcon 2017 / Round1 Extra semantics while changing
> only the implementation strategy used to reduce side-channel leakage.

That claim is not complete until:

- semantic-equivalence evidence is recorded
- timing evidence is recorded
- fuzz evidence is recorded on a suitable GNU/Linux sanitizer-capable host
- source-level review of strict-path internals is completed

Until `C1` closes, `ct_strict` should be described as:

- a strict-path engineering track
- a candidate constant-time backend
- a research implementation under active audit hardening

## Release-language rule

Any README text, release note, or external description must stay within the
boundaries above unless the repository explicitly closes the corresponding gate
with reviewable artifacts.
