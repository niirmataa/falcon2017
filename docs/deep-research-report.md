# Deep Research Roadmap

This document captures planning conclusions from deeper repository review. It is not the canonical status file; `SECURITY.md` and the claim documents under `docs/` are the documents of record.

## Current Assessment

The repository is already a much cleaner Falcon 2017 / Extra port than a monolithic prototype:

- the public API is intentionally narrow
- the `ref` and `ct_strict` paths are clearly separated
- the historical wire format is preserved
- workspaces, zeroization, and decoder hardening are already present

The main limitation is not basic functionality. The main limitation is claim discipline:

- `ct_strict` has real engineering progress, but the defensive CT claim is still open
- `*_in(...)` reduces scratch reuse costs, but it does not yet eliminate output allocations
- long-run fuzzing and audit evidence still need to be produced on the intended GNU/ASan host

## What Moved Into Repo Docs

The deeper review is now split into focused documents:

- `docs/baseline_definition.md`: semantic target for the historical baseline
- `docs/ref_equivalence.md`: stop conditions for a stronger reference-equivalence claim
- `docs/ref_security_claim.md`: boundary for the current `ref` security claim
- `docs/ct_equivalence.md`: semantic-equivalence requirements for `ct_strict`
- `docs/ct_threat_model.md`: threat model and evidence requirements for a stronger CT claim
- `docs/ct-strict.md`: engineering milestone log plus current claim boundary
- `docs/tests.md`: current coverage plus fuzz/audit direction

## Immediate Priorities

The next concrete priorities are:

1. unify documentation around one honest claim boundary
2. push strong fuzzing on a GNU/Linux sanitizer-capable host
3. preserve machine-readable `Rust ref <-> C baseline` differential artifacts
4. add dudect-like timing evidence for the strict path
5. review soft FPR, soft FFT, sampler, and strict signing for branch and memory-access behavior

## Working Gates

The repo should be driven by three gates:

- `R1`: close the reference-equivalence gate
- `C0`: define the exact `ct_strict` claim boundary
- `C1`: build a real strict-path audit-candidate dossier

Only after those gates should the repository revisit broader API generalization, aggressive `no_std` refactoring, or any shared Falcon/Hawk core.

## Final Direction

The engineering direction is intentionally conservative:

- finish Falcon 2017 / Extra reference fidelity first
- harden the strict signing path with strong fuzzing and a real audit trail
- avoid stronger CT language until the evidence exists
- defer Hawk-driven abstraction work until Falcon itself is through `R1`, `C0`, and `C1`

That sequencing keeps the repository auditable and avoids turning future architecture work into a substitute for present security evidence.
