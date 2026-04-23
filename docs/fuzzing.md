# GNU Fuzz Campaigns

This document defines the reproducible GNU/Linux fuzzing workflow for the
repository's audit-facing campaigns.

## Scope

The current in-repo libFuzzer targets are:

- `decode_signature`
- `decode_public_key`
- `decode_secret_key`
- `verify`

These targets are compiled from `fuzz/Cargo.toml` and are intended to run on a
GNU/Linux host with nightly Rust and sanitizer support.

## Host Requirements

The current campaign workflow expects:

- GNU/Linux host
- `rustup` with `nightly`
- `cargo-fuzz`
- Clang/LLVM sanitizer support
- working C toolchain for the frozen Falcon baseline helper

The local Alpine/musl setup is not the intended evidence host for long runs.

## Campaign Command

The in-repo campaign driver is:

```bash
scripts/run_gnu_fuzz_campaign.sh --time 1800
```

Useful variants:

```bash
scripts/run_gnu_fuzz_campaign.sh --target verify --time 3600
scripts/run_gnu_fuzz_campaign.sh --target decode_signature --target verify --time 7200
```

## Run Layout

By default the script writes to:

```text
artifacts/fuzz/runs/<timestamp>/
  metadata.json
  logs/
  artifacts/
  corpus/
  minimized-crashes/
```

Per target, the run stores:

- copied seed corpus used as campaign input
- libFuzzer log
- raw crash artifacts from `-artifact_prefix`
- minimized crash files via `cargo fuzz tmin`
- target exit status

The `artifacts/fuzz/runs/` tree is ignored by default because long campaigns
can generate large local outputs. Curated research results should be copied out
of a specific run and committed separately when they become part of the dossier.

## Interpretation

These campaigns provide robustness evidence, not semantic equivalence by
themselves.

Interpretation rules:

- a clean run strengthens decoder/verification hardening evidence
- a crash artifact must be preserved together with the target log and minimized case
- long-run fuzz evidence belongs in the `C1` dossier, not in the `R1` equivalence claim
- fuzzing complements, but does not replace, differential testing and timing analysis

## Tracked GNU/Linux ASan Checkpoint

The repository now tracks one curated GNU/Linux ASan campaign result under:

- `artifacts/fuzz/c1-gnu-asan-20260423.json`
- `artifacts/fuzz/c1-gnu-asan-20260423.md`

This checkpoint records a clean 1800-second campaign for:

- `decode_signature`
- `decode_public_key`
- `decode_secret_key`
- `verify`

Current recorded result:

- all four targets exited with status `0`
- no crash artifacts were emitted
- decoder targets reached large multi-million to multi-hundred-million execution counts
- the verification target completed cleanly at lower throughput and remains a good candidate for longer dedicated campaigns later
