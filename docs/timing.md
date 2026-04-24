# CT Timing Harness

This document defines the repository's current dudect-like timing workflow for
the `ct_strict` path.

## Scope

The current in-repo timing harness is:

```bash
cargo run --release --features deterministic-tests --bin ct_timing -- --out-dir artifacts --samples-per-class 256 --expand-batch 4 --sign-batch 4
```

It emits:

- `artifacts/ct-dynamic-timing.json`
- `artifacts/ct-dynamic-timing.md`

## What It Measures

The current harness records batch timings for:

- `SecretKey::expand_ct_strict()` on Falcon-512
- `SecretKey::expand_ct_strict()` on Falcon-1024
- `ExpandedSecretKeyCt::sign_ct_strict()` on Falcon-512 with `Compression::None`
- `ExpandedSecretKeyCt::sign_ct_strict()` on Falcon-1024 with `Compression::None`

The fixed class repeats one deterministic input family.

The varied class walks a deterministic family of:

- key-generation seeds
- signing seeds
- fixed-length messages

All class comparisons keep the same public parameter size.

## Statistic

The current summary computes Welch's t-statistic between the fixed and varied
classes.

Working interpretation:

- `|t| < 4.5`: no class separation observed at the current notice threshold
- `4.5 <= |t| < 10`: investigate on a controlled host
- `|t| >= 10`: strong separation signal; strong CT wording is blocked

This is dudect-like evidence, not a completed side-channel proof.

## Limits

The current harness does not by itself close `C1`.

Remaining gaps include:

- repeated runs on a quieter host with stronger frequency control, preferably bare metal
- retry-histogram evidence tying any signing-class timing difference back to attempt behavior
- residual-risk wording for the strict path
- final C1 dossier synthesis

## Tracked Pinned-CPU Checkpoints

The canonical repo-tracked timing artifacts now come from:

- `artifacts/ct-dynamic-timing.json`
- `artifacts/ct-dynamic-timing.md`
- `artifacts/ct-dynamic-timing-review.md`

The current tracked summary file comes from the first large-sample pinned run:

```bash
taskset -c 0 cargo run --release --features deterministic-tests --bin ct_timing -- --out-dir artifacts/timing-runs/c1-ct-timing-20260423T083941Z --samples-per-class 4096 --expand-batch 8 --sign-batch 8
```

Two direct repeated 4096-sample runs and one longer 16384-sample run on the same host were also captured and summarized in `artifacts/ct-dynamic-timing-review.md`:

```bash
taskset -c 0 cargo run --release --features deterministic-tests --bin ct_timing -- --out-dir artifacts/timing-runs/c1-ct-timing-20260423T-repeat2 --samples-per-class 4096 --expand-batch 8 --sign-batch 8
taskset -c 0 cargo run --release --features deterministic-tests --bin ct_timing -- --out-dir artifacts/timing-runs/c1-ct-timing-20260423T-repeat3 --samples-per-class 4096 --expand-batch 8 --sign-batch 8
taskset -c 0 cargo run --release --features deterministic-tests --bin ct_timing -- --out-dir artifacts/timing-runs/c1-ct-timing-long-20260424T080636Z --samples-per-class 16384 --expand-batch 8 --sign-batch 8
```

Current tracked interpretation:

- the host is a VMware guest and does not expose cpufreq governor control through `/sys/devices/system/cpu/cpu0/cpufreq/`
- both `expand_ct_strict()` benchmarks remained below the notice threshold in all tracked runs
- `sign_ct_strict_falcon512_none` crossed the notice threshold in the first 4096-sample run (`t = -5.890`) but not in the two immediate repeats (`t = 1.032`, `t = 1.434`) or the long run (`t = -0.142`)
- `sign_ct_strict_falcon1024_none` crossed the notice threshold in the long run (`t = -9.751`) after staying below the threshold in the three 4096-sample runs
- the current host therefore gives useful blocking evidence, but not a stable enough timing platform to support stronger CT wording or to close `C1`
