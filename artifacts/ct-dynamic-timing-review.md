# CT Dynamic Timing Review

This note interprets the repeated large-sample dudect-like timing checkpoints for
`expand_ct_strict()` and `sign_ct_strict()` that were run on the Ubuntu research
host and summarized in `artifacts/ct-dynamic-timing.md`.

## Host and Method

- host OS: `Linux 6.17.0-22-generic`
- virtualization reported by `systemd-detect-virt`: `vmware`
- CPU model from `/proc/cpuinfo`: `AMD Ryzen 3 5300U with Radeon Graphics`
- visible CPUs: `4`
- cpufreq governor interface: not exposed under `/sys/devices/system/cpu/cpu0/cpufreq/` on this host
- both runs were pinned to logical CPU `0` with `taskset -c 0`
- both runs used `--samples-per-class 4096 --expand-batch 8 --sign-batch 8`

Commands used:

```bash
taskset -c 0 cargo run --release --features deterministic-tests --bin ct_timing -- --out-dir artifacts/timing-runs/c1-ct-timing-20260423T083941Z --samples-per-class 4096 --expand-batch 8 --sign-batch 8
taskset -c 0 cargo run --release --features deterministic-tests --bin ct_timing -- --out-dir artifacts/timing-runs/c1-ct-timing-20260423T-repeat2 --samples-per-class 4096 --expand-batch 8 --sign-batch 8
```

## Welch t Summary

| Benchmark | Run 1 t | Run 2 t | Notes |
| --- | ---: | ---: | --- |
| `expand_ct_strict_falcon512` | `-0.221` | `1.301` | both runs below notice threshold |
| `expand_ct_strict_falcon1024` | `-1.462` | `0.222` | both runs below notice threshold |
| `sign_ct_strict_falcon512_none` | `-5.890` | `1.032` | first run crossed notice threshold; immediate repeat did not |
| `sign_ct_strict_falcon1024_none` | `0.158` | `1.532` | both runs below notice threshold |

## Interpretation

- Three of the four benchmarks remained below the notice threshold in both runs.
- `sign_ct_strict_falcon512_none` crossed the notice threshold in the first run, but the immediate repeated run on the same nominal host and command line did not reproduce that signal.
- The correct reading is therefore **not** "strict signing is proven constant-time" and also **not** "a stable Falcon-512 timing leak is already demonstrated".
- The correct reading is that the current VMware-host timing setup is still too noisy or insufficiently controlled to support stronger CT wording.
- This repo should therefore keep `C1` open and treat the current timing evidence as a blocking but inconclusive dossier checkpoint.

## Residual Technical Suspicion

The inconsistent sign-only result does not remove the structural reasons for caution:

- `src/sampler/sign_ct_strict.rs` still contains acceptance / retry logic
- `src/falcon/sign_ct_strict.rs` still retries until `is_short_binary(...)` accepts

Those control-flow structures remain the primary suspects for any real class-separation signal and should be paired with retry histograms and quieter-host reruns before stronger claims are made.

## Next Actions

1. rerun the same timing campaign on a quieter host with stronger frequency control, preferably bare metal
2. record retry histograms for the strict sampler and strict signer on the same deterministic input families
3. keep the final `C1` dossier language conservative until dynamic evidence and residual-risk wording settle
