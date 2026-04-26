# CT VM Checkpoint After Bounded Strict Rejection Loops

- commit under test: `1bb6deb sign: bound strict rejection loops`
- parent CT/FPR baseline: `6e0c1c2 fpr: remove soft backend control-flow branches`
- host: Ubuntu VM over SSH, `linux/x86_64`
- date: `2026-04-26`
- command:

```sh
cargo run --release --features deterministic-tests,ct-strict,soft-fpr --bin ct_timing -- \
  --out-dir artifacts/ct-vm-1bb6deb-20260426 \
  --samples-per-class 512 \
  --expand-batch 4 \
  --sign-batch 2
```

This is a diagnostic VM checkpoint, not an audit-closed CT proof. It is kept
because it directly follows the code change that bounds the strict sampler and
outer signing rejection loops.

Observed Welch `|t|` values stayed below the dudect-like notice threshold `4.5`:

- `expand_ct_strict_falcon512`: `0.020`
- `expand_ct_strict_falcon1024`: `0.469`
