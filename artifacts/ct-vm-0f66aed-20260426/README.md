# CT VM Checkpoint After Fixed-Step Soft-FPR Division

- commit under test: `0f66aed fpr: avoid hardware division in soft backend`
- previous timing checkpoint: `1ab2c05 artifacts: record ct timing after bounded loops`
- host: Ubuntu VM over SSH, `linux/x86_64`
- date: `2026-04-26`
- command:

```sh
cargo run --release --features deterministic-tests,ct-strict,soft-fpr --bin ct_timing -- \
  --out-dir artifacts/ct-vm-0f66aed-20260426 \
  --samples-per-class 256 \
  --expand-batch 2 \
  --sign-batch 1
```

This is a diagnostic VM checkpoint, not an audit-closed CT proof. It directly
follows replacing the soft-FPR `u128 / u128` and `%` operations in `fpr_div`
with a fixed 109-step binary long division.

A release ASM scan for `cargo rustc --release --no-default-features --features ct-strict --lib -- --emit=asm`
reported no `div`/`idiv` instruction matches in the generated `falcon2017-*.s`
files on this host.

Observed Welch `|t|` values stayed below the dudect-like notice threshold `4.5`:

- `expand_ct_strict_falcon512`: `1.266`
- `expand_ct_strict_falcon1024`: `0.885`
- `sign_ct_strict_falcon512_none`: `1.872`
- `sign_ct_strict_falcon1024_none`: `0.412`
