# CT Dynamic Timing Summary

- generated_at_unix_s: `1776926383`
- host: `linux/x86_64`
- hostname: `unknown`
- samples per class: `4096`
- dudect-like thresholds: notice `|t| >= 4.5`, strong `|t| >= 10.0`

This is a dudect-like timing checkpoint, not an audit-closed constant-time proof.
The fixed class repeats one deterministic input family; the varied class walks a deterministic seed family of equal public size.
Interpret this dataset together with `artifacts/ct-dynamic-timing-review.md`, which compares it against an immediate repeated pinned-CPU run on the same VMware host.

## expand_ct_strict_falcon512

- operation: `expand_ct_strict`
- logn: `9`
- batch: `8`
- fixed class: `fixed_secret_key`
- varied class: `varied_secret_keys`
- mean fixed per call: `3659139.2 ns`
- mean varied per call: `3666392.3 ns`
- median fixed batch: `26770303` ns
- median varied batch: `26896438` ns
- p95 fixed batch: `44354371` ns
- p95 varied batch: `44020859` ns
- Welch t: `-0.221`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## expand_ct_strict_falcon1024

- operation: `expand_ct_strict`
- logn: `10`
- batch: `8`
- fixed class: `fixed_secret_key`
- varied class: `varied_secret_keys`
- mean fixed per call: `7834752.8 ns`
- mean varied per call: `8053052.4 ns`
- median fixed batch: `59740649` ns
- median varied batch: `59531559` ns
- p95 fixed batch: `88536768` ns
- p95 varied batch: `88745552` ns
- Welch t: `-1.462`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## sign_ct_strict_falcon512_none

- operation: `sign_ct_strict`
- logn: `9`
- batch: `8`
- fixed class: `fixed_key_message_rng`
- varied class: `varied_key_message_rng`
- mean fixed per call: `8325674.7 ns`
- mean varied per call: `8845616.1 ns`
- median fixed batch: `58489967` ns
- median varied batch: `61798408` ns
- p95 fixed batch: `111713688` ns
- p95 varied batch: `121112269` ns
- Welch t: `-5.890`
- interpretation: class separation crossed the dudect notice threshold; rerun on a controlled host and investigate

## sign_ct_strict_falcon1024_none

- operation: `sign_ct_strict`
- logn: `10`
- batch: `8`
- fixed class: `fixed_key_message_rng`
- varied class: `varied_key_message_rng`
- mean fixed per call: `11324297.8 ns`
- mean varied per call: `11311620.0 ns`
- median fixed batch: `82758507` ns
- median varied batch: `82644336` ns
- p95 fixed batch: `133602525` ns
- p95 varied batch: `133519639` ns
- Welch t: `0.158`
- interpretation: no class separation observed at the current dudect notice threshold on this host
