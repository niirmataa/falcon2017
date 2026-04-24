# CT Dynamic Timing Summary

- generated_at_unix_s: `1776979504`
- host: `linux/x86_64`
- hostname: `unknown`
- samples per class: `4096`
- dudect-like thresholds: notice `|t| >= 4.5`, strong `|t| >= 10.0`

This is a dudect-like timing checkpoint, not an audit-closed constant-time proof.
The fixed class repeats one deterministic input family; the varied class walks a deterministic seed family of equal public size.

## expand_ct_strict_falcon512

- operation: `expand_ct_strict`
- logn: `9`
- batch: `8`
- fixed class: `fixed_secret_key`
- varied class: `varied_secret_keys`
- mean fixed per call: `2426739.7 ns`
- mean varied per call: `2434766.2 ns`
- median fixed batch: `18868369` ns
- median varied batch: `18916470` ns
- p95 fixed batch: `22688598` ns
- p95 varied batch: `22842358` ns
- Welch t: `-1.315`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## expand_ct_strict_falcon1024

- operation: `expand_ct_strict`
- logn: `10`
- batch: `8`
- fixed class: `fixed_secret_key`
- varied class: `varied_secret_keys`
- mean fixed per call: `5145017.6 ns`
- mean varied per call: `5131830.2 ns`
- median fixed batch: `40412282` ns
- median varied batch: `40458525` ns
- p95 fixed batch: `46072131` ns
- p95 varied batch: `46046292` ns
- Welch t: `1.359`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## sign_ct_strict_falcon512_none

- operation: `sign_ct_strict`
- logn: `9`
- batch: `8`
- fixed class: `fixed_key_message_rng`
- varied class: `varied_key_message_rng`
- mean fixed per call: `3835496.8 ns`
- mean varied per call: `3822993.5 ns`
- median fixed batch: `29975939` ns
- median varied batch: `29860521` ns
- p95 fixed batch: `35462044` ns
- p95 varied batch: `35372014` ns
- Welch t: `1.434`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## sign_ct_strict_falcon1024_none

- operation: `sign_ct_strict`
- logn: `10`
- batch: `8`
- fixed class: `fixed_key_message_rng`
- varied class: `varied_key_message_rng`
- mean fixed per call: `9318603.6 ns`
- mean varied per call: `9262500.9 ns`
- median fixed batch: `69644887` ns
- median varied batch: `69611592` ns
- p95 fixed batch: `95862043` ns
- p95 varied batch: `92985206` ns
- Welch t: `1.162`
- interpretation: no class separation observed at the current dudect notice threshold on this host

