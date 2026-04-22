# CT Dynamic Timing Summary

- generated_at_unix_s: `1776866874`
- host: `linux/x86_64`
- hostname: `unknown`
- samples per class: `256`
- dudect-like thresholds: notice `|t| >= 4.5`, strong `|t| >= 10.0`

This is a dudect-like timing checkpoint, not an audit-closed constant-time proof.
The fixed class repeats one deterministic input family; the varied class walks a deterministic seed family of equal public size.

## expand_ct_strict_falcon512

- operation: `expand_ct_strict`
- logn: `9`
- batch: `4`
- fixed class: `fixed_secret_key`
- varied class: `varied_secret_keys`
- mean fixed per call: `2897066.3 ns`
- mean varied per call: `2926002.5 ns`
- median fixed batch: `11209092` ns
- median varied batch: `11342573` ns
- p95 fixed batch: `14185438` ns
- p95 varied batch: `14194074` ns
- Welch t: `-0.666`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## expand_ct_strict_falcon1024

- operation: `expand_ct_strict`
- logn: `10`
- batch: `4`
- fixed class: `fixed_secret_key`
- varied class: `varied_secret_keys`
- mean fixed per call: `6426293.0 ns`
- mean varied per call: `6384628.3 ns`
- median fixed batch: `24810467` ns
- median varied batch: `24968736` ns
- p95 fixed batch: `31904224` ns
- p95 varied batch: `30704330` ns
- Welch t: `0.575`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## sign_ct_strict_falcon512_none

- operation: `sign_ct_strict`
- logn: `9`
- batch: `4`
- fixed class: `fixed_key_message_rng`
- varied class: `varied_key_message_rng`
- mean fixed per call: `4686400.6 ns`
- mean varied per call: `4745095.0 ns`
- median fixed batch: `18296265` ns
- median varied batch: `18604998` ns
- p95 fixed batch: `21890398` ns
- p95 varied batch: `23300067` ns
- Welch t: `-1.089`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## sign_ct_strict_falcon1024_none

- operation: `sign_ct_strict`
- logn: `10`
- batch: `4`
- fixed class: `fixed_key_message_rng`
- varied class: `varied_key_message_rng`
- mean fixed per call: `10587678.9 ns`
- mean varied per call: `10556171.2 ns`
- median fixed batch: `40965623` ns
- median varied batch: `41299182` ns
- p95 fixed batch: `50498301` ns
- p95 varied batch: `50144654` ns
- Welch t: `0.255`
- interpretation: no class separation observed at the current dudect notice threshold on this host
