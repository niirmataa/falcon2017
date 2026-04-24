# CT Dynamic Timing Summary

- generated_at_unix_s: `1777018045`
- host: `linux/x86_64`
- hostname: `unknown`
- samples per class: `16384`
- dudect-like thresholds: notice `|t| >= 4.5`, strong `|t| >= 10.0`

This is a dudect-like timing checkpoint, not an audit-closed constant-time proof.
The fixed class repeats one deterministic input family; the varied class walks a deterministic seed family of equal public size.

## expand_ct_strict_falcon512

- operation: `expand_ct_strict`
- logn: `9`
- batch: `8`
- fixed class: `fixed_secret_key`
- varied class: `varied_secret_keys`
- mean fixed per call: `2625317.0 ns`
- mean varied per call: `2622562.2 ns`
- median fixed batch: `19033569` ns
- median varied batch: `19024684` ns
- p95 fixed batch: `30576517` ns
- p95 varied batch: `30871536` ns
- Welch t: `0.250`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## expand_ct_strict_falcon1024

- operation: `expand_ct_strict`
- logn: `10`
- batch: `8`
- fixed class: `fixed_secret_key`
- varied class: `varied_secret_keys`
- mean fixed per call: `6374488.7 ns`
- mean varied per call: `6396840.2 ns`
- median fixed batch: `44748464` ns
- median varied batch: `44920207` ns
- p95 fixed batch: `84304789` ns
- p95 varied batch: `84384438` ns
- Welch t: `-0.753`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## sign_ct_strict_falcon512_none

- operation: `sign_ct_strict`
- logn: `9`
- batch: `8`
- fixed class: `fixed_key_message_rng`
- varied class: `varied_key_message_rng`
- mean fixed per call: `4249166.4 ns`
- mean varied per call: `4251361.5 ns`
- median fixed batch: `31201978` ns
- median varied batch: `31167108` ns
- p95 fixed batch: `48265402` ns
- p95 varied batch: `48179224` ns
- Welch t: `-0.142`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## sign_ct_strict_falcon1024_none

- operation: `sign_ct_strict`
- logn: `10`
- batch: `8`
- fixed class: `fixed_key_message_rng`
- varied class: `varied_key_message_rng`
- mean fixed per call: `9234895.2 ns`
- mean varied per call: `9533299.9 ns`
- median fixed batch: `67045475` ns
- median varied batch: `69646188` ns
- p95 fixed batch: `112006366` ns
- p95 varied batch: `115762382` ns
- Welch t: `-9.751`
- interpretation: class separation crossed the dudect notice threshold; rerun on a controlled host and investigate

