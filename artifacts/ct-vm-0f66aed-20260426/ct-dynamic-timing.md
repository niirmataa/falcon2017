# CT Dynamic Timing Summary

- generated_at_unix_s: `1777189883`
- host: `linux/x86_64`
- hostname: `unknown`
- samples per class: `256`
- dudect-like thresholds: notice `|t| >= 4.5`, strong `|t| >= 10.0`

This is a dudect-like timing checkpoint, not an audit-closed constant-time proof.
The fixed class repeats one deterministic input family; the varied class walks a deterministic seed family of equal public size.

## expand_ct_strict_falcon512

- operation: `expand_ct_strict`
- logn: `9`
- batch: `2`
- fixed class: `fixed_secret_key`
- varied class: `varied_secret_keys`
- mean fixed per call: `6821344.4 ns`
- mean varied per call: `6640026.0 ns`
- median fixed batch: `13085029` ns
- median varied batch: `13059531` ns
- p95 fixed batch: `14338725` ns
- p95 varied batch: `14143057` ns
- Welch t: `1.266`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## expand_ct_strict_falcon1024

- operation: `expand_ct_strict`
- logn: `10`
- batch: `2`
- fixed class: `fixed_secret_key`
- varied class: `varied_secret_keys`
- mean fixed per call: `14743450.3 ns`
- mean varied per call: `14803357.2 ns`
- median fixed batch: `29235944` ns
- median varied batch: `29289575` ns
- p95 fixed batch: `31023376` ns
- p95 varied batch: `31248503` ns
- Welch t: `-0.885`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## sign_ct_strict_falcon512_none

- operation: `sign_ct_strict`
- logn: `9`
- batch: `1`
- fixed class: `fixed_key_message_rng`
- varied class: `varied_key_message_rng`
- mean fixed per call: `154616857.2 ns`
- mean varied per call: `153476445.2 ns`
- median fixed batch: `153170259` ns
- median varied batch: `152529560` ns
- p95 fixed batch: `160527379` ns
- p95 varied batch: `158147510` ns
- Welch t: `1.872`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## sign_ct_strict_falcon1024_none

- operation: `sign_ct_strict`
- logn: `10`
- batch: `1`
- fixed class: `fixed_key_message_rng`
- varied class: `varied_key_message_rng`
- mean fixed per call: `321804950.1 ns`
- mean varied per call: `320245845.1 ns`
- median fixed batch: `308427037` ns
- median varied batch: `308486008` ns
- p95 fixed batch: `389817968` ns
- p95 varied batch: `379993561` ns
- Welch t: `0.412`
- interpretation: no class separation observed at the current dudect notice threshold on this host

