# CT Dynamic Timing Summary

- generated_at_unix_s: `1777188597`
- host: `linux/x86_64`
- hostname: `unknown`
- samples per class: `512`
- dudect-like thresholds: notice `|t| >= 4.5`, strong `|t| >= 10.0`

This is a dudect-like timing checkpoint, not an audit-closed constant-time proof.
The fixed class repeats one deterministic input family; the varied class walks a deterministic seed family of equal public size.

## expand_ct_strict_falcon512

- operation: `expand_ct_strict`
- logn: `9`
- batch: `4`
- fixed class: `fixed_secret_key`
- varied class: `varied_secret_keys`
- mean fixed per call: `4424300.3 ns`
- mean varied per call: `4424557.4 ns`
- median fixed batch: `17478482` ns
- median varied batch: `17511605` ns
- p95 fixed batch: `18856084` ns
- p95 varied batch: `19018720` ns
- Welch t: `-0.020`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## expand_ct_strict_falcon1024

- operation: `expand_ct_strict`
- logn: `10`
- batch: `4`
- fixed class: `fixed_secret_key`
- varied class: `varied_secret_keys`
- mean fixed per call: `10575659.4 ns`
- mean varied per call: `10536304.6 ns`
- median fixed batch: `41062648` ns
- median varied batch: `41051688` ns
- p95 fixed batch: `48687683` ns
- p95 varied batch: `47864132` ns
- Welch t: `0.469`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## sign_ct_strict_falcon512_none

- operation: `sign_ct_strict`
- logn: `9`
- batch: `2`
- fixed class: `fixed_key_message_rng`
- varied class: `varied_key_message_rng`
- mean fixed per call: `104407769.1 ns`
- mean varied per call: `104525324.7 ns`
- median fixed batch: `185826302` ns
- median varied batch: `189379357` ns
- p95 fixed batch: `335450787` ns
- p95 varied batch: `341481762` ns
- Welch t: `-0.057`
- interpretation: no class separation observed at the current dudect notice threshold on this host

## sign_ct_strict_falcon1024_none

- operation: `sign_ct_strict`
- logn: `10`
- batch: `2`
- fixed class: `fixed_key_message_rng`
- varied class: `varied_key_message_rng`
- mean fixed per call: `168305284.8 ns`
- mean varied per call: `167580690.8 ns`
- median fixed batch: `330651965` ns
- median varied batch: `330100404` ns
- p95 fixed batch: `367267068` ns
- p95 varied batch: `364120727` ns
- Welch t: `1.126`
- interpretation: no class separation observed at the current dudect notice threshold on this host

