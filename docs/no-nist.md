# No NIST

This repository does not target the later NIST / FIPS Falcon line.

The source of truth is Falcon 2017 / Extra, not the later submission variants and not the final standardization track.
Implementation choices, tests, and wire-format compatibility must therefore follow the `references/falcon-2017-extra/` baseline.

For v1, the public API supports only binary Falcon parameter sets:

- Falcon512
- Falcon1024

The repository does not expose ternary Falcon in the public API for v1.
Any future work must preserve this scope unless the project rules are explicitly changed.
