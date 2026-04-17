# Baseline

`falcon2017` implements the historical Falcon 2017 / Extra code line.

The immutable reference baseline for this repository is stored in `references/falcon-2017-extra/`.
That directory mirrors the C sources taken from `falcon_final/Extra/c/` in the original round-1 package.

For v1, the repository is intentionally scoped to the Falcon 2017 / Extra semantics and wire format.
The reference sources define the behavior for:

- key generation
- signature generation
- verification
- encoding and decoding
- SHAKE and PRNG behavior

The baseline is preserved in-repo so that every Rust porting step can be checked against a fixed source of truth.
