# Reference Security Claim Boundary

This document defines the security claim that may be made about the Rust
reference backend, and the evidence required to support it.

## What is being claimed

The intended claim is narrow:

> The Rust `ref` backend preserves the semantics and parameter choices of Falcon
> 2017 / Round1 Extra closely enough that its security should be interpreted as
> the security of that historical scheme, not as a new Rust-specific variant.

This is not a proof of Falcon security from first principles.

## What must be shown

### 1. Parameter consistency

The Rust implementation must use the same:

- modulus `q = 12289`
- ring `Z_q[x] / (x^n + 1)`
- dimensions `n = 512, 1024`
- Gaussian/sampling constants
- rejection thresholds
- acceptance criteria

Any parameter drift invalidates the claim.

### 2. Scheme relation preservation

The implementation must preserve:

- `fG - gF = q mod (x^n + 1)`
- public key derivation semantics
- signature generation distribution
- verification norm checks
- acceptance and rejection boundaries

### 3. Distribution preservation

The implementation must not silently alter:

- PRNG source
- sampler draw order
- rejection sampling logic
- normalization/rounding behavior

This is the core reason the `ref` backend exists separately from `ct_strict`.

### 4. Implementation-safety hygiene

The repository should establish that the Rust implementation does not introduce
new accidental weaknesses through:

- arithmetic overflow changing semantics
- undefined behavior in FFI or unsafe code
- untracked randomness sources
- decoding ambiguities

Recommended tools:

- `cargo test`
- `cargo miri test`
- sanitizers on GNU/Linux
- property tests
- differential campaigns

## What is explicitly not claimed

This repository does not claim that:

- Falcon 2017 has been reproved mathematically here
- the `ref` backend is constant-time
- side-channel resistance follows from equivalence to C
- the scheme is aligned with later NIST/FIPS Falcon choices

Those are separate claims and require separate evidence.

## Current status

At the current stage, the repository can reasonably claim:

- strong historical compatibility testing
- preserved wire formats
- preserved core parameter choices
- preserved public API semantics for the scoped variant

It should not yet claim:

- completed reference-security dossier
- completed sampler statistical report
- completed Miri/sanitizer evidence on the target Ubuntu research host

## Stop condition

The `ref` security claim is accepted when:

1. `docs/baseline_definition.md` is complete and stable.
2. `docs/ref_equivalence.md` stop conditions are met.
3. parameter derivations are documented from the 2017 paper.
4. implementation-safety checks have been run and recorded.
5. no semantic drift remains between Rust `ref` and C Extra.

At that point the repository may state:

> The Rust `ref` backend is a faithful implementation of Falcon 2017 / Round1
> Extra, and its security claims are the historical claims of that scheme.
