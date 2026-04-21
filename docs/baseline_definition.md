# Baseline Definition: Falcon 2017 / Round1 Extra

This document defines the normative baseline for the `ref` backend in this
repository. Its purpose is to pin down the exact scheme semantics that the Rust
port is expected to preserve.

## Baseline source

- Upstream package: `falcon-round1.zip`
- Frozen local reference: `references/falcon-2017-extra/`
- Historical source family: Falcon 2017 / Round1 `Extra/c`
- Implementation line: pre-NIST Falcon, not the later standardized variant

The Rust `ref` backend is judged against the frozen C sources in
`references/falcon-2017-extra/`, not against later Falcon revisions.

## Public parameter set

- Ring modulus: `q = 12289`
- Ring: `Z_q[x] / (x^n + 1)`
- Supported degrees in v1:
  - `n = 512` (`logn = 9`)
  - `n = 1024` (`logn = 10`)
- Public v1 scope: binary Falcon only
- Explicitly out of scope:
  - ternary Falcon
  - NIST/FIPS Falcon
  - Hawk
  - SIMD-specialized paths

## Key material semantics

Private keys are represented by the four polynomials:

- `f`
- `g`
- `F`
- `G`

with the NTRU relation:

`fG - gF = q (mod x^n + 1)`

The secret key format does not store the public key polynomial `h`.

The Rust representation must preserve:

- coefficient values
- coefficient ordering
- binary-vs-ternary tag semantics
- compression tag semantics
- degree encoding via `logn`

## Secret key wire format

The secret key header is defined as:

`(ter << 7) | (comp << 5) | logn`

For the current public scope:

- `ter = 0` for binary Falcon
- `comp` is the compression mode tag used by the historical baseline
- `logn` is `9` or `10`

The body encodes exactly the four vectors `f`, `g`, `F`, `G`.

## Public key wire format

The public key represents the polynomial `h = g / f mod q` encoded in the
historical Round1 Extra format. Rust `PublicKey::to_bytes()` and
`PublicKey::from_bytes()` are required to preserve that encoding exactly.

## Signature wire format

A detached signature consists of:

- a nonce
- a compressed signature body

The nonce is an explicit protocol object and remains part of the wire format.
The body uses the historical compressed encoding rules from Round1 Extra.

For the current public API:

- `Compression::None`
- `Compression::Static`

are the only supported compression modes.

## Hash-to-point semantics

`hash_to_point` is defined exactly by the historical SHAKE-based procedure from
the frozen Extra reference:

- absorb `nonce || message`
- derive coefficients in the Falcon ring
- reject out-of-range values exactly as in the C baseline

Any Rust optimization or refactor is required to preserve:

- coefficient distribution
- rejection rules
- output ordering
- degree-specific behavior

## Sampler semantics

The signing sampler is defined by the Falcon 2017 / Extra Gaussian sampling
procedure driven by SHAKE-derived randomness. The Rust `ref` backend must match
the historical baseline in:

- PRNG consumption order
- buffering behavior
- rejection behavior
- output distribution
- number of draws for equivalent execution paths

The `ct_strict` backend is allowed to replace the implementation strategy, but
not the mathematical distribution or acceptance criteria.

## Verification semantics

The verification baseline is defined by the historical Extra code path:

- same `hash_to_point`
- same signature decoding
- same norm check
- same distinction between malformed encoding and invalid signature

Rust verification is considered correct only if it preserves those exact
accept/reject conditions.

## Interpretation rule

When a Rust implementation detail and a historical C behavior disagree, the
frozen Extra C reference wins for the `ref` backend.

This document defines the semantic target for:

- differential testing
- regression testing
- strict-CT equivalence arguments
- future research claims made about this repository
