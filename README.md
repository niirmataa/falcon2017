# falcon2017

`falcon2017` is a security-first Rust port of the historical Falcon 2017 / Extra code line.

The repository is intentionally narrow in scope:

- baseline: Falcon 2017 / Extra, not NIST / FIPS Falcon
- public parameter sets: binary `Falcon512` and `Falcon1024`
- wire format: compatible with the preserved C baseline in `references/falcon-2017-extra/`
- implementation path: first a faithful reference backend, then a strict constant-time signing backend

The project is being built as a single crate first. Hawk and any shared Falcon/Hawk core are explicitly deferred until Falcon itself reaches its reference and CT milestones.

## Status

Current checkpoint: `v0.1-step21`

Implemented today:

- reference key generation for `Falcon512` and `Falcon1024`
- reference detached signing with default 40-byte nonce and externally supplied nonce
- one-shot verification
- prepared public key verification
- streaming verifier
- encode/decode for public keys, secret keys, and signatures
- SHAKE, PRNG, `fpr`, FFT, NTT/modp, `zint`, and `solve_NTRU`
- advanced `*_in(...)` APIs with reusable workspaces for the reference path

Not implemented yet:

- strict constant-time expanded secret key
- strict constant-time signing path
- CT audit and CT-specific tests
- Hawk integration

## Design Constraints

This repository follows a few non-negotiable rules:

- it tracks the historical Falcon 2017 / Extra semantics, not the later standardized line
- public API stays binary-only for v1
- secret keys do not embed the public key
- nonce is explicit and public
- `SecretKey` and `ExpandedSecretKeyCt` do not implement `Debug` or plain `Clone`
- secret-bearing storage is zeroized on drop where applicable
- workspace-backed APIs exist for allocation control, but one-shot APIs remain available

## Project Flow

The implementation flow is deliberate:

1. Freeze the C baseline in-repo.
2. Port the reference implementation until `keygen -> sign_ref -> verify` is stable and testable.
3. Add allocation-aware reference workspaces and harden the public surface.
4. Close the reference gate (`R1`).
5. Add the strict constant-time backend on the same math and wire format.
6. Close the CT gate (`C1`).
7. Only then evaluate Falcon/Hawk shared abstractions.

This keeps the current crate understandable and auditable while avoiding premature generalization.

## Public API Shape

The public surface is intentionally small:

- `Falcon512`, `Falcon1024`
- `Keypair<LOGN>`, `PublicKey<LOGN>`, `PreparedPublicKey<LOGN>`
- `SecretKey<LOGN>`, `ExpandedSecretKeyCt<LOGN>`
- `DetachedSignature<LOGN>`, `Nonce`, `Verifier<LOGN>`
- `Compression`, `Error`, `Result`
- `KeygenWorkspace<LOGN>`, `SignRefWorkspace<LOGN>`, `VerifyWorkspace<LOGN>`

The intended usage split is:

- one-shot API for straightforward integration
- prepared / streaming verification for repeated verification on the same public key
- workspace-backed `*_in(...)` calls for callers that want to reuse scratch buffers

## Example

```rust
use falcon2017::{Compression, Falcon512};
use rand_core::{CryptoRng, RngCore};

fn roundtrip(rng: &mut (impl RngCore + CryptoRng)) -> falcon2017::Result<()> {
    let keypair = Falcon512::keygen(rng)?;
    let message = b"example message";

    let sig = keypair.secret.sign_ref(message, Compression::Static, rng)?;
    keypair.public.verify_detached(message, &sig)?;

    let prepared = keypair.public.prepare()?;
    prepared.verify_detached(message, &sig)?;

    Ok(())
}
```

Advanced flow with reusable workspaces:

```rust
use falcon2017::{
    Compression, Falcon512, KeygenWorkspace, SignRefWorkspace, VerifyWorkspace,
};
use rand_core::{CryptoRng, RngCore};

fn roundtrip_in(rng: &mut (impl RngCore + CryptoRng)) -> falcon2017::Result<()> {
    let mut keygen_ws = KeygenWorkspace::<9>::new();
    let mut sign_ws = SignRefWorkspace::<9>::new();
    let mut verify_ws = VerifyWorkspace::<9>::new();

    let keypair = Falcon512::keygen_in(rng, &mut keygen_ws)?;
    let message = b"example message";

    let sig = keypair
        .secret
        .sign_ref_in(message, Compression::Static, rng, &mut sign_ws)?;

    keypair
        .public
        .verify_detached_in(message, &sig, &mut verify_ws)?;

    Ok(())
}
```

## Build and Test

Default build:

```bash
cargo test
```

Deterministic test helpers:

```bash
cargo test --features deterministic-tests
```

The current default feature set includes:

- `std`
- `ref-f64`
- `zeroize`

CT-related features are present but not finished yet:

- `soft-fpr`
- `ct-strict`

## Repository Layout

```text
src/
  encoding/      wire format codecs
  falcon/        protocol-level operations and workspaces
  math/          fpr, FFT, modular arithmetic, NTT, zint
  rng/           SHAKE and PRNG
  sampler/       reference and future CT sampler code
references/
  falcon-2017-extra/   frozen C baseline
docs/
  baseline.md
  no-nist.md
  api.md
tests/
  KATs, roundtrips, malformed inputs, differential tests
```

## Baseline and Compatibility

All compatibility claims in this repository are relative to the preserved historical baseline under:

`references/falcon-2017-extra/`

This means:

- private key encoding follows the historical `f, g, F, G` layout
- public key and signature wire format match the preserved C implementation
- SHAKE / PRNG / `hash_to_point` behavior is checked against the same reference line

The repository does not claim compatibility with later NIST / FIPS Falcon variants.

## What This Repository Is Not

It is not:

- a generic Falcon framework
- a multi-crate workspace
- a no-std portability target
- an AVX2 / SIMD implementation
- a Hawk repository
- a standardization-track Falcon implementation

The goal is narrower: get a correct, auditable Falcon 2017 / Extra port into a stable reference state first, then add a strict CT signing backend without changing the external wire format.
