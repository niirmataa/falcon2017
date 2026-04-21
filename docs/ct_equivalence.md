# Strict CT Semantic Equivalence

This document defines what must be shown before the repository can claim that
the `ct_strict` backend is not a new scheme, but a semantically equivalent
implementation of Falcon 2017 / Round1 Extra.

## Core claim

The intended claim is:

> `ct_strict` preserves the semantics of Falcon 2017 / Round1 Extra while
> changing only the implementation strategy used to achieve stronger
> side-channel resistance.

This claim is stronger than “the backend works” and weaker than “the backend is
mathematically reproven here”.

## Semantic invariants

The following must remain identical to the `ref` backend:

### 1. Public parameters

- same modulus
- same ring
- same degrees
- same sampler constants
- same norm bounds

### 2. Key semantics

- same secret key meaning: `f, g, F, G`
- same public key derivation
- same acceptance/rejection behavior in key generation

### 3. Signature semantics

- same nonce role
- same signature body interpretation
- same compression modes
- same verification acceptance condition

### 4. Wire formats

- same secret key encoding
- same public key encoding
- same detached signature encoding

### 5. Distributional behavior

- same mathematical signer distribution
- same rejection logic
- same verifier-visible outputs

## Required tests

The equivalence claim requires at minimum:

### 1. Cross-backend verification

For randomized campaigns:

- `verify_ref(sign_ref(...)) == OK`
- `verify_ref(sign_ct_strict(...)) == OK`
- `verify_ct(sign_ref(...)) == OK` if a CT verifier exists later

### 2. Differential decoding

Artifacts emitted by `ct_strict` must be decodable by the `ref` path without
special casing or format translation.

### 3. Statistical sampler comparison

If the strict sampler is not byte-identical to the reference sampler, the
repository must show that the produced distribution still matches the intended
historical distribution within the agreed statistical bounds.

### 4. Norm-bound identity

Accepted signatures from `ct_strict` must satisfy the same norm bound as the
reference path, with no relaxed threshold and no hidden redefinition.

## Current status

The repository already has:

- working `ref` and `ct_strict` paths
- cross-path tests
- engineering evidence that the strict path can be executed without `ref_f64`

The repository still needs a stronger semantic-equivalence dossier:

- explicit artifact reports
- larger statistical comparison for the sampler
- final Ubuntu-host timing and fuzz evidence

## Stop condition

The `ct_strict` equivalence claim is accepted only when:

1. all semantic invariants above are documented and tested
2. emitted artifacts interoperate with `ref`
3. sampler equivalence is justified
4. norm bounds are unchanged
5. no parameter or format drift exists

At that point the repository may state:

> The `ct_strict` backend is a semantically equivalent implementation of Falcon
> 2017 / Round1 Extra, not a new signature scheme.
