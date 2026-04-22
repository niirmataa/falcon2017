# Reference Equivalence Plan

This document defines what must be demonstrated before the repository can make
the claim:

> The Rust `ref` backend is semantically equivalent to Falcon 2017 / Round1
> Extra.

Equivalence here means preservation of algorithmic behavior relative to the
frozen C baseline in `references/falcon-2017-extra/`.

## Claim boundary

The claim is limited to:

- binary Falcon
- `logn = 9` and `logn = 10`
- the historical Round1 Extra parameter set
- the current Rust `ref` backend

It does not cover:

- ternary Falcon
- later Falcon revisions
- NIST/FIPS Falcon
- the `ct_strict` backend by itself

## Required evidence

### 1. Key generation differential campaign

For at least `10_000` deterministic seeds:

- run Rust `keygen_from_seed(seed)`
- run C Extra `keygen_from_seed(seed)`

Compare:

- `f`
- `g`
- `F`
- `G`
- `h`
- encoded secret key
- encoded public key

Any mismatch is a failure of equivalence.

Current repository status:

- a reproducible `10_000`-seed keygen differential artifact campaign exists
- the GNU/Linux host reproduces that campaign cleanly with zero mismatches

### 2. Signing differential campaign

For at least `1_000` deterministic key/signing seed pairs:

- generate the same key in Rust and C
- sign the same message in Rust and C
- compare nonce and signature body byte-for-byte

If a mismatch appears, the first debugging target is PRNG buffering and random
draw order.

Current repository status:

- a reproducible `1_000`-case signing differential artifact campaign exists
- the GNU/Linux host reproduces that campaign cleanly with zero nonce/signature mismatches and zero cross-verification failures

### 3. NTRU solver equivalence

The Rust NTRU path must match the historical reference on:

- small NTRU vectors from `test_falcon.c`
- degree-512 vectors
- acceptance/rejection outcomes

The solver is considered equivalent only if both coefficient outputs and
success/failure behavior align with the baseline.

### 4. Codec equivalence

Roundtrip and malformed-input requirements:

- `sk -> bytes -> sk`
- `pk -> bytes -> pk`
- `sig -> bytes -> sig`

Additionally:

- randomized 1-bit mutations must be rejected
- malformed encodings must map to `InvalidEncoding`
- valid-but-wrong signatures must map to `InvalidSignature`

### 5. Verification equivalence

For all differential signing artifacts:

- `verify_ref_rust(sig, pk, msg)` must match C Extra
- acceptance and rejection outcomes must match
- encoding-vs-signature error split must match repository policy

### 6. Sampler equivalence

The sampler must be validated both operationally and statistically:

- exact draw-order equivalence where deterministic comparison is possible
- statistical agreement where only distribution-level validation is practical

This evidence is not complete until the statistical report exists.

## Reproducible Artifact Set

The current in-repo artifact generator is:

```bash
cargo run --features deterministic-tests --bin r1_artifacts -- all --out-dir artifacts --keygen-cases 10000 --sign-cases 1000
```

The matching validation command is:

```bash
cargo run --features deterministic-tests --bin r1_artifacts -- check-all --out-dir artifacts --keygen-cases 10000 --sign-cases 1000
```

The current deterministic artifact set is:

- `artifacts/ref-differential-keygen.json`
- `artifacts/ref-differential-sign.json`
- `artifacts/ref-differential-summary.md`

The pinned deterministic campaigns use:

- keygen seeds: `step-r1-keygen-512`, `step-r1-keygen-1024`
- signing key seeds: `step-r1-sign-key-512`, `step-r1-sign-key-1024`
- signing RNG seeds: `step-r1-sign-seed-512`, `step-r1-sign-seed-1024`
- signing messages: `step-r1-sign-msg-512`, `step-r1-sign-msg-1024`
- alternating `Compression::{None, Static}` per case
- current keygen scale: `10_000` cases per public `logn`
- current signing scale: `1_000` cases per public `logn`

`ref-differential-keygen.json` records, per case:

- the deterministic seed
- expected encoded public-key and secret-key lengths plus SHA-256 digests from the frozen C baseline
- pass/fail booleans for Rust keygen, `derive_public()`, and decode/re-encode checks
- Rust-side raw values only if a mismatch occurs

`ref-differential-sign.json` records, per case:

- key seed, signing seed, message, and compression mode
- expected nonce and signature body from the frozen C baseline
- pass/fail booleans for key agreement, nonce/signature agreement, and cross-verification in both implementations
- Rust-side raw values only if a mismatch occurs

`ref-differential-summary.md` is the deterministic pass/fail digest for the current artifact set.

This artifact set is the repository's current reproducible `R1` checkpoint for deterministic keygen/signing differential evidence.

Known remaining gap outside this deterministic `R1` checkpoint:

- sampler statistical evidence is still tracked separately in the broader reference-equivalence dossier

## Required artifacts

Before making the equivalence claim, the repository should contain:

- deterministic campaign harnesses
- machine-readable mismatch logs
- seed inventories
- a summary report with pass/fail criteria

Current supporting artifacts:

- `artifacts/ref-differential-keygen.json`
- `artifacts/ref-differential-sign.json`
- `artifacts/ref-differential-summary.md`
- `artifacts/ref-sampler-report.md`

## Stop condition

The `ref` equivalence claim is accepted only when all of the following hold:

1. `10_000` keygen seeds pass byte-for-byte against C Extra.
2. signing differential tests pass on the agreed deterministic campaign.
3. NTRU vectors match 1:1.
4. codec roundtrips and malformed-input tests pass.
5. verification behavior matches the baseline.
6. sampler validation is documented and accepted.

Until then, the repository may say:

> The `ref` backend is strongly tested against the historical baseline.

It may not yet say:

> The `ref` backend is fully proven equivalent.
