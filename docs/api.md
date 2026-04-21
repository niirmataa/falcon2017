# API

The public crate API is intentionally narrow and aligned with the repository's current scope rules.

Publicly exported types:

- `Falcon512`, `Falcon1024`
- `Falcon512Keypair`, `Falcon1024Keypair`
- `Keypair<const LOGN: u32>`
- `PublicKey<const LOGN: u32>`
- `PreparedPublicKey<const LOGN: u32>`
- `SecretKey<const LOGN: u32>`
- `ExpandedSecretKeyCt<const LOGN: u32>`
- `DetachedSignature<const LOGN: u32>`
- `Nonce`
- `Verifier<const LOGN: u32>`
- `ExpandCtWorkspace<const LOGN: u32>`
- `KeygenWorkspace<const LOGN: u32>`
- `SignRefWorkspace<const LOGN: u32>`
- `SignCtWorkspace<const LOGN: u32>`
- `VerifyWorkspace<const LOGN: u32>`
- `Compression::{None, Static}`
- `Error::{InvalidEncoding, InvalidSignature, InvalidParameter, Randomness, Internal}`
- `Result<T>`

Public methods available at this stage:

- `Falcon512::keygen()`
- `Falcon1024::keygen()`
- `Falcon512::keygen_in()` and `Falcon1024::keygen_in()`
- `Falcon512::keygen_from_seed()` and `Falcon1024::keygen_from_seed()` behind the `deterministic-tests` feature
- `Falcon512::keygen_from_seed_in()` and `Falcon1024::keygen_from_seed_in()` behind the `deterministic-tests` feature
- `SecretKey::{to_bytes, from_bytes, derive_public, sign_ref, sign_ref_in, sign_ref_with_external_nonce, sign_ref_with_external_nonce_in, expand_ct_strict, expand_ct_strict_in}`
- `ExpandedSecretKeyCt::{sign_ct_strict, sign_ct_strict_with_external_nonce, sign_ct_strict_in, sign_ct_strict_with_external_nonce_in}`
- `PublicKey::{to_bytes, from_bytes, prepare, verify_detached, verify_detached_in}`
- `PreparedPublicKey::{verify_detached, verify_detached_in, verifier}`
- `Verifier::{update, finalize}`
- `Nonce::{as_bytes, from_bytes}`
- `DetachedSignature::{nonce, body_bytes}`

Verification model:

- `PublicKey::verify_detached()` exists for one-shot signature verification.
- The intended path for repeated verification is `PublicKey::prepare()` -> `PreparedPublicKey`, followed by `PreparedPublicKey::verify_detached()` or `PreparedPublicKey::verifier(&Nonce)`.
- `Verifier` has no public constructors; it is created only through `PreparedPublicKey::verifier()`.

Workspace model:

- The one-shot API still allocates its own scratch space.
- Advanced `*_in(...)` paths take `&mut Workspace<LOGN>` and allow scratch reuse across calls.
- Workspaces do not change wire format or signature semantics.
- From Step 28 onward, the strict path has its own `ExpandCtWorkspace` and `SignCtWorkspace`.

Current caveats:

- `Nonce` remains a separate public type and currently accepts arbitrary byte lengths. This preserves historical interop and deterministic test coverage, but it is broader than the eventual safe/hazmat split the repository intends to adopt.
- `*_in(...)` reduces scratch reallocation, but returned keys and signatures are still heap-backed values.
- `ct_strict` is a runtime integer-only signing path, not yet a completed defensive constant-time claim. The claim boundary is defined in `SECURITY.md` and `docs/ct_threat_model.md`.
- `hazmat` is not exposed yet; it is planned as a future feature gate rather than part of the current public API.

Important public-surface constraints:

- only binary Falcon is public: `logn = 9` and `logn = 10`
- there are no public implementation modules such as `encoding`, `rng`, `math`, `sampler`, or `params`
- the wire format must remain compatible with Falcon 2017 / Extra

Rules already enforced for secret-bearing types:

- `SecretKey` and `ExpandedSecretKeyCt` do not implement `Debug`
- `SecretKey` and `ExpandedSecretKeyCt` do not implement `Clone`
- internal secret fields are not public
- secret-bearing storage is cleared through `Drop + zeroize`
- runtime state used by signing and keygen (`ShakeContext`, `Prng`, local seeds, workspace secret scratch) is also cleared with `zeroize`

State after the current strict-path milestones:

- `ExpandedSecretKeyCt::{sign_ct_strict, sign_ct_strict_with_external_nonce}` return signatures for the public `Falcon512` and `Falcon1024` parameter sets
- the signing path performs runtime strict-path signing without an intermediate bridge to the `ref_f64` backend
- the expanded key is used directly by the soft-FFT / soft-FPR executor while preserving Falcon/Extra wire semantics
- `ExpandCtWorkspace<LOGN>` and `SignCtWorkspace<LOGN>` are part of the public API
- the one-shot strict signer remains a thin wrapper over the workspace-backed path

Still open, among other things:

- a stricter safe/hazmat split for nonce and seeded execution
- output-buffer variants such as `*_to_slice(...)` / `*_into_buf(...)`
- further side-channel audits and final closure of gate `C1`
