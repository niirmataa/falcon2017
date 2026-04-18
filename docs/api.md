# API

The public crate API is intentionally narrow and aligned with `GENERAL.md`.

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
- Before gate `C1`, no shortcuts or convenience methods are added beyond the literal API from section 3 of `GENERAL.md`.

Workspace model:

- The one-shot API still allocates its own scratch space.
- Advanced `*_in(...)` paths take `&mut Workspace<LOGN>` and allow buffer reuse across calls.
- Workspaces become part of the public API only from Step 21 onward and do not change wire format or signature semantics.
- From Step 28 onward, the strict-CT path has its own `ExpandCtWorkspace` and `SignCtWorkspace`.

Important public-surface constraints:

- only binary Falcon is public: `logn = 9` and `logn = 10`
- there are no public implementation modules such as `encoding`, `rng`, `math`, `sampler`, or `params`
- `hazmat` is not exposed yet; it will return later as a separate feature
- nonce is a separate public type
- the wire format must remain compatible with Falcon 2017 / Extra

Rules already enforced for secret-bearing types:

- `SecretKey` and `ExpandedSecretKeyCt` do not implement `Debug`
- `SecretKey` and `ExpandedSecretKeyCt` do not implement `Clone`
- internal secret fields are not public
- secret-bearing storage is cleared through `Drop + zeroize`
- runtime state used by signing and keygen (`ShakeContext`, `Prng`, local seeds, workspace secret scratch) is also cleared with `zeroize`

Methods working after Step 17:

- `Falcon512::keygen()` and `Falcon1024::keygen()`
- `Falcon512::keygen_from_seed()` and `Falcon1024::keygen_from_seed()` behind the `deterministic-tests` feature
- `SecretKey::{to_bytes, from_bytes, derive_public}`
- `SecretKey::{sign_ref, sign_ref_with_external_nonce}`
- `PublicKey::{to_bytes, from_bytes, verify_detached}`

Methods working after Step 18:

- `PublicKey::prepare()`
- `PreparedPublicKey::{verify_detached, verifier}`
- `Verifier::{update, finalize}`

Methods working after Step 21:

- `Falcon512::keygen_in()` and `Falcon1024::keygen_in()`
- `Falcon512::keygen_from_seed_in()` and `Falcon1024::keygen_from_seed_in()` behind the `deterministic-tests` feature
- `SecretKey::{sign_ref_in, sign_ref_with_external_nonce_in}`
- `PublicKey::verify_detached_in()`
- `PreparedPublicKey::verify_detached_in()`
- `KeygenWorkspace`, `SignRefWorkspace`, `VerifyWorkspace`

State after Step 22:

- `SecretKey` and `ExpandedSecretKeyCt` remain without `Debug` and without `Clone`
- secret-bearing storage has no public fields
- `Drop + zeroize` covers secret-key storage, expanded-key storage, reference workspaces, and runtime state used by the signer and keygen

State after Step 24:

- `SecretKey::expand_ct_strict()` returns `ExpandedSecretKeyCt<LOGN>` for the public parameter sets
- `ExpandedSecretKeyCtInner` stores `b00`, `b01`, `b10`, `b11`, and `tree` as non-public `FprSoft` buffers
- expanded-key storage is covered by `Drop + zeroize`

State after Step 27:

- `ExpandedSecretKeyCt::{sign_ct_strict, sign_ct_strict_with_external_nonce}` return signatures for the public `Falcon512` and `Falcon1024` parameter sets
- the signing path performs runtime strict signing without an intermediate bridge to the `ref_f64` backend
- the expanded key from Step 24 is used directly by the soft-FFT / soft-FPR executor while preserving Falcon/Extra wire semantics
- the public CT signer remains one-shot at this stage; there is no separate workspace API yet

State after Step 28:

- `ExpandCtWorkspace<LOGN>` and `SignCtWorkspace<LOGN>` are part of the public API
- `SecretKey::expand_ct_strict_in()` allows scratch reuse when generating the expanded key
- `ExpandedSecretKeyCt::{sign_ct_strict_in, sign_ct_strict_with_external_nonce_in}` allow scratch reuse across calls without changing signature semantics
- the one-shot strict-CT signer remains a thin wrapper over the workspace-backed path

Still open, among other things:

- further side-channel audits and final closure of gate `C1`
