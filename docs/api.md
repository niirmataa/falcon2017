# API

Publiczne API crate jest celowo wąskie i zgodne z `GENERAL.md`.

Publicznie eksportowane typy:

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
- `Compression::{None, Static}`
- `Error::{InvalidEncoding, InvalidSignature, InvalidParameter, Randomness, Internal}`
- `Result<T>`

Publiczne metody obecne na tym etapie:

- `Falcon512::keygen()`
- `Falcon1024::keygen()`
- `Falcon512::keygen_from_seed()` i `Falcon1024::keygen_from_seed()` za feature `deterministic-tests`
- `SecretKey::{to_bytes, from_bytes, derive_public, sign_ref, sign_ref_with_external_nonce, expand_ct_strict}`
- `ExpandedSecretKeyCt::{sign_ct_strict, sign_ct_strict_with_external_nonce}`
- `PublicKey::{to_bytes, from_bytes, prepare, verify_detached}`
- `PreparedPublicKey::{verify_detached, verifier}`
- `Verifier::{update, finalize}`
- `Nonce::{as_bytes, from_bytes}`
- `DetachedSignature::{nonce, body_bytes}`

Ważne ograniczenia publicznego surface:

- publicznie tylko binary Falcon: `logn = 9` i `logn = 10`
- brak publicznych modułów implementacyjnych typu `encoding`, `rng`, `math`, `sampler` czy `params`
- `hazmat` nie jest częścią domyślnego API i pozostaje za feature `hazmat`
- nonce jest osobnym typem publicznym
- wire format ma pozostać zgodny z Falcon 2017 / Extra

Wymuszone już teraz zasady dla typów sekretów:

- `SecretKey` i `ExpandedSecretKeyCt` nie mają `Debug`
- `SecretKey` i `ExpandedSecretKeyCt` nie mają `Clone`
- pola wewnętrzne sekretów są niepubliczne
- secret-bearing storage jest czyszczone przez `Drop + zeroize`

Na tym etapie większość metod nadal ma charakter placeholderów i zwraca `Error::Internal`; pełna semantyka dochodzi w kolejnych krokach portu.
