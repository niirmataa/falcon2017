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
- `KeygenWorkspace<const LOGN: u32>`
- `SignRefWorkspace<const LOGN: u32>`
- `VerifyWorkspace<const LOGN: u32>`
- `Compression::{None, Static}`
- `Error::{InvalidEncoding, InvalidSignature, InvalidParameter, Randomness, Internal}`
- `Result<T>`

Publiczne metody obecne na tym etapie:

- `Falcon512::keygen()`
- `Falcon1024::keygen()`
- `Falcon512::keygen_in()` i `Falcon1024::keygen_in()`
- `Falcon512::keygen_from_seed()` i `Falcon1024::keygen_from_seed()` za feature `deterministic-tests`
- `Falcon512::keygen_from_seed_in()` i `Falcon1024::keygen_from_seed_in()` za feature `deterministic-tests`
- `SecretKey::{to_bytes, from_bytes, derive_public, sign_ref, sign_ref_in, sign_ref_with_external_nonce, sign_ref_with_external_nonce_in, expand_ct_strict}`
- `ExpandedSecretKeyCt::{sign_ct_strict, sign_ct_strict_with_external_nonce}`
- `PublicKey::{to_bytes, from_bytes, prepare, verify_detached, verify_detached_in}`
- `PreparedPublicKey::{verify_detached, verify_detached_in, verifier}`
- `Verifier::{update, finalize}`
- `Nonce::{as_bytes, from_bytes}`
- `DetachedSignature::{nonce, body_bytes}`

Model weryfikacji:

- `PublicKey::verify_detached()` istnieje dla jednorazowego sprawdzenia podpisu.
- Docelową ścieżką dla wielokrotnej weryfikacji jest `PublicKey::prepare()` -> `PreparedPublicKey`, a następnie `PreparedPublicKey::verify_detached()` albo `PreparedPublicKey::verifier(&Nonce)`.
- `Verifier` nie ma publicznych konstruktorów; jest tworzony wyłącznie przez `PreparedPublicKey::verifier()`.
- Przed bramką `C1` nie dodajemy żadnych skrótów ani metod wygodowych ponad literalny zakres z sekcji 3 `GENERAL.md`.

Model workspace:

- One-shot API nadal samo alokuje scratch.
- Zaawansowane ścieżki `*_in(...)` przyjmują `&mut Workspace<LOGN>` i pozwalają reużywać bufory między wywołaniami.
- Workspace są częścią publicznego API dopiero od Kroku 21 i nie zmieniają wire formatu ani semantyki podpisu.

Ważne ograniczenia publicznego surface:

- publicznie tylko binary Falcon: `logn = 9` i `logn = 10`
- brak publicznych modułów implementacyjnych typu `encoding`, `rng`, `math`, `sampler` czy `params`
- `hazmat` nie jest jeszcze wystawiony; wróci później jako osobny feature
- nonce jest osobnym typem publicznym
- wire format ma pozostać zgodny z Falcon 2017 / Extra

Wymuszone już teraz zasady dla typów sekretów:

- `SecretKey` i `ExpandedSecretKeyCt` nie mają `Debug`
- `SecretKey` i `ExpandedSecretKeyCt` nie mają `Clone`
- pola wewnętrzne sekretów są niepubliczne
- secret-bearing storage jest czyszczone przez `Drop + zeroize`

Metody już działające po Kroku 17:

- `Falcon512::keygen()` i `Falcon1024::keygen()`
- `Falcon512::keygen_from_seed()` i `Falcon1024::keygen_from_seed()` za feature `deterministic-tests`
- `SecretKey::{to_bytes, from_bytes, derive_public}`
- `SecretKey::{sign_ref, sign_ref_with_external_nonce}`
- `PublicKey::{to_bytes, from_bytes, verify_detached}`

Metody działające po Kroku 18:

- `PublicKey::prepare()`
- `PreparedPublicKey::{verify_detached, verifier}`
- `Verifier::{update, finalize}`

Metody działające po Kroku 21:

- `Falcon512::keygen_in()` i `Falcon1024::keygen_in()`
- `Falcon512::keygen_from_seed_in()` i `Falcon1024::keygen_from_seed_in()` za feature `deterministic-tests`
- `SecretKey::{sign_ref_in, sign_ref_with_external_nonce_in}`
- `PublicKey::verify_detached_in()`
- `PreparedPublicKey::verify_detached_in()`
- `KeygenWorkspace`, `SignRefWorkspace`, `VerifyWorkspace`

Placeholderami pozostają jeszcze m.in.:

- `ExpandedSecretKeyCt::*`
