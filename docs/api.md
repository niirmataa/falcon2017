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
- `ExpandCtWorkspace<const LOGN: u32>`
- `KeygenWorkspace<const LOGN: u32>`
- `SignRefWorkspace<const LOGN: u32>`
- `SignCtWorkspace<const LOGN: u32>`
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
- `SecretKey::{to_bytes, from_bytes, derive_public, sign_ref, sign_ref_in, sign_ref_with_external_nonce, sign_ref_with_external_nonce_in, expand_ct_strict, expand_ct_strict_in}`
- `ExpandedSecretKeyCt::{sign_ct_strict, sign_ct_strict_with_external_nonce, sign_ct_strict_in, sign_ct_strict_with_external_nonce_in}`
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
- Od Kroku 28 strict-CT path ma własne `ExpandCtWorkspace` i `SignCtWorkspace`, mimo że bridge
  signer nadal używa referencyjnego układu scratcha pod spodem.

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
- runtime state dla podpisu i keygen (`ShakeContext`, `Prng`, lokalne seedy, workspace secret scratch) też jest czyszczony przy `zeroize`

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

Stan po Kroku 22:

- `SecretKey` i `ExpandedSecretKeyCt` pozostają bez `Debug` i bez `Clone`
- secret-bearing storage nie ma publicznych pól
- `Drop + zeroize` obejmuje secret key storage, expanded key storage, reference workspaces oraz runtime state używany przez signer/keygen

Stan po Kroku 24:

- `SecretKey::expand_ct_strict()` zwraca `ExpandedSecretKeyCt<LOGN>` dla publicznych parametrów
- `ExpandedSecretKeyCtInner` przechowuje `b00`, `b01`, `b10`, `b11` i `tree` jako niepubliczne
  bufory `FprSoft`
- expanded-key storage jest objęty `Drop + zeroize`

Stan po Kroku 27:

- `ExpandedSecretKeyCt::{sign_ct_strict, sign_ct_strict_with_external_nonce}` zwracają podpisy dla
  publicznych parametrów `Falcon512` i `Falcon1024`
- ścieżka podpisu ładuje expanded key z Kroku 24 do przejściowego scratcha `ref_f64`, żeby
  zamrozić wire-semantykę Falcon/Extra przed finalnym integer-only executorem
- publiczny CT signer na tym etapie pozostaje one-shot; nie ma jeszcze osobnego workspace API

Stan po Kroku 28:

- `ExpandCtWorkspace<LOGN>` i `SignCtWorkspace<LOGN>` są częścią publicznego API
- `SecretKey::expand_ct_strict_in()` pozwala reużywać scratch przy generowaniu expanded key
- `ExpandedSecretKeyCt::{sign_ct_strict_in, sign_ct_strict_with_external_nonce_in}` pozwalają
  reużywać scratch między wywołaniami bez zmiany semantyki podpisu
- one-shot strict-CT signer pozostaje cienką nakładką na ścieżkę workspace-backed

Otwarte pozostają jeszcze m.in.:

- finalny integer-only executor dla `ExpandedSecretKeyCt::*`
