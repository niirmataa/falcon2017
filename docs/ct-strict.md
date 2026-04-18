# CT Strict

This document will track the strict constant-time rules and audit notes for the `ct_strict` backend.

## Strict CT

Faza C używa osobnego backendu `math/fpr/soft.rs`, który emuluje binary64 na integerach.

Założenia Kroku 23:
- brak `f64` w kodzie produkcyjnym modułu,
- brak `libm`,
- stałe binary64 trzymane jako surowe wzorce bitowe,
- `of`, `scaled`, `add`, `sub`, `mul`, `div`, `sqrt`, `rint`, `floor` i `exp_small`
  działają przez własny decode/round/pack.

Weryfikacja Kroku 23:
- testy jednostkowe porównują operacje bitowo z natywnym binary64 na stałych wektorach,
- `exp_small` jest porównane z backendem `ref_f64`,
- pełne `cargo test` i `cargo test --features deterministic-tests` przechodzą w WSL Alpine.

## Krok 24

Stan po Kroku 24:
- `ExpandedSecretKeyCtInner` przechowuje `b00`, `b01`, `b10`, `b11` i `tree` jako `FprSoft`,
- `SecretKey::expand_ct_strict()` działa dla publicznych parametrów `Falcon512` i `Falcon1024`,
- expanded-key storage jest secret-bearing i jest czyszczony przez `Drop + zeroize`,
- semantyka Falcon/Extra dla expandowania klucza jest na tym etapie zamrożona przez bitowo zgodne
  skopiowanie prepared-key z backendu `ref` do reprezentacji `FprSoft`.

Aktualny zakres Kroku 24:
- to jest krok reprezentacyjny i API, nie końcowy audyt `C1`,
- `sign_ct_strict` nadal pozostaje placeholderem,
- pełne usunięcie zależności od referencyjnego expandowania pozostaje otwartą pracą przed
  domknięciem strict sign path i audytu z Kroku 29.

Weryfikacja Kroku 24:
- test jednostkowy w `src/falcon/expand_ct.rs` porównuje expanded key bitowo z referencyjnym
  `prepare_signing_key_into`,
- smoke-test w `tests/ct_consistency.rs` sprawdza publiczne `expand_ct_strict()` dla 512 i 1024
  oraz odrzucenie niepublicznego `logn`,
- `cargo test --features std,ref-f64,ct-strict,soft-fpr` przechodzi na zielono.

## Krok 25

Stan po Kroku 25:
- `src/sampler/sign_ct_strict.rs` implementuje wariant `SAMPLER_CDF=1` i `CT_BEREXP=1`,
- `gaussian0_sampler_ct()` zawsze zużywa dwa bloki `u64` z PRNG,
- `ber_exp_ct()` używa stałego budżetu odczytów PRNG dla pojedynczej próby odrzucenia.

Weryfikacja Kroku 25:
- testy jednostkowe w `src/sampler/sign_ct_strict.rs` sprawdzają stały budżet PRNG dla
  `gaussian0_sampler_ct()` i `ber_exp_ct()`,
- test regresyjny stabilizuje krótką sekwencję `sample_binary_ct()` na stałym seedzie,
- `cargo test --lib sampler::sign_ct_strict -- --nocapture` przechodzi na zielono.

## Krok 27

Stan po Kroku 27:
- `ExpandedSecretKeyCt::{sign_ct_strict, sign_ct_strict_with_external_nonce}` działają dla
  publicznych parametrów `Falcon512` i `Falcon1024`,
- signer ładuje expanded key z Kroku 24 do przejściowego scratcha `ref_f64` i wykonuje historyczny
  Falcon/Extra signing flow bez zmiany wire formatu,
- semantyka nonce i podpisu jest na tym etapie zamrożona przez zgodność z referencyjnym signerem i
  zachowanym baseline C.

Aktualny zakres Kroku 27:
- to nadal bridge przed `C1`, a nie finalny integer-only strict signer,
- runtime execution wciąż zależy tu od referencyjnego backendu `ref_f64`,
- osobny CT workspace API nie został jeszcze dodany.

Weryfikacja Kroku 27:
- testy jednostkowe w `src/falcon/sign_ct_strict.rs` porównują domyślny nonce i external nonce z
  zachowanymi wektorami C z Kroku 17,
- `tests/ct_consistency.rs` sprawdza roundtrip `verify(sign_ct_strict(...))` dla 512 i 1024 oraz
  parzystość `sign_ct_strict` z `sign_ref` na stałych seedach,
- `cargo test --features std,ref-f64,ct-strict,soft-fpr` oraz
  `cargo test --no-default-features --features ct-strict` przechodzą na zielono.

## Krok 28

Stan po Kroku 28:
- `ExpandCtWorkspace<LOGN>` i `SignCtWorkspace<LOGN>` są publicznymi workspace dla strict-CT
  bridge path,
- `SecretKey::expand_ct_strict_in()` reużywa scratch przy przygotowaniu expanded key,
- `ExpandedSecretKeyCt::{sign_ct_strict_in, sign_ct_strict_with_external_nonce_in}` reużywają
  scratch między wywołaniami bez dodatkowego API-hackingu po stronie użytkownika,
- one-shot strict-CT signer deleguje do ścieżki workspace-backed, więc semantyka podpisu pozostaje
  jedna.

Aktualny zakres Kroku 28:
- to nadal bridge przed `C1`, a nie finalny integer-only strict signer,
- runtime execution wciąż zależy od backendu `ref_f64`,
- krok 28 domyka publiczny surface CT dla ścieżek `*_in(...)`, ale nie zamyka jeszcze audytu.

Weryfikacja Kroku 28:
- `tests/ct_consistency.rs` sprawdza zgodność `expand_ct_strict_in()` z one-shot oraz roundtrip dla
  `sign_ct_strict_in()` i zgodność one-shot/workspace na tych samych seedach i nonce,
- pełne `cargo test` oraz `cargo test --no-default-features --features ct-strict` przechodzą na
  zielono.

## Krok 29

Stan po Kroku 29:
- `src/falcon/sign_ct_strict.rs`, `src/sampler/sign_ct_strict.rs`, `src/falcon/expand_ct.rs` i
  `src/math/fft_soft.rs` nie importują już bezpośrednio `ref_f64` ani `libm`,
- `gaussian0_sampler_ct()` nie ma już wczesnego wyjścia po CDF i zużywa stały budżet PRNG dla
  pojedynczej próby,
- `SignCtWorkspace<LOGN>` ma własny scratch i `Drop + zeroize` dla buforów strict-path,
- dodany został prywatny groundwork `src/math/fft_soft.rs` oraz tabela
  `src/math/fft_gm_bits_table.rs`, ale ten executor nie jest jeszcze domyślną ścieżką runtime.

Wynik audytu Kroku 29:
- publiczne moduły strict zostały odcięte od bezpośrednich importów `ref_f64`,
- strict signer używa już strict samplera z Kroku 25,
- jednocześnie wykonanie signing math pozostaje jeszcze spięte przez prywatny helper
  `src/falcon/sign_ct_bridge_ref.rs`, więc **Bramka C1.3 (`ct_strict` nie używa `f64`) nadal nie
  jest zamknięta**.

Weryfikacja Kroku 29:
- `tests/ct_consistency.rs` ma audyt źródeł `strict_modules_do_not_directly_import_ref_f64_or_libm`,
- testy strict roundtrip dla 512 i 1024 przechodzą na zielono,
- `cargo test --test ct_consistency`, `cargo test sign_ct_strict` i pełne `cargo test` przechodzą
  w WSL Alpine.

## Krok 30

Stan po Kroku 30:
- `tests/ct_consistency.rs` domyka publiczne testy strict-path: roundtrip
  `verify(sign_ct_strict(...))`, parity nagłówka/wire formatu `ref` vs `ct_strict` dla
  `Compression::{None, Static}` oraz timing smoke na stałych seedach,
- `src/sampler/sign_ct_strict.rs` ma distribution smoke i timing smoke dla strict samplera,
- `fuzz/decode_signature` jest kompilowalnym harnesssem `libFuzzer` dla wspólnego dekodera
  podpisu używanego przez `ref` i `ct_strict`.

Wynik Kroku 30:
- domknięty jest audyt testowy i regresyjny dla strict surface oraz shared signature decode,
- jednocześnie **Bramka C1.3 nadal pozostaje otwarta**, bo runtime strict signing wciąż przechodzi
  przez prywatny bridge `src/falcon/sign_ct_bridge_ref.rs`, więc wykonanie nadal zależy od
  referencyjnego backendu `ref_f64`.

Weryfikacja Kroku 30:
- `cargo test --test ct_consistency`,
- `cargo test sampler::sign_ct_strict`,
- `cargo test --no-default-features --features ct-strict`,
- `CXX=clang++ cargo check --manifest-path fuzz/Cargo.toml`,
- pełne `cargo test` w WSL Alpine.
