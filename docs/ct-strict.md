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
