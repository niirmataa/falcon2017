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
