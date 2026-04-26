# DGS_PROD_V1 Sampling Profile

Status: design target, not yet implemented. The current `sign_ct_strict`
sampler remains research-only. This document defines the production-grade DGS
profile that must be proven before it can replace or support any security claim.

## Scope

`DGS_PROD_V1` is a static inverse-CDF discrete Gaussian sampler profile:

- runtime uses static CDF tables only;
- no runtime table generation;
- no rejection or retry loop;
- every 256-bit draw maps to exactly one output bucket;
- all table scans are fixed length for a given table;
- all bounds are stated for scalar DGS draws, not whole signatures/proofs unless explicitly stated.

This profile is not a claim that the current Falcon 2017 Extra reference sampler
has been replaced. Falcon integration requires a separate equivalence or
statistical-distance proof for the exact signing distribution.

## Parameters

```text
profile_name           = DGS_PROD_V1
den_bits               = 256
threshold_bits         = 256
threshold_words        = 4
S                      = 2^256
CDF entry              = [u64; 4]
CDF len                = n - 1
last bucket            = implicit
n_max                  = 1024
lambda_security_target = 128
N_DGS_budget_scalar    = 2^32
lambda_tail_per_draw   = 192
M(sigma)               = ceil(16.357103 * sigma)
quant_bound_per_draw   = n / 2^257
runtime_error          = 0
```

Important convention: `N_DGS_budget_scalar = 2^32` means total scalar DGS calls
covered by this profile. If one proof/signature consumes up to `1024` scalar DGS
calls, then this profile covers at most `2^22` such proofs/signatures. If the
security statement must cover `2^32` full proofs/signatures with `1024` DGS calls
each, the tail profile must be strengthened; see the high-budget note below.

## Table Representation

Each static table describes a complete finite output bucket set of size `n`.
The table stores `n - 1` cumulative thresholds:

```text
0 < T_0 < T_1 < ... < T_{n-2} < S
S = 2^256
```

Runtime sampling draws a 256-bit secret `u` and returns the first bucket `i` with
`u < T_i`; if no threshold matches, it returns the implicit last bucket. There is
no failure state and no retry.

The Rust in-memory representation is `[u64; 4]` with little-endian limbs:

```text
value = words[0] + 2^64*words[1] + 2^128*words[2] + 2^192*words[3]
```

Generated table files should also include a canonical 32-byte big-endian hex
encoding for review, but runtime code must consume only checked static arrays.

The canonical manifest format is frozen separately in
`docs/dgs_table_manifest_v1.md`. Checked-in tables must pass
`scripts/check_dgs_table_manifest.py` before any Rust table is generated.

## Tail Bound

The published multiplier is:

```text
k = 16.357103
M(sigma) = ceil(k * sigma)
```

It is chosen as the 6-decimal upward rounding of:

```text
sqrt(2 * ln(2) * 193) = 16.357102790413066...
```

Therefore:

```text
2 * exp(-k^2 / 2) <= 2^-192
```

For any table with support radius `M(sigma)`, table generation must either verify
the discrete tail directly or prove it by a certified continuous upper bound:

```text
eps_tail_per_draw <= 2^-192
```

For the scalar draw budget:

```text
eps_tail_global <= 2^32 * 2^-192 = 2^-160
```

This satisfies the project target `lambda_security_target = 128` with 32 bits of
margin for the scalar DGS budget.

### High-Budget Note

If `2^32` means full proofs/signatures and each proof/signature may consume up
to `1024 = 2^10` scalar DGS draws, then the total scalar budget is `2^42`, not
`2^32`. Under `lambda_tail_per_draw = 192`, the global tail bound becomes:

```text
2^42 * 2^-192 = 2^-150
```

That is still above 128-bit security, but it no longer matches the stated
`2^-160` target. To retain `2^-160` for `2^32` full `1024`-draw proofs,
use at least:

```text
lambda_tail_per_draw = 202
M(sigma)             = ceil(16.775511 * sigma)
```

because `16.775511` is the 6-decimal upward rounding of
`sqrt(2 * ln(2) * 203)`.

## Quantization Bound

Each CDF threshold is rounded to denominator `S = 2^256`. With nearest rounding,
each boundary contributes at most `1 / (2S)` absolute CDF error. For `n` buckets,
a conservative per-draw statistical-distance bound is:

```text
eps_quant_per_draw <= n / (2S) = n / 2^257
```

With `n <= 1024 = 2^10`:

```text
eps_quant_per_draw <= 2^10 / 2^257 = 2^-247
```

For `N_DGS_budget_scalar = 2^32`:

```text
eps_quant_global <= 2^32 * 2^-247 = 2^-215
```

## Global Targets

For `N_DGS_budget_scalar = 2^32` and `n <= 1024`:

```text
eps_tail_global  <= 2^-160
eps_quant_global <= 2^-215
eps_runtime      = 0
```

Combined non-ideal mass, using a union bound, is dominated by the tail term:

```text
eps_total_global <= 2^-160 + 2^-215
```

The safe headline is therefore:

```text
eps_total_global < 2^-159
```

For formal claims, keep the tail and quantization components separate rather
than compressing them into a single rounded number.

## DGS Authority

```text
tablegen primary = C + Arb/MPFR interval arithmetic
checker          = Python/Sage/python-flint independent verifier
Rust tablegen    = dev/reference only
runtime          = static CDF only
```

The primary generator must emit:

- table ID and table hash;
- sigma or parameter identifier;
- bucket encoding and ordering;
- `M(sigma)`, `n`, and denominator;
- interval-enclosed probability masses;
- rounded CDF thresholds;
- per-table tail and quantization certificate;
- generator source commit and precision settings.

The checker must independently verify:

- monotonic thresholds;
- `0 < T_0 < ... < T_{n-2} < 2^256`;
- bucket count `n <= 1024`;
- all rounded thresholds are inside the certified rounding intervals;
- per-table tail bound;
- per-table quantization bound;
- table hash and metadata consistency.

Rust code may include developer-only tablegen utilities, but runtime tables must
come from checked static artifacts. No runtime MPFR, no runtime floating point,
no runtime CDF construction.

## DGS Noise

```text
model       = SecretNoisePRG
seed        = secret
algorithm   = public
proof_seed  = KDF(seed_master, "dgs/noise/v1" || proof_id || table_id || counter_domain)
u_i         = PRG(proof_seed, i)
```

`u_i` is the 256-bit sampling draw for scalar sample index `i`. It is sometimes
called a threshold in notes, but it must not be confused with static CDF
thresholds `T_i`.

Rules:

- `seed_master` is secret;
- `proof_id` must be unique for the security context;
- `table_id` and `counter_domain` are domain separators;
- counters are public and fixed-width;
- the PRG must output exactly 256 bits per scalar draw;
- no modulo reduction and no rejection are allowed;
- reusing `(seed_master, proof_id, table_id, counter_domain, i)` is forbidden.

The project should use one KDF/PRG construction consistently, preferably based on
SHAKE256/cSHAKE-style domain separation because SHAKE is already in the codebase.
The exact encoding must be specified before implementation.

## Runtime Algorithm

For a table with `n - 1` thresholds:

```text
u = SecretNoisePRG.next_u256()
answer = last_bucket
for i in 0..n-1:
    take = (u < T_i) & not_found
    answer = ct_select(answer, bucket_i, take)
    not_found = not_found & !take
return answer
```

This is fixed-work for a given table. A professional implementation must also
avoid secret-dependent memory access. The scan must touch every CDF entry in the
same order for every draw.

## Implementation Gates

Do not implement `DGS_PROD_V1` as production code until all gates are satisfied:

1. Table format and bucket ordering are frozen.
2. C+Arb/MPFR table generator exists and emits certificates.
3. Independent checker accepts all checked-in tables.
4. `scripts/check_dgs_prod_v1_bounds.py` passes.
5. Runtime sampler has no rejection and no runtime error path.
6. Runtime sampler has source grep and ASM checks for no secret-dependent branch patterns.
7. Dudect-style runs on bare metal pass for every table family.
8. Distribution tests compare runtime samples against certified table probabilities.
9. Integration proof states whether this sampler is exact, statistically close, or research-only for Falcon.

## Current Project Decision

The current strict Falcon sampler remains research-only. `DGS_PROD_V1` is the
professional target for a future production sampler. The next concrete task is
to implement the table generator/checker pipeline and freeze one certified table
family before touching signing semantics.
