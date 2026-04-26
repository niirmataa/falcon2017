# DGS Table Manifest V1

Status: shape contract for `DGS_PROD_V1` table artifacts. This is not a table
generator and not a distribution certificate by itself.

## Purpose

Every production DGS table must have a machine-checkable manifest before it can
be converted into Rust static arrays. The manifest separates four layers:

- payload: the exact table semantics and thresholds;
- table ID: a deterministic hash of the payload;
- certificate: provenance and bounds produced by external authorities;
- runtime: Rust static arrays generated only after the manifest is accepted.

The runtime sampler must not parse JSON and must not build CDF tables at runtime.
This format is for review, reproducibility, and checked code generation.

## File Format

The manifest is UTF-8 JSON with this top-level shape:

```json
{
  "schema": "falcon2017.dgs_prod_v1.table_manifest.v1",
  "table_id": "dgs-prod-v1:payload-sha256:<64 lowercase hex>",
  "payload": { "...": "..." },
  "certificate": { "...": "..." }
}
```

No extra top-level keys are allowed in V1. Any semantic extension requires a new
schema string.

## Payload

Payload fields are canonicalized with JSON object keys sorted lexicographically
and compact separators before hashing:

```text
canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
payload_sha256    = SHA256(canonical_payload)
table_id          = "dgs-prod-v1:payload-sha256:" || hex(payload_sha256)
```

Required payload fields:

```json
{
  "profile": "DGS_PROD_V1",
  "den_bits": 256,
  "threshold_bits": 256,
  "threshold_words": 4,
  "bucket_count": 0,
  "threshold_count": 0,
  "bucket_order": "signed_centered",
  "support_min": 0,
  "support_max": 0,
  "sigma": {
    "id": "sigma-id",
    "decimal": "1.234567890000000000"
  },
  "thresholds_hex_be": []
}
```

Rules:

- `bucket_count` is the number of output buckets and must satisfy `2 <= bucket_count <= 1024`.
- `threshold_count == bucket_count - 1`.
- `thresholds_hex_be.len() == threshold_count`.
- `support_max - support_min + 1 == bucket_count`.
- `bucket_order == "signed_centered"` for V1.
- each threshold is exactly 64 lowercase hex characters;
- each threshold encodes an integer `T_i` with `0 < T_i < 2^256`;
- thresholds are strictly increasing: `T_i < T_{i+1}`.

The signed-centered bucket order is:

```text
bucket_index 0 -> support_min
bucket_index 1 -> support_min + 1
...
bucket_index bucket_count-1 -> support_max
```

For centered zero-mean tables this normally means `support_min = -M` and
`support_max = M`, but the manifest stores the actual inclusive support range so
that shifted or specialized tables cannot rely on implicit assumptions.

## Threshold Encoding

Manifest thresholds use canonical big-endian hex for review:

```text
T_i = int(thresholds_hex_be[i], 16)
```

Rust runtime arrays use little-endian `u64` limbs:

```text
limb0 = T_i mod 2^64
limb1 = floor(T_i / 2^64) mod 2^64
limb2 = floor(T_i / 2^128) mod 2^64
limb3 = floor(T_i / 2^192) mod 2^64
```

The checker also computes:

```text
thresholds_sha256 = SHA256(concat(bytes.fromhex(T_i_hex_be) for i in thresholds))
```

The certificate must repeat this value so reviewers can detect accidental edits
to the threshold array independently from the payload hash.

## Certificate

V1 certificate fields:

```json
{
  "status": "fixture-not-production",
  "purpose": "human-readable note",
  "thresholds_sha256": "<64 lowercase hex>",
  "generator": {
    "authority": "C+Arb/MPFR interval arithmetic",
    "source_commit": "<git commit>",
    "precision_bits": 0
  },
  "checker": {
    "authority": "Python/Sage/python-flint independent verifier",
    "source_commit": "<git commit>"
  },
  "bounds": {
    "tail_per_draw_bits_min": 192,
    "quant_per_draw_bits_min": 247,
    "runtime_error": "0"
  }
}
```

Allowed `status` values:

- `fixture-not-production`: shape test only, never usable for signing claims;
- `certified`: accepted by the primary generator and independent checker.

When `scripts/check_dgs_table_manifest.py --require-certified` is used, the
checker requires `status == "certified"`, `runtime_error == "0"`,
`tail_per_draw_bits_min >= 192`, and `quant_per_draw_bits_min` at least as strong
as the table-size-derived quantization bound.

## Gate

A table can become a Rust static table only after all commands pass:

```text
python3 scripts/check_dgs_prod_v1_bounds.py
python3 scripts/check_dgs_table_manifest.py --require-certified path/to/table.json
```

The toy fixture in `tests/fixtures/dgs_prod_v1_toy_manifest.json` is deliberately
not certified. It exists only to lock the schema and checker behavior.
