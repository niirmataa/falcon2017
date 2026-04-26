#!/usr/bin/env python3
"""Validate DGS_PROD_V1 table manifest shape.

This checker verifies canonical table identity, threshold encoding, monotonicity,
and the minimal certificate fields defined in docs/dgs_table_manifest_v1.md. It
does not replace the independent Arb/MPFR or Sage/python-flint distribution
certificate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "falcon2017.dgs_prod_v1.table_manifest.v1"
TABLE_ID_PREFIX = "dgs-prod-v1:payload-sha256:"
PROFILE = "DGS_PROD_V1"
DEN_BITS = 256
THRESHOLD_BITS = 256
THRESHOLD_WORDS = 4
BUCKET_COUNT_MIN = 2
BUCKET_COUNT_MAX = 1024
TAIL_BITS_MIN = 192
HEX_256 = re.compile(r"^[0-9a-f]{64}$")
LABEL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
DECIMAL = re.compile(r"^[0-9]+\.[0-9]+$")


class ManifestError(ValueError):
    """Raised when a manifest violates the frozen V1 shape."""


def fail(message: str) -> None:
    raise ManifestError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def require_object(value: Any, field: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{field} must be an object")
    return value


def require_int(value: Any, field: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{field} must be an integer")
    return value


def require_str(value: Any, field: str) -> str:
    require(isinstance(value, str), f"{field} must be a string")
    return value


def require_exact_keys(obj: dict[str, Any], field: str, allowed: set[str]) -> None:
    actual = set(obj)
    missing = sorted(allowed - actual)
    extra = sorted(actual - allowed)
    require(not missing, f"{field} missing keys: {', '.join(missing)}")
    require(not extra, f"{field} has unknown keys: {', '.join(extra)}")


def canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return encoded.encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ceil_log2(x: int) -> int:
    require(x > 0, "ceil_log2 input must be positive")
    return (x - 1).bit_length()


def parse_thresholds(thresholds: Any) -> tuple[list[int], str]:
    require(isinstance(thresholds, list), "payload.thresholds_hex_be must be a list")
    values: list[int] = []
    raw = bytearray()
    previous = 0

    for index, item in enumerate(thresholds):
        text = require_str(item, f"payload.thresholds_hex_be[{index}]")
        require(HEX_256.fullmatch(text) is not None, f"threshold {index} must be 64 lowercase hex chars")
        value = int(text, 16)
        require(value > 0, f"threshold {index} must be nonzero")
        require(value > previous, f"threshold {index} must be strictly greater than previous")
        values.append(value)
        raw.extend(bytes.fromhex(text))
        previous = value

    return values, sha256_hex(bytes(raw))


def validate_sigma(value: Any) -> None:
    sigma = require_object(value, "payload.sigma")
    require_exact_keys(sigma, "payload.sigma", {"id", "decimal"})
    sigma_id = require_str(sigma["id"], "payload.sigma.id")
    sigma_decimal = require_str(sigma["decimal"], "payload.sigma.decimal")
    require(LABEL.fullmatch(sigma_id) is not None, "payload.sigma.id must be a lowercase stable label")
    require(DECIMAL.fullmatch(sigma_decimal) is not None, "payload.sigma.decimal must be fixed-point decimal")


def validate_payload(payload: Any) -> tuple[str, str, int, int]:
    payload = require_object(payload, "payload")
    require_exact_keys(
        payload,
        "payload",
        {
            "profile",
            "den_bits",
            "threshold_bits",
            "threshold_words",
            "bucket_count",
            "threshold_count",
            "bucket_order",
            "support_min",
            "support_max",
            "sigma",
            "thresholds_hex_be",
        },
    )

    require(payload["profile"] == PROFILE, "payload.profile mismatch")
    require(require_int(payload["den_bits"], "payload.den_bits") == DEN_BITS, "payload.den_bits must be 256")
    require(
        require_int(payload["threshold_bits"], "payload.threshold_bits") == THRESHOLD_BITS,
        "payload.threshold_bits must be 256",
    )
    require(
        require_int(payload["threshold_words"], "payload.threshold_words") == THRESHOLD_WORDS,
        "payload.threshold_words must be 4",
    )

    bucket_count = require_int(payload["bucket_count"], "payload.bucket_count")
    threshold_count = require_int(payload["threshold_count"], "payload.threshold_count")
    support_min = require_int(payload["support_min"], "payload.support_min")
    support_max = require_int(payload["support_max"], "payload.support_max")

    require(BUCKET_COUNT_MIN <= bucket_count <= BUCKET_COUNT_MAX, "payload.bucket_count outside V1 range")
    require(threshold_count == bucket_count - 1, "payload.threshold_count must equal bucket_count - 1")
    require(support_max >= support_min, "payload support range is inverted")
    require(support_max - support_min + 1 == bucket_count, "payload support range does not match bucket_count")
    require(payload["bucket_order"] == "signed_centered", "payload.bucket_order must be signed_centered")
    validate_sigma(payload["sigma"])

    thresholds, thresholds_sha256 = parse_thresholds(payload["thresholds_hex_be"])
    require(len(thresholds) == threshold_count, "threshold list length does not match threshold_count")

    payload_sha256 = sha256_hex(canonical_payload_bytes(payload))
    quant_bits_floor = DEN_BITS + 1 - ceil_log2(bucket_count)
    return payload_sha256, thresholds_sha256, bucket_count, quant_bits_floor


def validate_certificate(cert: Any, thresholds_sha256: str, quant_bits_floor: int, require_certified: bool) -> str:
    cert = require_object(cert, "certificate")
    require_exact_keys(
        cert,
        "certificate",
        {"status", "purpose", "thresholds_sha256", "generator", "checker", "bounds"},
    )

    status = require_str(cert["status"], "certificate.status")
    require(status in {"fixture-not-production", "certified"}, "certificate.status is not allowed")
    require_str(cert["purpose"], "certificate.purpose")
    require(cert["thresholds_sha256"] == thresholds_sha256, "certificate.thresholds_sha256 mismatch")

    generator = require_object(cert["generator"], "certificate.generator")
    checker = require_object(cert["checker"], "certificate.checker")
    bounds = require_object(cert["bounds"], "certificate.bounds")
    require_exact_keys(generator, "certificate.generator", {"authority", "source_commit", "precision_bits"})
    require_exact_keys(checker, "certificate.checker", {"authority", "source_commit"})
    require_exact_keys(bounds, "certificate.bounds", {"tail_per_draw_bits_min", "quant_per_draw_bits_min", "runtime_error"})
    require_str(generator["authority"], "certificate.generator.authority")
    require_str(generator["source_commit"], "certificate.generator.source_commit")
    require_int(generator["precision_bits"], "certificate.generator.precision_bits")
    require_str(checker["authority"], "certificate.checker.authority")
    require_str(checker["source_commit"], "certificate.checker.source_commit")

    tail_bits = require_int(bounds["tail_per_draw_bits_min"], "certificate.bounds.tail_per_draw_bits_min")
    quant_bits = require_int(bounds["quant_per_draw_bits_min"], "certificate.bounds.quant_per_draw_bits_min")
    runtime_error = require_str(bounds["runtime_error"], "certificate.bounds.runtime_error")

    if require_certified:
        require(status == "certified", "--require-certified requires certificate.status == certified")
        require(tail_bits >= TAIL_BITS_MIN, "certified table tail bound is too weak")
        require(quant_bits >= quant_bits_floor, "certified table quantization bound is too weak")
        require(runtime_error == "0", "certified table runtime_error must be 0")

    return status


def validate_manifest(path: Path, require_certified: bool) -> str:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON: {exc}")

    manifest = require_object(manifest, "manifest")
    require_exact_keys(manifest, "manifest", {"schema", "table_id", "payload", "certificate"})
    require(manifest["schema"] == SCHEMA, "schema mismatch")

    payload_sha256, thresholds_sha256, bucket_count, quant_bits_floor = validate_payload(manifest["payload"])
    expected_table_id = f"{TABLE_ID_PREFIX}{payload_sha256}"
    table_id = require_str(manifest["table_id"], "table_id")
    require(table_id == expected_table_id, "table_id does not match canonical payload hash")
    status = validate_certificate(manifest["certificate"], thresholds_sha256, quant_bits_floor, require_certified)

    return (
        f"OK {path} table_id={table_id} status={status} "
        f"bucket_count={bucket_count} thresholds_sha256={thresholds_sha256}"
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="+", type=Path, help="DGS table manifest JSON file")
    parser.add_argument("--require-certified", action="store_true", help="reject fixture/not-production manifests")
    args = parser.parse_args(argv)

    for path in args.manifest:
        try:
            print(validate_manifest(path, args.require_certified))
        except ManifestError as exc:
            print(f"FAIL {path}: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
