#!/usr/bin/env python3
"""Recompute DGS_PROD_V1 headline bounds.

This is a reproducibility checker for docs/dgs_prod_v1.md. It is not a table
certificate and does not replace Arb/MPFR interval verification.
"""

from __future__ import annotations

import math

DEN_BITS = 256
THRESHOLD_BITS = 256
THRESHOLD_WORDS = 4
N_MAX_LOG2 = 10
N_MAX = 1 << N_MAX_LOG2
N_DGS_BUDGET_LOG2 = 32
N_DGS_BUDGET = 1 << N_DGS_BUDGET_LOG2
LAMBDA_SECURITY_TARGET = 128
LAMBDA_TAIL_PER_DRAW = 192
K_PUBLISHED = 16.357103


def bits_of_probability(p: float) -> float:
    return -math.log2(p)


def main() -> int:
    k_min = math.sqrt(2.0 * math.log(2.0) * (LAMBDA_TAIL_PER_DRAW + 1))
    tail_per_draw = 2.0 * math.exp(-(K_PUBLISHED * K_PUBLISHED) / 2.0)
    tail_per_draw_bits = bits_of_probability(tail_per_draw)
    tail_global_bits = tail_per_draw_bits - N_DGS_BUDGET_LOG2

    quant_per_draw_bits = (DEN_BITS + 1) - N_MAX_LOG2
    quant_global_bits = quant_per_draw_bits - N_DGS_BUDGET_LOG2

    high_budget_scalar_log2 = N_DGS_BUDGET_LOG2 + N_MAX_LOG2
    high_budget_tail_global_bits = tail_per_draw_bits - high_budget_scalar_log2
    high_budget_required_lambda = 160 + high_budget_scalar_log2
    high_budget_k = math.sqrt(2.0 * math.log(2.0) * (high_budget_required_lambda + 1))

    print("DGS_PROD_V1 bound check")
    print(f"den_bits                         = {DEN_BITS}")
    print(f"threshold_bits                   = {THRESHOLD_BITS}")
    print(f"threshold_words                  = {THRESHOLD_WORDS}")
    print(f"n_max                            = {N_MAX} = 2^{N_MAX_LOG2}")
    print(f"N_DGS_budget_scalar              = {N_DGS_BUDGET} = 2^{N_DGS_BUDGET_LOG2}")
    print(f"lambda_security_target           = {LAMBDA_SECURITY_TARGET}")
    print(f"lambda_tail_per_draw_target      = {LAMBDA_TAIL_PER_DRAW}")
    print(f"k_min_for_two_sided_2^-192       = {k_min:.15f}")
    print(f"k_published                      = {K_PUBLISHED:.6f}")
    print(f"tail_per_draw_bits               = {tail_per_draw_bits:.12f}")
    print(f"tail_global_bits                 = {tail_global_bits:.12f}")
    print(f"quant_per_draw_bits              = {quant_per_draw_bits}")
    print(f"quant_global_bits                = {quant_global_bits}")
    print(f"max_full_1024_draw_proofs        = 2^{N_DGS_BUDGET_LOG2 - N_MAX_LOG2}")
    print(f"tail_bits_if_2^32_full_1024_draw = {high_budget_tail_global_bits:.12f}")
    print(f"lambda_needed_for_2^-160_full    = {high_budget_required_lambda}")
    print(f"k_needed_for_2^-160_full         = {high_budget_k:.15f}")

    assert DEN_BITS == 256
    assert THRESHOLD_BITS == 256
    assert THRESHOLD_WORDS == 4
    assert K_PUBLISHED >= k_min
    assert tail_per_draw_bits >= LAMBDA_TAIL_PER_DRAW
    assert tail_global_bits >= 160.0
    assert quant_per_draw_bits >= 247
    assert quant_global_bits >= 215
    assert LAMBDA_SECURITY_TARGET <= 128

    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
