# Strict CT Threat Model

This document defines what the repository means by `ct_strict`, what threats it
is intended to address, and what evidence is required before making a defensive
constant-time claim.

## Goal

`ct_strict` is intended to be a semantically equivalent backend for Falcon 2017
/ Round1 Extra signing operations with stronger resistance to timing and
microarchitectural leakage than the reference path.

The goal is not to define a new scheme. The goal is to preserve scheme
semantics while changing implementation strategy.

## Threat model

The backend is designed against attackers who can observe:

- wall-clock timing
- fine-grained local timing
- cache-sensitive execution behavior
- branch-dependent execution behavior
- memory-access-pattern differences

The backend is therefore expected to avoid:

- secret-dependent branches
- secret-dependent indexing
- data-dependent floating-point behavior
- data-dependent PRNG call counts

## Required design constraints

A backend qualifies as `ct_strict` only if all of the following hold:

1. no `f64` arithmetic in the signing path
2. no `libm` dependence in the signing path
3. no secret-dependent branches
4. no secret-dependent memory access
5. fixed operation shape for equal public sizes
6. fixed PRNG usage pattern for equivalent signing calls

These constraints apply to:

- key expansion
- sampler
- FFT/FPR support path
- signing flow

## Allowed differences from `ref`

The following implementation changes are allowed:

- software emulation of binary64 behavior
- branchless selects and masking
- different workspace organization
- different internal helper decomposition

The following semantic changes are not allowed:

- new wire formats
- changed distributions
- changed norm bounds
- changed acceptance criteria
- changed public parameters

## Evidence required

The defensive CT claim requires all of the following:

### 1. Source-level audit

Demonstrate the absence of:

- `f64`
- `std::f64`
- `libm`
- secret-driven branches
- secret-driven indexing

### 2. Dynamic timing analysis

Run `dudect` or equivalent with large sample counts against:

- `expand_ct_strict`
- `sign_ct_strict`

The implementation fails the CT claim if the resulting score crosses the agreed
threshold.

### 3. Fuzz robustness

Fuzz at minimum:

- secret-key decode
- signature decode
- verification

The long-run campaign should execute on a GNU/Linux host with sanitizer support.

### 4. Differential semantic checks

For equivalent inputs:

- `verify_ref(sign_ct_strict(...)) == OK`
- wire formats remain decodable by the reference path
- norm checks remain unchanged

## Current boundary

The repository may currently describe `ct_strict` as:

- a strict-CT research backend with strong engineering constraints
- a candidate constant-time implementation path

It should reserve the stronger claim:

> defensively constant-time backend

until the source audit, statistical timing evidence, and long-run fuzz evidence
are all recorded from the Ubuntu research host.
