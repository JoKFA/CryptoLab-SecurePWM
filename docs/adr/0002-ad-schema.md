# ADR 0002: Associated Data (AD) Schema

Status: Accepted
Date: 2025-11-13

## Context

AD binds ciphertexts to their context. We need a canonical and stable representation.

## Decision

- Use JSON Canonicalization (JCS-like) for AD objects
- Fields per context as in docs/crypto-spec.md Section 5

## Consequences

- Deterministic serialization eases testing and cross-language portability.

