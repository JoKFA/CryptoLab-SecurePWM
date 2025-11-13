# ADR 0004: FIPS Profile

Status: Accepted
Date: 2025-11-13

## Context

Some environments require FIPS-validated primitives and providers.

## Decision

- Provide a FIPS profile: AES-256-GCM only; OpenSSL provider path
- Select via `SPWM_PROFILE=fips` or CLI `--profile fips`

## Consequences

- Reduced algorithm set; potential performance differences; larger binaries when statically linking providers

