# ADR 0003: KDF Tuning Strategy

Status: Accepted
Date: 2025-11-13

## Context

KDF parameters must balance security and usability across devices.

## Decision

- Calibrate scrypt to ~150–400 ms interactive latency and 64–256 MB memory
- Store per-vault parameters in `vault_state.kdf_params`
- Provide retune command that updates params and rewraps keys atomically

## Consequences

- Predictable unlock latency; platform-specific comfort via calibration

