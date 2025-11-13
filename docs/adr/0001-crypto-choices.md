# ADR 0001: Cryptography Choices

Status: Accepted
Date: 2025-11-13

## Context

We need strong, misuse-resistant primitives with good library support across platforms.

## Decision

- KDF: scrypt (default), Argon2id optional later
- AEAD: XChaCha20-Poly1305 (default), AES-256-GCM for FIPS profile
- HKDF-SHA-256 for subkeys; HMAC-SHA-256 for audit
- RNG via OS CSPRNG

## Consequences

- XChaCha requires libsodium bindings; AES-GCM path for FIPS and environments without libsodium.

