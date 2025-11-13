# Testing Strategy

We use pytest + Hypothesis. The strategy focuses on correctness, misuse resistance, and integrity.

## Test Types

- Unit tests
  - Crypto wrappers: vectors and parameter validation
  - Vault repo: CRUD, transactions, PRAGMAs applied
  - Audit chain: append/verify, payload hashing

- Property tests
  - Crypto round-trips (plaintext, AD) across sizes [0, 64KiB]
  - Tamper tests: flip bits in ct/tag/nonce/AD → decrypt fails
  - Nonce uniqueness: detect duplicate nonces per key under test harness

- Misuse tests
  - Wrong AD fields/values → fail
  - Swap KE/AD between entries → fail
  - Reuse nonce (same key) → detect via harness; library may not fail

- Integration tests
  - CLI flows: init → add → get → update → delete → audit verify
  - Crash simulation: kill between transaction steps (use threads) and verify integrity

- Performance tests
  - KDF calibration latency window; unlock time under targets

## Coverage Targets

- Crypto and vault services: ≥ 95%
- CLI integration: basic happy paths

## Running Tests

```
pytest -q
pytest -q tests/test_crypto_property.py -k roundtrip
```

