# Policy Engine

The policy engine enforces password quality and hygiene without storing plaintexts.

## Rules

- Minimum length (default 12)
- zxcvbn score threshold (default 3)
- Expiry reminders (e.g., 180 days)
- Reuse prevention: compare against hashed history

## Hashing Strategy

- Store `H(password)` where `H = HKDF(K_config, info="spwm/policy/hash/v1")` + `HMAC-SHA-256(password)`
- Do not store plaintext; ensure domain separation from other keys

## Passgen

- Default charset: upper, lower, digits, symbols (configurable)
- Option to avoid ambiguous characters (O/0, l/1, etc.)
- Ensure at least one char from required classes if symbols allowed

## API

See docs/api-contracts.md (PolicyEngine) for signatures.

