# CLI Specification (spwm)

CLI is implemented with Typer. All commands are non-interactive friendly and return non-zero exit codes on failure. Secrets are never echoed or logged.

## Global

- `--vault PATH` (default: platform config dir)
- `--profile [default|fips]`
- `--json` for machine-readable output where applicable

## Commands

### Vault lifecycle

- `spwm init [--algo xchacha20poly1305|aes256gcm]`
  - Prompts for master password (or `SPWM_MASTER` env var for automation)
  - Outputs vault id and KDF params

- `spwm lock`
- `spwm unlock`
- `spwm info` (prints state; redacted)

### Entries

- `spwm add [--label LABEL] [--stdin]`
  - Reads secret from stdin or prompts securely
  - Prints entry id

- `spwm get --id UUID [--copy] [--stdout]`
  - `--copy` copies to clipboard with timeout

- `spwm list [--all]`
- `spwm update --id UUID [--stdin]`
- `spwm delete --id UUID [--hard]`
- `spwm passgen [--length 20] [--no-symbols] [--no-ambiguous]`

### Policy

- `spwm policy check --stdin` (score password)
- `spwm policy set --min-length N --zxcvbn-threshold T --max-age-days D --prevent-reuse N`

### Audit

- `spwm audit verify`
- `spwm audit export --out PATH`

### Master/keys

- `spwm master change` (securely prompts old/new; atomic rewrap)
- `spwm keys rotate` (aliases master change; reserved for future subkey rotation)

### Recovery

- `spwm recovery init --n 5 --k 3 --print [--out DIR]`
- `spwm recovery combine` (prompts k mnemonics; verifies vault binding)

### TOTP

- `spwm totp setup --issuer NAME --account NAME`
- `spwm totp verify --token CODE`
- `spwm totp remove`

### Sync (optional)

- `spwm sync push`
- `spwm sync pull`
- `spwm sync status`

## Exit Codes

- 0 success; 1 generic error; 2 policy violation; 3 audit verification failed; 4 vault locked; 5 not found; 6 invalid args.

## Environment Variables

- `SPWM_VAULT` path override
- `SPWM_PROFILE` `default|fips`
- `SPWM_MASTER` master password for automation (CI only; avoid in production)
- `SPWM_CLIPBOARD_TIMEOUT` seconds for `--copy`

