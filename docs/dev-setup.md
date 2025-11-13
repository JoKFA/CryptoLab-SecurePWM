# Developer Setup

Target: Python 3.12+, Windows/macOS/Linux

## Prerequisites

- Python 3.12+
- pipx or venv
- Git
- Optional: libsodium (via pynacl wheels) and OpenSSL for FIPS paths

## Create Environment

Windows (PowerShell):

```
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -U pip
```

macOS/Linux:

```
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
```

## Install Dev Dependencies

```
pip install typer[all] rich pynacl cryptography pyotp slip39 hypothesis pytest ruff black mypy bandit pip-audit
```

## Pre-commit (optional)

```
pip install pre-commit
pre-commit install
```

## Running Tests

```
pytest -q
```

Property tests may take longer; see docs/testing.md for focused runs.

## Running CLI (during development)

We will package the CLI under `securepwm/cli`. For local runs:

```
python -m securepwm.cli --help
```

## Profiles

- Default profile uses XChaCha20-Poly1305.
- FIPS profile uses AES-256-GCM: set `SPWM_PROFILE=fips` or `--profile fips`.

## Platform Notes

- Windows clipboard may require `pyperclip` or `win32clipboard` backend.
- Ensure your terminal supports secure password input (no echo).

