# UI/UX Guidelines

CLI first; desktop app later. UX must be explicit and safe.

## CLI

- Never echo secrets; use secure prompts
- `--stdin` and `--stdout` for automation
- `--copy` clears clipboard after timeout (configurable via `SPWM_CLIPBOARD_TIMEOUT`)
- Clear error messages with typed exit codes

## Desktop (PySide6)

- Views: unlock, list, editor, audit, recovery
- Clipboard hygiene: opt-in copy with countdown; wipe on lock
- No auto-fill integrations in v1

## Accessibility

- Keyboard navigation; high-contrast mode; screen-reader labels

