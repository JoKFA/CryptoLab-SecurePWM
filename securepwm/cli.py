"""
SecurePWM - Command Line Interface

Simple CLI for password manager using only built-in argparse (no dependencies!).

Commands:
    spwm init              - Create new vault
    spwm add               - Add password entry
    spwm get <id>          - Get password by ID
    spwm list              - List all entries
    spwm delete <id>       - Delete entry
    spwm generate          - Generate strong password
    spwm verify            - Verify audit log
    spwm recovery-create   - Create recovery kit
    spwm recovery-use      - Recover vault from shares
"""

import argparse
import sys
import os
import getpass
from pathlib import Path

from . import crypto
from .vault import Vault
from .recovery import generate_recovery_shares, combine_recovery_shares, print_recovery_kit


# =============================================================================
# CONFIGURATION
# =============================================================================

DEFAULT_VAULT_PATH = os.path.join(os.path.expanduser("~"), ".securepwm", "vault.db")


# =============================================================================
# CLI COMMANDS
# =============================================================================

def cmd_init(args):
    """Initialize a new vault."""
    print("=== SecurePWM - Initialize New Vault ===\n")

    # Create directory if needed
    vault_dir = os.path.dirname(args.vault)
    if vault_dir and not os.path.exists(vault_dir):
        os.makedirs(vault_dir)

    # Check if vault already exists
    if os.path.exists(args.vault):
        print(f"ERROR: Vault already exists at {args.vault}")
        print("Use a different path or delete the existing vault.")
        return 1

    # Get master password
    while True:
        password = getpass.getpass("Enter master password: ")
        password2 = getpass.getpass("Confirm master password: ")

        if password != password2:
            print("Passwords don't match. Try again.\n")
            continue

        if len(password) < 8:
            print("Password too short. Use at least 8 characters.\n")
            continue

        break

    # Initialize vault
    print("\nInitializing vault (deriving keys, this may take a moment)...")
    vault = Vault(args.vault)
    vault_id = vault.initialize(password)

    print(f"\n✓ Vault created successfully!")
    print(f"  Vault ID: {vault_id}")
    print(f"  Location: {args.vault}")
    print(f"\nIMPORTANT: Your master password is NOT stored anywhere.")
    print("If you forget it, you'll need recovery shares to regain access.")
    print("\nNext steps:")
    print(f"  1. Create recovery kit: python -m securepwm.cli recovery-create")
    print(f"  2. Add your first password: python -m securepwm.cli add")

    vault.lock()
    return 0


def cmd_add(args):
    """Add a new password entry."""
    print("=== Add New Entry ===\n")

    # Check vault exists
    if not os.path.exists(args.vault):
        print(f"ERROR: Vault not found at {args.vault}")
        print("Run 'init' first to create a vault.")
        return 1

    # Unlock vault
    password = getpass.getpass("Master password: ")
    vault = Vault(args.vault)

    try:
        vault.unlock(password)
    except Exception as e:
        print(f"ERROR: Failed to unlock vault. Wrong password?")
        return 1

    # Get secret to store
    if args.generate:
        # Generate password
        secret = crypto.generate_password(args.length, use_symbols=not args.no_symbols)
        print(f"\nGenerated password: {secret}")
        print("(This will be stored in the vault)")
    else:
        # Prompt for secret
        secret = getpass.getpass("\nEnter secret to store: ")

    # Add entry
    try:
        entry_id = vault.add_entry(secret.encode('utf-8'))
        print(f"\n✓ Entry added successfully!")
        print(f"  Entry ID: {entry_id}")
        print(f"\nTo retrieve: python -m securepwm.cli get {entry_id}")
    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        vault.lock()

    return 0


def cmd_get(args):
    """Retrieve a password entry."""
    print("=== Get Entry ===\n")

    # Check vault exists
    if not os.path.exists(args.vault):
        print(f"ERROR: Vault not found at {args.vault}")
        return 1

    # Unlock vault
    password = getpass.getpass("Master password: ")
    vault = Vault(args.vault)

    try:
        vault.unlock(password)
    except Exception:
        print(f"ERROR: Failed to unlock vault.")
        return 1

    # Get entry
    try:
        secret = vault.get_entry(args.entry_id)
        print(f"\nSecret: {secret.decode('utf-8')}")

        if args.copy:
            try:
                import pyperclip
                pyperclip.copy(secret.decode('utf-8'))
                print("(Copied to clipboard)")
            except ImportError:
                print("(Install pyperclip for clipboard support)")

    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        vault.lock()

    return 0


def cmd_list(args):
    """List all entries."""
    print("=== List Entries ===\n")

    if not os.path.exists(args.vault):
        print(f"ERROR: Vault not found at {args.vault}")
        return 1

    password = getpass.getpass("Master password: ")
    vault = Vault(args.vault)

    try:
        vault.unlock(password)
        entries = vault.list_entries()

        if not entries:
            print("No entries in vault.")
        else:
            print(f"Found {len(entries)} entries:\n")
            for entry in entries:
                from datetime import datetime
                created = datetime.fromtimestamp(entry['created_at']).strftime('%Y-%m-%d %H:%M')
                print(f"  {entry['id']}")
                print(f"    Created: {created}\n")

    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        vault.lock()

    return 0


def cmd_delete(args):
    """Delete an entry."""
    print("=== Delete Entry ===\n")

    if not os.path.exists(args.vault):
        print(f"ERROR: Vault not found.")
        return 1

    password = getpass.getpass("Master password: ")
    vault = Vault(args.vault)

    try:
        vault.unlock(password)

        # Confirm deletion
        confirm = input(f"Delete entry {args.entry_id}? (yes/no): ")
        if confirm.lower() != 'yes':
            print("Cancelled.")
            return 0

        vault.delete_entry(args.entry_id, hard=args.hard)
        print(f"✓ Entry deleted.")

    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        vault.lock()

    return 0


def cmd_generate(args):
    """Generate a strong password."""
    password = crypto.generate_password(args.length, use_symbols=not args.no_symbols)
    print(password)
    return 0


def cmd_verify(args):
    """Verify audit log integrity."""
    print("=== Verify Audit Log ===\n")

    if not os.path.exists(args.vault):
        print(f"ERROR: Vault not found.")
        return 1

    password = getpass.getpass("Master password: ")
    vault = Vault(args.vault)

    try:
        vault.unlock(password)

        if vault.verify_audit_log():
            print("✓ Audit log is intact!")
            print("  No tampering detected.")
        else:
            print("✗ AUDIT LOG HAS BEEN TAMPERED!")
            print("  The vault may have been compromised.")
            return 1

    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        vault.lock()

    return 0


def cmd_recovery_create(args):
    """Create recovery kit."""
    print("=== Create Recovery Kit ===\n")

    if not os.path.exists(args.vault):
        print(f"ERROR: Vault not found.")
        return 1

    password = getpass.getpass("Master password: ")
    vault = Vault(args.vault)

    try:
        vault.unlock(password)

        # Generate shares
        print(f"\nGenerating {args.n} shares (need {args.k} to recover)...")
        shares = generate_recovery_shares(vault.recovery_key, args.k, args.n)

        # Format recovery kit
        kit_text = print_recovery_kit(shares, vault.vault_id, args.k)

        # Save to file
        output_file = args.output or "recovery_kit.txt"
        with open(output_file, 'w') as f:
            f.write(kit_text)

        print(f"\n✓ Recovery kit saved to: {output_file}")
        print(f"\nIMPORTANT:")
        print(f"  - Print this file and store shares in separate locations")
        print(f"  - You need {args.k} shares to recover if you forget your password")
        print(f"  - DELETE THIS FILE after printing!")

    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        vault.lock()

    return 0


def cmd_recovery_use(args):
    """Recover vault using shares."""
    print("=== Recover Vault ===\n")
    print("This feature would reset your master password using recovery shares.")
    print("(Not fully implemented in this simplified version)")
    return 0


# =============================================================================
# MAIN CLI ENTRY POINT
# =============================================================================

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="SecurePWM - Zero-Knowledge Password Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--vault',
        default=DEFAULT_VAULT_PATH,
        help=f'Vault database path (default: {DEFAULT_VAULT_PATH})'
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # init command
    parser_init = subparsers.add_parser('init', help='Initialize new vault')

    # add command
    parser_add = subparsers.add_parser('add', help='Add password entry')
    parser_add.add_argument('--generate', action='store_true', help='Generate random password')
    parser_add.add_argument('--length', type=int, default=20, help='Password length (default: 20)')
    parser_add.add_argument('--no-symbols', action='store_true', help='No symbols in generated password')

    # get command
    parser_get = subparsers.add_parser('get', help='Get password entry')
    parser_get.add_argument('entry_id', help='Entry ID')
    parser_get.add_argument('--copy', action='store_true', help='Copy to clipboard (requires pyperclip)')

    # list command
    parser_list = subparsers.add_parser('list', help='List all entries')

    # delete command
    parser_delete = subparsers.add_parser('delete', help='Delete entry')
    parser_delete.add_argument('entry_id', help='Entry ID')
    parser_delete.add_argument('--hard', action='store_true', help='Permanently delete (vs soft delete)')

    # generate command
    parser_gen = subparsers.add_parser('generate', help='Generate strong password')
    parser_gen.add_argument('--length', type=int, default=20, help='Password length')
    parser_gen.add_argument('--no-symbols', action='store_true', help='No symbols')

    # verify command
    parser_verify = subparsers.add_parser('verify', help='Verify audit log integrity')

    # recovery-create command
    parser_rec_create = subparsers.add_parser('recovery-create', help='Create recovery kit')
    parser_rec_create.add_argument('--k', type=int, default=3, help='Threshold (shares needed)')
    parser_rec_create.add_argument('--n', type=int, default=5, help='Total shares to create')
    parser_rec_create.add_argument('--output', help='Output file (default: recovery_kit.txt)')

    # recovery-use command
    parser_rec_use = subparsers.add_parser('recovery-use', help='Recover vault from shares')

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Route to command handler
    commands = {
        'init': cmd_init,
        'add': cmd_add,
        'get': cmd_get,
        'list': cmd_list,
        'delete': cmd_delete,
        'generate': cmd_generate,
        'verify': cmd_verify,
        'recovery-create': cmd_recovery_create,
        'recovery-use': cmd_recovery_use,
    }

    return commands[args.command](args)


if __name__ == '__main__':
    sys.exit(main())
