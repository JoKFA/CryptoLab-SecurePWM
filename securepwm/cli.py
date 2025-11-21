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

DEFAULT_VAULT_PATH = os.path.join(os.path.expanduser("~"), ".securepwm", "vault.db")

def cmd_init(args):
    print("=== SecurePWM - Initialize New Vault ===\n")
    vault_dir = os.path.dirname(args.vault)
    if vault_dir and not os.path.exists(vault_dir):
        os.makedirs(vault_dir)
    if os.path.exists(args.vault):
        print(f"ERROR: Vault already exists at {args.vault}")
        return 1
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
    print("\nInitializing vault...")
    vault = Vault(args.vault)
    vault_id = vault.initialize(password)
    print(f"\n✓ Vault created!")
    print(f"  Vault ID: {vault_id}")
    print(f"  Location: {args.vault}")
    vault.lock()
    return 0

def cmd_add(args):
    print("=== Add New Entry ===\n")
    if not os.path.exists(args.vault):
        print(f"ERROR: Vault not found at {args.vault}")
        return 1
    password = getpass.getpass("Master password: ")
    vault = Vault(args.vault)
    try:
        vault.unlock(password)
    except Exception:
        print("ERROR: Failed to unlock vault.")
        return 1

    # Get username (required)
    username = args.username or input("Username (required): ").strip()
    if not username:
        print("ERROR: Username is required.")
        vault.lock()
        return 1

    # Get site (optional)
    site = args.site or input("Site/URL (optional): ").strip() or None

    # Get or generate secret
    if args.generate:
        secret = crypto.generate_password(args.length, use_symbols=not args.no_symbols)
        print(f"\nGenerated password: {secret}")
    else:
        secret = getpass.getpass("\nEnter secret/password to store: ")

    try:
        entry_id = vault.add_entry(secret.encode('utf-8'), username, site)
        print(f"\n✓ Entry added!")
        print(f"  Entry ID: {entry_id}")
        print(f"  Username: {username}")
        if site:
            print(f"  Site: {site}")
    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        vault.lock()
    return 0

def cmd_get(args):
    print("=== Get Entry ===\n")
    if not os.path.exists(args.vault):
        print(f"ERROR: Vault not found")
        return 1
    password = getpass.getpass("Master password: ")
    vault = Vault(args.vault)
    try:
        vault.unlock(password)
    except Exception:
        print("ERROR: Failed to unlock vault.")
        return 1
    try:
        entry = vault.get_entry(args.entry_id)
        print(f"\n  ID: {entry['id']}")
        print(f"  Username: {entry['username']}")
        if entry['site']:
            print(f"  Site: {entry['site']}")
        print(f"  Secret: {entry['secret'].decode('utf-8')}")
        if args.copy:
            try:
                import pyperclip
                pyperclip.copy(entry['secret'].decode('utf-8'))
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
    print("=== List Entries ===\n")
    if not os.path.exists(args.vault):
        print(f"ERROR: Vault not found")
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
            print(f"{'ID':<36}  {'Username':<20}  {'Site':<30}")
            print("-" * 90)
            for e in entries:
                site = e['site'] or '-'
                print(f"{e['id']:<36}  {e['username']:<20}  {site:<30}")
    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        vault.lock()
    return 0

def cmd_search(args):
    print("=== Search Entries ===\n")
    if not os.path.exists(args.vault):
        print(f"ERROR: Vault not found")
        return 1
    password = getpass.getpass("Master password: ")
    vault = Vault(args.vault)
    try:
        vault.unlock(password)
        if args.username:
            entries = vault.search_by_username(args.username)
            print(f"Searching by username: {args.username}\n")
        elif args.site:
            entries = vault.search_by_site(args.site)
            print(f"Searching by site: {args.site}\n")
        else:
            print("ERROR: Specify --username or --site")
            return 1
        if not entries:
            print("No matching entries found.")
        else:
            print(f"Found {len(entries)} entries:\n")
            print(f"{'ID':<36}  {'Username':<20}  {'Site':<30}")
            print("-" * 90)
            for e in entries:
                site = e['site'] or '-'
                print(f"{e['id']:<36}  {e['username']:<20}  {site:<30}")
    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        vault.lock()
    return 0

def cmd_delete(args):
    print("=== Delete Entry ===\n")
    if not os.path.exists(args.vault):
        print(f"ERROR: Vault not found.")
        return 1
    password = getpass.getpass("Master password: ")
    vault = Vault(args.vault)
    try:
        vault.unlock(password)
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
    password = crypto.generate_password(args.length, use_symbols=not args.no_symbols)
    print(password)
    return 0

def cmd_verify(args):
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
        else:
            print("✗ AUDIT LOG HAS BEEN TAMPERED!")
            return 1
    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        vault.lock()
    return 0

def cmd_recovery_create(args):
    print("=== Create Recovery Kit ===\n")
    if not os.path.exists(args.vault):
        print(f"ERROR: Vault not found.")
        return 1
    password = getpass.getpass("Master password: ")
    vault = Vault(args.vault)
    try:
        vault.unlock(password)
        print(f"\nGenerating {args.n} shares (need {args.k} to recover)...")
        shares = generate_recovery_shares(vault.recovery_key, args.k, args.n)
        kit_text = print_recovery_kit(shares, vault.vault_id, args.k)
        output_file = args.output or "recovery_kit.txt"
        with open(output_file, 'w') as f:
            f.write(kit_text)
        print(f"\n✓ Recovery kit saved to: {output_file}")
    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    finally:
        vault.lock()
    return 0

def cmd_recovery_use(args):
    print("=== Recover Vault ===\n")
    print("(Not fully implemented in simplified version)")
    return 0

def main():
    parser = argparse.ArgumentParser(description="SecurePWM - Zero-Knowledge Password Manager")
    parser.add_argument('--vault', default=DEFAULT_VAULT_PATH, help='Vault path')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    subparsers.add_parser('init', help='Initialize new vault')

    p_add = subparsers.add_parser('add', help='Add password entry')
    p_add.add_argument('--username', '-u', help='Username (required)')
    p_add.add_argument('--site', '-s', help='Site/URL (optional)')
    p_add.add_argument('--generate', '-g', action='store_true', help='Generate password')
    p_add.add_argument('--length', '-l', type=int, default=20, help='Password length')
    p_add.add_argument('--no-symbols', action='store_true', help='No symbols')

    p_get = subparsers.add_parser('get', help='Get entry')
    p_get.add_argument('entry_id', help='Entry ID')
    p_get.add_argument('--copy', '-c', action='store_true', help='Copy to clipboard')

    subparsers.add_parser('list', help='List all entries')

    p_search = subparsers.add_parser('search', help='Search entries')
    p_search.add_argument('--username', '-u', help='Search by username')
    p_search.add_argument('--site', '-s', help='Search by site')

    p_delete = subparsers.add_parser('delete', help='Delete entry')
    p_delete.add_argument('entry_id', help='Entry ID')
    p_delete.add_argument('--hard', action='store_true', help='Permanent delete')

    p_gen = subparsers.add_parser('generate', help='Generate password')
    p_gen.add_argument('--length', '-l', type=int, default=20, help='Length')
    p_gen.add_argument('--no-symbols', action='store_true', help='No symbols')

    subparsers.add_parser('verify', help='Verify audit log')

    p_rec = subparsers.add_parser('recovery-create', help='Create recovery kit')
    p_rec.add_argument('--k', type=int, default=3, help='Threshold')
    p_rec.add_argument('--n', type=int, default=5, help='Total shares')
    p_rec.add_argument('--output', '-o', help='Output file')

    subparsers.add_parser('recovery-use', help='Recover vault')

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    commands = {
        'init': cmd_init, 'add': cmd_add, 'get': cmd_get, 'list': cmd_list,
        'search': cmd_search, 'delete': cmd_delete, 'generate': cmd_generate,
        'verify': cmd_verify, 'recovery-create': cmd_recovery_create,
        'recovery-use': cmd_recovery_use,
    }
    return commands[args.command](args)

if __name__ == '__main__':
    sys.exit(main())
