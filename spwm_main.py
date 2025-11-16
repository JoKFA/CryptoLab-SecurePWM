import os
import sys
import getpass
from pathlib import Path

from securepwm.vault import Vault
from securepwm.recovery import generate_recovery_shares, print_recovery_kit
from securepwm import crypto

from datetime import datetime

# Try to reuse the same default path as the existing CLI, but fall back if import fails
try:
    from securepwm.cli import DEFAULT_VAULT_PATH
except Exception:  # safety fallback
    DEFAULT_VAULT_PATH = os.path.join(os.path.expanduser("~"), ".securepwm", "vault.db")


def clear_screen() -> None:
    """Clear the terminal screen (best effort)."""
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except Exception:
        pass


def pause() -> None:
    input("\nPress Enter to continue...")


def choose_vault_path(current: str | None = None) -> str:
    """Ask user which vault path to use."""
    default = current or DEFAULT_VAULT_PATH
    print(f"Vault file path [{default}]: ", end="")
    path = input().strip() or default
    return path


def ensure_vault_dir(path: str) -> None:
    """Make sure the directory for the vault exists."""
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)


def unlock_flow(vault_path: str) -> Vault | None:
    """Prompt for master password and unlock the vault at the given path."""
    if not os.path.exists(vault_path):
        print(f"\nERROR: Vault not found at {vault_path}")
        print("Create one first from the menu.")
        pause()
        return None

    password = getpass.getpass("\nMaster password: ")
    vault = Vault(vault_path)
    try:
        vault.unlock(password)
        print("\n✓ Vault unlocked.")
        pause()
        return vault
    except Exception as e:
        print(f"\nERROR: Failed to unlock vault ({e}).")
        pause()
        return None


def require_unlocked(vault: Vault | None, vault_path: str) -> Vault | None:
    """
    Make sure we have an unlocked vault.
    If not, try to unlock the current vault_path.
    """
    if vault is not None:
        return vault
    return unlock_flow(vault_path)


def cmd_init(vault_path: str) -> tuple[Vault | None, str]:
    clear_screen()
    print("=== Initialize New Vault ===\n")

    vault_path = choose_vault_path(vault_path)

    if os.path.exists(vault_path):
        print(f"\nA vault already exists at:\n  {vault_path}")
        print("If you really want to overwrite it, delete it manually first.")
        pause()
        return None, vault_path

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

    ensure_vault_dir(vault_path)

    print("\nInitializing vault (deriving keys, this may take a moment)...")
    vault = Vault(vault_path)
    try:
        vault_id = vault.initialize(password)
    except Exception as e:
        print(f"\nERROR: Failed to initialize vault: {e}")
        pause()
        return None, vault_path

    print(f"\n✓ Vault created successfully!")
    print(f"  Vault ID: {vault_id}")
    print(f"  Location: {vault_path}")
    print("\nIMPORTANT: Your master password is NOT stored anywhere.")
    print("If you forget it, you'll need recovery shares to regain access.")
    print("\nNext steps:")
    print("  1. Create recovery kit (option 7 in the menu)")
    print("  2. Add your first password (options 2 or 3 in the menu)")
    pause()

    # Keep vault unlocked so user can start using it right away
    return vault, vault_path


def cmd_add_manual(vault: Vault | None, vault_path: str) -> Vault | None:
    clear_screen()
    print("=== Add New Entry (Manual) ===\n")
    vault = require_unlocked(vault, vault_path)
    if vault is None:
        return None

    secret = getpass.getpass("Enter secret to store: ")
    if not secret:
        print("No secret entered, cancelled.")
        pause()
        return vault

    try:
        entry_id = vault.add_entry(secret.encode("utf-8"))
        print(f"\n✓ Entry added successfully!")
        print(f"  Entry ID: {entry_id}")
        print("\nYou can retrieve it later via option 5 (Get entry).")
    except Exception as e:
        print(f"\nERROR: {e}")
    pause()
    return vault


def cmd_add_generated(vault: Vault | None, vault_path: str) -> Vault | None:
    clear_screen()
    print("=== Add New Entry (Generated Password) ===\n")
    vault = require_unlocked(vault, vault_path)
    if vault is None:
        return None

    try:
        length_str = input("Password length [20]: ").strip()
        length = int(length_str) if length_str else 20
    except ValueError:
        print("Invalid length, using default 20.")
        length = 20

    use_symbols_input = input("Include symbols? [Y/n]: ").strip().lower()
    use_symbols = not (use_symbols_input == "n" or use_symbols_input == "no")

    password = crypto.generate_password(length=length, use_symbols=use_symbols)
    print(f"\nGenerated password:\n  {password}")
    print("(This will be stored in the vault.)")

    try:
        entry_id = vault.add_entry(password.encode("utf-8"))
        print(f"\n✓ Entry added successfully!")
        print(f"  Entry ID: {entry_id}")
    except Exception as e:
        print(f"\nERROR: {e}")
    pause()
    return vault


def cmd_list_entries(vault: Vault | None, vault_path: str) -> Vault | None:
    clear_screen()
    print("=== List Entries ===\n")
    vault = require_unlocked(vault, vault_path)
    if vault is None:
        return None

    try:
        entries = vault.list_entries()
        if not entries:
            print("No entries in vault.")
        else:
            print(f"Found {len(entries)} entries:\n")
            for entry in entries:
                created = datetime.fromtimestamp(entry["created_at"]).strftime(
                    "%Y-%m-%d %H:%M"
                )
                print(f"  {entry['id']}")
                print(f"    Created: {created}\n")
    except Exception as e:
        print(f"ERROR: {e}")
    pause()
    return vault


def cmd_get_entry(vault: Vault | None, vault_path: str) -> Vault | None:
    clear_screen()
    print("=== Get Entry ===\n")
    vault = require_unlocked(vault, vault_path)
    if vault is None:
        return None

    entry_id = input("Entry ID: ").strip()
    if not entry_id:
        print("No entry ID provided, cancelled.")
        pause()
        return vault

    try:
        secret = vault.get_entry(entry_id)
        secret_str = secret.decode("utf-8")
        print(f"\nSecret:\n  {secret_str}")

        copy = input("\nCopy to clipboard? [y/N]: ").strip().lower()
        if copy in ("y", "yes"):
            try:
                import pyperclip

                pyperclip.copy(secret_str)
                print("(Copied to clipboard)")
            except ImportError:
                print("(Install 'pyperclip' for clipboard support)")
    except Exception as e:
        print(f"\nERROR: {e}")
    pause()
    return vault


def cmd_verify(vault: Vault | None, vault_path: str) -> Vault | None:
    clear_screen()
    print("=== Verify Audit Log ===\n")
    vault = require_unlocked(vault, vault_path)
    if vault is None:
        return None

    try:
        if vault.verify_audit_log():
            print("✓ Audit log is intact!")
            print("  No tampering detected.")
        else:
            print("✗ AUDIT LOG HAS BEEN TAMPERED!")
            print("  The vault may have been compromised.")
    except Exception as e:
        print(f"\nERROR: {e}")
    pause()
    return vault


def cmd_recovery_create(vault: Vault | None, vault_path: str) -> Vault | None:
    clear_screen()
    print("=== Create Recovery Kit ===\n")
    vault = require_unlocked(vault, vault_path)
    if vault is None:
        return None

    # Threshold and total shares
    try:
        k_str = input("Threshold (shares needed) [3]: ").strip()
        n_str = input("Total shares to create [5]: ").strip()
        k = int(k_str) if k_str else 3
        n = int(n_str) if n_str else 5
    except ValueError:
        print("Invalid numbers, using default k=3, n=5.")
        k, n = 3, 5

    if k > n:
        print("ERROR: Threshold k cannot be greater than total shares n.")
        pause()
        return vault

    # Output file
    default_output = "recovery_kit.txt"
    output_file = input(f"Output file [{default_output}]: ").strip() or default_output

    try:
        print(f"\nGenerating {n} shares (need {k} to recover)...")
        shares = generate_recovery_shares(vault.recovery_key, k, n)
        kit_text = print_recovery_kit(shares, vault.vault_id, k)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(kit_text)

        print(f"\n✓ Recovery kit saved to: {output_file}")
        print("\nIMPORTANT:")
        print("  - Print this file and store shares in separate locations")
        print("  - You need the threshold number of shares to recover")
        print("  - DELETE THIS FILE after printing!")
    except Exception as e:
        print(f"\nERROR: {e}")
    pause()
    return vault


def cmd_lock(vault: Vault | None) -> None:
    clear_screen()
    print("=== Lock Vault ===\n")
    if vault is not None:
        vault.lock()
        print("✓ Vault locked and database connection closed.")
    else:
        print("Vault is already locked / not opened.")
    pause()


def main_menu() -> None:
    vault: Vault | None = None
    vault_path: str = DEFAULT_VAULT_PATH

    while True:
        clear_screen()
        print("SecurePWM - Interactive Menu")
        print("=" * 40)
        print(f"Current vault: {vault_path}")
        print(f"Status: {'UNLOCKED' if vault is not None else 'LOCKED/NOT OPEN'}")
        print("\nChoose an option:")
        print(" 1) Initialize new vault")
        print(" 2) Add password (manual)")
        print(" 3) Add password (generated)")
        print(" 4) List entries")
        print(" 5) Get entry")
        print(" 6) Verify audit log")
        print(" 7) Create recovery kit")
        print(" 8) Change vault file path")
        print(" 9) Lock vault")
        print(" 0) Exit")
        choice = input("\n> ").strip()

        if choice == "1":
            vault, vault_path = cmd_init(vault_path)
        elif choice == "2":
            vault = cmd_add_manual(vault, vault_path)
        elif choice == "3":
            vault = cmd_add_generated(vault, vault_path)
        elif choice == "4":
            vault = cmd_list_entries(vault, vault_path)
        elif choice == "5":
            vault = cmd_get_entry(vault, vault_path)
        elif choice == "6":
            vault = cmd_verify(vault, vault_path)
        elif choice == "7":
            vault = cmd_recovery_create(vault, vault_path)
        elif choice == "8":
            print("\nChange vault path")
            vault_path = choose_vault_path(vault_path)
            pause()
        elif choice == "9":
            cmd_lock(vault)
            vault = None
        elif choice == "0":
            if vault is not None:
                vault.lock()
            print("\nGoodbye!")
            break
        else:
            print("Invalid choice.")
            pause()


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nInterrupted. Exiting...")
        sys.exit(0)
