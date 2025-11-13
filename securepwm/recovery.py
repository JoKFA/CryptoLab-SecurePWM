"""
SecurePWM - Recovery Module (Shamir Secret Sharing)

This implements k-of-n recovery:
- Split recovery key into n shares
- Any k shares can reconstruct the key
- Fewer than k shares reveal NOTHING

Example: 3-of-5 scheme
- Generate 5 shares
- Print them on paper
- Any 3 shares can recover the vault
- Losing 2 shares is okay!

Use case: Disaster recovery if you forget master password
"""

from typing import List
from shamir_mnemonic import shamir


def generate_recovery_shares(recovery_key: bytes, k: int, n: int) -> List[List[str]]:
    """
    Split recovery key into n shares (need k to recover).

    Args:
        recovery_key: 32-byte key from derive_subkeys()
        k: Threshold (minimum shares needed)
        n: Total number of shares to create

    Returns:
        List of n shares (each share is list of mnemonic words)

    Example:
        >>> recovery_key = os.urandom(32)
        >>> shares = generate_recovery_shares(recovery_key, k=3, n=5)
        >>> len(shares)  # 5 shares
        5
        >>> len(shares[0])  # Each share is ~20 words
        20

    Security:
        - Need exactly k shares to reconstruct
        - k-1 shares give ZERO information
        - Based on Shamir Secret Sharing (polynomial interpolation)
    """
    if k > n:
        raise ValueError(f"k ({k}) cannot be greater than n ({n})")

    if k < 2:
        raise ValueError(f"k must be at least 2")

    if n > 16:
        raise ValueError(f"n cannot exceed 16 (library limitation)")

    # Generate shares using SLIP-0039 (Shamir's Secret Sharing with mnemonics)
    # Groups: We use one group with threshold=k and member_threshold=k
    groups = shamir.generate_mnemonics(
        group_threshold=1,  # Need 1 group
        groups=[(k, n)],    # One group with k-of-n threshold
        master_secret=recovery_key
    )

    # Return shares from the single group
    return groups[0]


def combine_recovery_shares(shares: List[str]) -> bytes:
    """
    Reconstruct recovery key from k shares.

    Args:
        shares: List of mnemonic word lists (at least k shares)

    Returns:
        32-byte recovery key

    Raises:
        Exception: If shares are invalid or insufficient

    Example:
        >>> # User inputs 3 shares (out of 5)
        >>> shares_input = [shares[0], shares[2], shares[4]]
        >>> recovered_key = combine_recovery_shares(shares_input)
        >>> recovered_key == recovery_key
        True
    """
    try:
        # Combine shares using SLIP-0039
        recovered = shamir.combine_mnemonics(shares)
        return recovered
    except Exception as e:
        raise Exception(f"Failed to combine shares: {e}")


def print_recovery_kit(shares: List[List[str]], vault_id: str, k: int) -> str:
    """
    Format recovery shares for printing.

    Returns formatted text that can be printed on paper.

    Args:
        shares: Recovery shares
        vault_id: UUID of vault
        k: Threshold (how many shares needed)

    Returns:
        Formatted string ready for printing

    Example:
        >>> text = print_recovery_kit(shares, vault_id, k=3)
        >>> print(text)
        >>> # Or save to file:
        >>> with open("recovery_kit.txt", "w") as f:
        ...     f.write(text)
    """
    output = []
    output.append("=" * 70)
    output.append("SecurePWM RECOVERY KIT")
    output.append("=" * 70)
    output.append(f"\nVault ID: {vault_id}")
    output.append(f"Threshold: Need {k} of {len(shares)} shares to recover")
    output.append("\nIMPORTANT:")
    output.append("- Print this document and store shares in separate secure locations")
    output.append("- Any {k} shares can recover your vault if you forget the master password")
    output.append("- Losing fewer than {k} shares is okay")
    output.append("- NEVER store all shares together!\n")
    output.append("=" * 70)

    for i, share in enumerate(shares, 1):
        output.append(f"\n\nSHARE {i} of {len(shares)}")
        output.append("-" * 70)
        # Join mnemonic words with spaces
        output.append(" ".join(share))
        output.append("\n" + "-" * 70)

    output.append("\n\nTo recover:")
    output.append("1. Run: spwm recover")
    output.append("2. Enter any {k} shares when prompted")
    output.append("3. Set a new master password\n")

    return "\n".join(output)


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

if __name__ == "__main__":
    import os

    # Simulate recovery key
    recovery_key = os.urandom(32)
    print(f"Original recovery key: {recovery_key.hex()[:32]}...")

    # Generate 3-of-5 shares
    print("\nGenerating 3-of-5 recovery shares...")
    shares = generate_recovery_shares(recovery_key, k=3, n=5)

    print(f"Generated {len(shares)} shares")
    print(f"Share 1 (first few words): {' '.join(shares[0][:5])}...")

    # Recover using 3 shares
    print("\nRecovering from shares 1, 3, and 5...")
    recovered = combine_recovery_shares([shares[0], shares[2], shares[4]])

    print(f"Recovered key: {recovered.hex()[:32]}...")
    print(f"Match: {recovered == recovery_key}")

    # Print recovery kit
    print("\n" + "=" * 70)
    print(print_recovery_kit(shares, "test-vault-123", k=3))
