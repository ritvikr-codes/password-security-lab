"""
wordlist_loader.py

Utilities for loading password wordlists.
"""

from pathlib import Path
def load_wordlist(path: str) -> list[str]:
    """
    Load a wordlist from a text file.

    Args:
        path: Path to the wordlist file.

    Returns:
        A list of passwords.
    """
    with Path(path).open("r", encoding="utf-8") as file:
        return [
            line.strip()
            for line in file
            if line.strip()
        ]