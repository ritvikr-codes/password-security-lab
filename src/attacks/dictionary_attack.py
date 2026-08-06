"""
dictionary_attack.py

Implements dictionary attacks against password hashes.
"""

from ..hashing.hash_generator import (
    generate_sha256,
    generate_sha512,
    verify_bcrypt,
)

def crack_sha256(target_hash: str, wordlist: list[str]) -> str | None:
    """
    Attempt to crack a SHA-256 hash using a dictionary attack.
    """
    for password in wordlist:
        if generate_sha256(password) == target_hash:
            return password
    return None

def crack_sha512(target_hash: str, wordlist: list[str]) -> str | None:
    """
    Attempt to crack a SHA-512 hash using a dictionary attack.
    """
    for password in wordlist:
        if generate_sha512(password) == target_hash:
            return password
    return None

def crack_bcrypt(target_hash: bytes, wordlist: list[str]) -> str | None:
    """
    Attempt to crack a bcrypt hash using a dictionary attack.
    """
    for password in wordlist:
        if verify_bcrypt(password, target_hash):
            return password
    return None