"""
brute_force.py

Implements brute-force attacks against password hashes.
"""

import itertools

from ..hashing.hash_generator import (
    generate_sha256,
    generate_sha512,
)

def crack_sha256(target_hash: str,
                 charset: str,
                 max_length: int) -> str | None:
    
    # Brute-force a SHA-256 hash.
    for length in range(1, max_length + 1):
        for chars in itertools.product(charset, repeat=length):
            password = "".join(chars)
            if generate_sha256(password) == target_hash:
                return password
    return None

def crack_sha512(target_hash: str, charset: str, max_length: int) -> str | None:

    # Brute-force a SHA-512 hash.
    for length in range(1, max_length + 1):
        for chars in itertools.product(charset, repeat=length):
            password = "".join(chars)
            if generate_sha512(password) == target_hash:
                return password
    return None