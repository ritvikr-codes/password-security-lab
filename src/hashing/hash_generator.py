"""
hash_generator.py

Provides functions for generating and verifying password hashes using
SHA-256, SHA-512, and bcrypt.

This module is intended for educational purposes to demonstrate secure
password hashing techniques.
"""

import hashlib
import bcrypt

def generate_sha256(password: str) -> str:
    """
    Generate a SHA-256 hash of the given password.

    Args:
        password: The plain-text password.

    Returns:
        A hexadecimal SHA-256 hash string.
    """
    password_bytes = password.encode("utf-8")
    sha256_hash = hashlib.sha256(password_bytes).hexdigest()
    return sha256_hash


def generate_sha512(password: str) -> str:
    """
    Generate a SHA-512 hash of the given password.

    Args:
        password: The plain-text password.

    Returns:
        A hexadecimal SHA-512 hash string.
    """
    password_bytes = password.encode("utf-8")
    sha512_hash = hashlib.sha512(password_bytes).hexdigest()
    return sha512_hash


def generate_bcrypt(password: str) -> bytes:
    """
    Generate a bcrypt hash of the given password.

    bcrypt automatically generates a random salt and embeds it into the
    resulting hash.

    Args:
        password: The plain-text password.

    Returns:
        A bcrypt hash as bytes.
    """
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    bcrypt_hash = bcrypt.hashpw(password_bytes, salt)
    return bcrypt_hash


def verify_bcrypt(password: str, hashed_password: bytes) -> bool:
    """
    Verify whether a password matches a stored bcrypt hash.

    Args:
        password: The plain-text password entered by the user.
        hashed_password: The stored bcrypt hash.

    Returns:
        True if the password matches the hash, otherwise False.
    """
    password_bytes = password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_password)
