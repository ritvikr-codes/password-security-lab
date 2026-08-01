"""
test_hash_generator.py

Unit tests for the hash_generator module, verifying that SHA-256,
SHA-512, and bcrypt hashing and verification behave correctly.

These tests confirm:
    - Hash functions are deterministic where expected (SHA-256, SHA-512).
    - Hash functions produce correct, known output for fixed input.
    - bcrypt hashes are salted and therefore non-deterministic.
    - Password verification correctly accepts valid passwords and
      rejects invalid ones.

Run with:
    pytest tests/test_hash_generator.py -v
"""

import sys
import os

# Make src/ importable when running pytest from the project root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hashing.hash_generator import (
    generate_sha256,
    generate_sha512,
    generate_bcrypt,
    verify_bcrypt,
)

def test_sha256_is_deterministic():
    """
    Verify that hashing the same password with SHA-256 twice produces
    the same hash both times.

    This confirms SHA-256 has no built-in randomness (no salt) --
    which is exactly why it is unsafe for password storage on its own.
    """
    password = "Password123"
    first_hash = generate_sha256(password)
    second_hash = generate_sha256(password)
    assert first_hash == second_hash

def test_sha256_known_value():
    """
    Verify that generate_sha256() produces the correct, independently
    known SHA-256 hash for a fixed input password.

    This catches the case where the function runs without error but
    computes the wrong value (a bug that determinism alone would not
    detect).
    """
    password = "password"
    expected_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    assert generate_sha256(password) == expected_hash

def test_sha256_different_passwords_differ():
    """
    Verify that two different passwords produce two different
    SHA-256 hashes.
    """
    hash_one = generate_sha256("password1")
    hash_two = generate_sha256("password2")
    assert hash_one != hash_two

def test_sha512_is_deterministic():
    """
    Verify that hashing the same password with SHA-512 twice produces
    the same hash both times, for the same reason as SHA-256.
    """
    password = "Password123"
    first_hash = generate_sha512(password)
    second_hash = generate_sha512(password)
    assert first_hash == second_hash

def test_sha512_produces_correct_length():
    """
    Verify that generate_sha512() always returns a 128-character
    hexadecimal string, since SHA-512 produces a fixed-size 512-bit
    digest regardless of input length.
    """
    hashed_password = generate_sha512("anything")
    assert len(hashed_password) == 128

def test_bcrypt_hashes_are_salted():
    """
    Verify that hashing the same password with bcrypt twice produces
    two different hashes.

    This confirms bcrypt's built-in random salting is working -- the
    entire reason bcrypt resists rainbow table attacks where SHA-256
    and SHA-512 do not.
    """
    password = "Password123"
    hash_one = generate_bcrypt(password)
    hash_two = generate_bcrypt(password)
    assert hash_one != hash_two

def test_bcrypt_verify_correct_password():
    """
    Verify that verify_bcrypt() returns True when the correct
    plain-text password is checked against its own bcrypt hash.
    """
    password = "Password123"
    hashed_password = generate_bcrypt(password)
    assert verify_bcrypt(password, hashed_password) is True

def test_bcrypt_verify_wrong_password_fails():
    """
    Verify that verify_bcrypt() returns False when an incorrect
    plain-text password is checked against a bcrypt hash it does not
    match.
    """
    password = "Password123"
    hashed_password = generate_bcrypt(password)
    assert verify_bcrypt("WrongPassword", hashed_password) is False

def test_bcrypt_verify_empty_password_fails():
    """
    Verify that verify_bcrypt() returns False for an empty string
    password, confirming the function does not accidentally accept
    blank input as a match.
    """
    hashed_password = generate_bcrypt("Password123")
    assert verify_bcrypt("", hashed_password) is False