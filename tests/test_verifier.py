"""
Unit tests for verifier.py
"""

import pytest
from src.hashing.hash_generator import generate_bcrypt
from src.hashing.verifier import verify_password

def test_verify_password_success():
    hashed = generate_bcrypt("Password123")
    assert verify_password(
        "Password123",
        hashed,
        "bcrypt",
    )

def test_verify_password_failure():
    hashed = generate_bcrypt("Password123")
    assert not verify_password(
        "WrongPassword",
        hashed,
        "bcrypt",
    )

def test_unsupported_algorithm():
    hashed = generate_bcrypt("Password123")
    with pytest.raises(ValueError):
        verify_password(
            "Password123",
            hashed,
            "md5",
        )