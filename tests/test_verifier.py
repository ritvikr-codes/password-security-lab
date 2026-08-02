"""
Unit tests for verifier.py
"""

import sys
import os

# Make src/ importable when running pytest from the project root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from hashing.hash_generator import generate_bcrypt
from hashing.verifier import verify_password

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