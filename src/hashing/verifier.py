"""
verifier.py

Provides a unified interface for verifying password hashes.
"""

from .hash_generator import verify_bcrypt
def verify_password (
    password: str,
    hashed_password: bytes,
    algorithm: str,
) -> bool:
    """
    Verify a password using the specified hashing algorithm.
    Args:
        password:
            Plain-text password entered by the user.

        hashed_password:
            Stored password hash.

        algorithm:
            Hashing algorithm.

    Returns:
        True if verification succeeds.
        False otherwise.
    """

    algorithm = algorithm.lower()
    if algorithm == "bcrypt":
        return verify_bcrypt(password, hashed_password)
    raise ValueError(
        f"Unsupported algorithm: {algorithm}"
    )