from src.attacks.brute_force import (
    crack_sha256,
    crack_sha512,
)

from src.hashing.hash_generator import (
    generate_sha256,
    generate_sha512,
)

def test_bruteforce_sha256_success():
    password = "ab"
    target = generate_sha256(password)
    result = crack_sha256(
        target,
        charset="abc",
        max_length=2,
    )
    assert result["password"] == password
    assert result["attempts"] > 0
    assert result["time"] >= 0
    assert result["attempts_per_second"] >= 0

def test_bruteforce_sha256_failure():
    target = generate_sha256("zz")
    result = crack_sha256(
        target,
        charset="abc",
        max_length=2,
    )
    assert result["password"] is None
    assert result["attempts"] == 12

def test_bruteforce_sha512_success():
    password = "ba"
    target = generate_sha512(password)
    result = crack_sha512(
        target,
        charset="abc",
        max_length=2,
    )
    assert result["password"] == password
    assert result["attempts"] > 0