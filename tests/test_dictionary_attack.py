from hashing.hash_generator import generate_sha256
from attacks.dictionary_attack import crack_sha256

def test_dictionary_attack_sha256():
    password = "Password123"
    target_hash = generate_sha256(password)
    wordlist = [
        "123456",
        "password",
        "admin",
        "Password123",
        "welcome",
    ]
    cracked = crack_sha256(target_hash, wordlist)
    assert cracked == password