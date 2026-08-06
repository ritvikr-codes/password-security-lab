from src.utils.wordlist_loader import load_wordlist


def test_load_wordlist():
    words = load_wordlist("wordlists/common_passwords.txt")

    assert "password" in words
    assert "admin" in words
    assert len(words) >= 10