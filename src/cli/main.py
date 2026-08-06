"""
main.py

Command-line interface for the Password Security Lab.
"""

import argparse
from ..hashing.hash_generator import (
    generate_sha256,
    generate_sha512,
    generate_bcrypt,
)

from ..attacks.dictionary_attack import (
    crack_sha256,
    crack_sha512,
    crack_bcrypt,
)

from ..utils.wordlist_loader import load_wordlist

def hash_command(args):
    """Handle the 'hash' command."""
    if args.algorithm == "sha256":
        hashed = generate_sha256(args.password)
    elif args.algorithm == "sha512":
        hashed = generate_sha512(args.password)
    else:
        hashed = generate_bcrypt(args.password).decode("utf-8")

    print("\nHash generated successfully!\n")
    print(f"Algorithm : {args.algorithm}")
    print(f"Password  : {args.password}")
    print(f"Hash      : {hashed}")

def dictionary_command(args):
    """Handle the dictionary attack command."""

    wordlist = load_wordlist(args.wordlist)
    print("\nDictionary Attack\n")
    print(f"Loaded {len(wordlist)} passwords.\n")
    if args.algorithm == "sha256":
        result = crack_sha256(args.hash, wordlist)
    elif args.algorithm == "sha512":
        result = crack_sha512(args.hash, wordlist)
    else:
        result = crack_bcrypt(
            args.hash.encode("utf-8"),
            wordlist,
        )

    if result is None:
        print("Password not found.")
    else:
        print("SUCCESS!")
        print(f"Recovered password : {result}")

def main():
    parser = argparse.ArgumentParser(
        description="Password Security Lab"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # hash command
    hash_parser = subparsers.add_parser(
        "hash",
        help="Generate password hashes",
    )

    hash_parser.add_argument(
        "password",
        help="Password to hash",
    )

    hash_parser.add_argument(
        "--algorithm",
        choices=["sha256", "sha512", "bcrypt"],
        default="sha256",
        help="Hashing algorithm",
    )

    hash_parser.set_defaults(func=hash_command)
    # dictionary command
    dictionary_parser = subparsers.add_parser(
        "dictionary",
        help="Run a dictionary attack",
    )

    dictionary_parser.add_argument(
        "--algorithm",
        required=True,
        choices=["sha256", "sha512", "bcrypt"],
    )

    dictionary_parser.add_argument(
        "--hash",
        required=True,
    )

    dictionary_parser.add_argument(
        "--wordlist",
        required=True,
    )

    dictionary_parser.set_defaults(
        func=dictionary_command
    )
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()