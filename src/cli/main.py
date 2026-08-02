"""
main.py

Command-line interface for the Password-Security Lab
"""

import argparse

from src.hashing.hash_generator import (
    generate_sha256,
    generate_sha512,
    generate_bcrypt,
)

parser = argparse.ArgumentParser(
    description="Password Security Lab CLI"
)
parser.add_argument(
    "password",
    help="Password to hash"
)
parser.add_argument(
    "--algorithm",
    choices=["sha256", "sha512", "bcrypt"],
    default="sha256",
    help="Hashing algorithm to use"
)
args = parser.parse_args()
if args.algorithm == "sha256":
    hashed_password = generate_sha256(args.password)

elif args.algorithm == "sha512":
    hashed_password = generate_sha512(args.password)

else:
    hashed_password = generate_bcrypt(args.password).decode("utf-8")
print("\nHash generated successfully!\n")
print(f"Algorithm : {args.algorithm}")
print(f"Hash      : {hashed_password}")
