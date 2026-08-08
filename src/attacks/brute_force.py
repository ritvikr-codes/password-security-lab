"""
brute_force.py

Implements brute-force attacks against password hashes.
"""

import itertools
import time

from ..hashing.hash_generator import (
    generate_sha256,
    generate_sha512,
)

def crack_sha256(
    target_hash: str,
    charset: str,
    max_length: int,
) -> dict:
    """
    Brute-force a SHA-256 hash and return attack statistics.
    """
    attempts = 0
    start_time = time.perf_counter()
    for length in range(1, max_length + 1):
        for chars in itertools.product(charset, repeat=length):
            password = "".join(chars)
            attempts += 1
            if generate_sha256(password) == target_hash:
                elapsed_time = time.perf_counter() - start_time
                return {
                    "password": password,
                    "attempts": attempts,
                    "time": elapsed_time,
                    "attempts_per_second": attempts / elapsed_time
                    if elapsed_time > 0
                    else 0,
                }
    elapsed_time = time.perf_counter() - start_time
    return {
        "password": None,
        "attempts": attempts,
        "time": elapsed_time,
        "attempts_per_second": attempts / elapsed_time
        if elapsed_time > 0
        else 0,
    }

def crack_sha512(
    target_hash: str,
    charset: str,
    max_length: int,
) -> dict:
    """
    Brute-force a SHA-512 hash and return attack statistics.
    """
    attempts = 0
    start_time = time.perf_counter()

    for length in range(1, max_length + 1):
        for chars in itertools.product(charset, repeat=length):
            password = "".join(chars)
            attempts += 1
            if generate_sha512(password) == target_hash:
                elapsed_time = time.perf_counter() - start_time
                return {
                    "password": password,
                    "attempts": attempts,
                    "time": elapsed_time,
                    "attempts_per_second": attempts / elapsed_time
                    if elapsed_time > 0
                    else 0,
                }
    elapsed_time = time.perf_counter() - start_time

    return {
        "password": None,
        "attempts": attempts,
        "time": elapsed_time,
        "attempts_per_second": attempts / elapsed_time
        if elapsed_time > 0
        else 0,
    }