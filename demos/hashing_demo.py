"""
Educational password-hashing demonstration (SEPARATE from the analyzer).

    password -> + unique random salt -> slow password-hashing function -> stored hash

This file shows how a login system SHOULD store passwords, using Argon2id
(winner of the Password Hashing Competition, recommended by OWASP).
It uses a SYNTHETIC demo password only and is never connected to the
analyzer: passwords typed into the analyzer are never hashed or stored.

Key ideas:
  * Hashing is ONE-WAY. To log someone in, hash what they typed (with the
    stored salt and parameters) and compare. Nothing is ever "decrypted".
  * Encryption is TWO-WAY: anyone holding the key can recover the plaintext.
    That is why encryption is the wrong tool for storing passwords.
  * A random salt makes identical passwords produce different hashes and
    defeats precomputed ("rainbow") tables.
  * Argon2id is deliberately slow and memory-hard, which makes offline
    guessing expensive. Fast general-purpose hashes (MD5, SHA-1, SHA-256)
    are designed for speed - which helps attackers - so they are not suitable
    on their own for password storage.

Run from the project root:
    python demos/hashing_demo.py
"""

import hashlib
import hmac
import os
import time

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
except ImportError:  # pragma: no cover
    PasswordHasher = None

# Clearly synthetic value - never use a real password in demos.
DEMO_PASSWORD = "demo-only-maple-orbit-lantern"

# Parameters close to OWASP's Argon2id recommendation (m=19 MiB, t=2, p=1).
_hasher = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1) if PasswordHasher else None


def hash_password(password: str) -> str:
    """
    Hash a password for storage with Argon2id.

    The returned string encodes algorithm, parameters, salt and hash, e.g.
    $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
    """
    if _hasher is not None:
        return _hasher.hash(password)
    # Fallback (standard library): scrypt, another memory-hard function.
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(stored_hash: str, candidate: str) -> bool:
    """Return True if `candidate` matches the stored hash (constant-time compare)."""
    if stored_hash.startswith("$argon2") and _hasher is not None:
        try:
            return _hasher.verify(stored_hash, candidate)
        except VerifyMismatchError:
            return False
    _, salt_hex, digest_hex = stored_hash.split("$")
    digest = hashlib.scrypt(candidate.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
    return hmac.compare_digest(digest.hex(), digest_hex)


def main() -> None:
    print("=== Password hashing demo (synthetic password only) ===\n")
    print("Algorithm:", "Argon2id (argon2-cffi)" if _hasher else "scrypt (stdlib fallback)")

    start = time.perf_counter()
    hash_1 = hash_password(DEMO_PASSWORD)
    elapsed_ms = (time.perf_counter() - start) * 1000
    hash_2 = hash_password(DEMO_PASSWORD)

    print("\n1) Same password hashed twice -> different results (random salt):")
    print("   hash #1:", hash_1)
    print("   hash #2:", hash_2)
    print("   identical?", hash_1 == hash_2)

    print("\n2) Verification is one-way: re-hash the candidate and compare")
    print("   correct password  ->", verify_password(hash_1, DEMO_PASSWORD))
    print("   wrong password    ->", verify_password(hash_1, "demo-only-wrong-guess"))

    print("\n3) Cost per hash")
    print(f"   one Argon2id/scrypt hash took about {elapsed_ms:.0f} ms on this machine")
    start = time.perf_counter()
    for _ in range(10_000):
        hashlib.sha256(DEMO_PASSWORD.encode()).digest()
    sha_ms = (time.perf_counter() - start) * 1000 / 10_000
    print(f"   one plain SHA-256 hash took about {sha_ms * 1000:.2f} microseconds")
    print("   -> a fast hash lets an attacker test vastly more guesses per second offline,")
    print("      which is why password storage uses slow, salted, memory-hard functions.")


if __name__ == "__main__":
    main()
