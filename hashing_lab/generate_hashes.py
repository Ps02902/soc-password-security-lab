#!/usr/bin/env python3
"""
Hashing Lab - generates passwords of varying strength and hashes them
with MD5, SHA-256, and bcrypt, producing files formatted for John the
Ripper / Hashcat so you can benchmark how hash choice + password strength
affect crack time.

Usage:
    pip install bcrypt --break-system-packages
    python3 generate_hashes.py

Outputs (in ./output/):
    passwords_plaintext.csv   - the generated passwords + metadata (keep private!)
    md5_hashes.txt            - "user:hash" format for `john --format=Raw-MD5`
    sha256_hashes.txt         - "user:hash" format for `john --format=Raw-SHA256`
    bcrypt_hashes.txt         - "user:hash" format for `john --format=bcrypt`
    results_template.csv      - fill this in after cracking, for your report/charts
"""
import csv
import hashlib
import math
import os
import secrets
import string

try:
    import bcrypt
except ImportError:
    bcrypt = None

SYMBOLS = "!@#$%^&*()-_=+"
OUT_DIR = os.path.join(os.path.dirname(__file__), "output")


def random_from(alphabet, n):
    return "".join(secrets.choice(alphabet) for _ in range(n))


def build_test_set():
    """A deliberately varied set of passwords: weak dictionary-style,
    medium human-style, and strong random, at a few lengths each."""
    weak_bases = ["password", "dragon", "football", "qwerty", "letmein"]
    passwords = []

    # Weak: raw dictionary words / classic patterns (will fall almost instantly)
    for w in weak_bases:
        passwords.append((w, "weak_dictionary"))
        passwords.append((w.capitalize() + "123", "weak_mutated"))

    # Medium: human-style passphrase-ish, 10-12 chars, some complexity
    for _ in range(5):
        word = secrets.choice(weak_bases).capitalize()
        passwords.append((f"{word}{secrets.randbelow(100)}!", "medium_human"))

    # Strong: fully random at increasing lengths
    alphabet = string.ascii_letters + string.digits + SYMBOLS
    for length in (12, 16, 20, 24):
        passwords.append((random_from(alphabet, length), f"strong_random_{length}"))

    return passwords


def entropy_bits(pw):
    charset = 0
    if any(c.islower() for c in pw):
        charset += 26
    if any(c.isupper() for c in pw):
        charset += 26
    if any(c.isdigit() for c in pw):
        charset += 10
    if any(c in SYMBOLS for c in pw):
        charset += len(SYMBOLS)
    charset = max(charset, 1)
    return round(len(pw) * math.log2(charset), 1)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    test_set = build_test_set()

    plaintext_rows = []
    md5_lines, sha256_lines, bcrypt_lines = [], [], []

    for i, (pw, label) in enumerate(test_set):
        user = f"user{i:02d}_{label}"

        md5_hash = hashlib.md5(pw.encode()).hexdigest()
        sha256_hash = hashlib.sha256(pw.encode()).hexdigest()

        md5_lines.append(f"{user}:{md5_hash}")
        sha256_lines.append(f"{user}:{sha256_hash}")

        if bcrypt:
            bcrypt_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()
            bcrypt_lines.append(f"{user}:{bcrypt_hash}")
        else:
            bcrypt_hash = "(bcrypt not installed - pip install bcrypt --break-system-packages)"

        plaintext_rows.append({
            "user": user,
            "password": pw,
            "label": label,
            "length": len(pw),
            "entropy_bits": entropy_bits(pw),
            "md5": md5_hash,
            "sha256": sha256_hash,
            "bcrypt": bcrypt_hash,
        })

    with open(os.path.join(OUT_DIR, "passwords_plaintext.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=plaintext_rows[0].keys())
        writer.writeheader()
        writer.writerows(plaintext_rows)

    with open(os.path.join(OUT_DIR, "md5_hashes.txt"), "w") as f:
        f.write("\n".join(md5_lines) + "\n")

    with open(os.path.join(OUT_DIR, "sha256_hashes.txt"), "w") as f:
        f.write("\n".join(sha256_lines) + "\n")

    if bcrypt:
        with open(os.path.join(OUT_DIR, "bcrypt_hashes.txt"), "w") as f:
            f.write("\n".join(bcrypt_lines) + "\n")

    with open(os.path.join(OUT_DIR, "results_template.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["user", "label", "length", "entropy_bits", "algorithm",
                          "cracked", "time_to_crack_seconds", "method_used"])
        for row in plaintext_rows:
            for algo in (["md5", "sha256", "bcrypt"] if bcrypt else ["md5", "sha256"]):
                writer.writerow([row["user"], row["label"], row["length"],
                                  row["entropy_bits"], algo, "", "", ""])

    print(f"Done. Files written to {OUT_DIR}/")
    print("Next steps:")
    print(f"  john --format=Raw-MD5 {OUT_DIR}/md5_hashes.txt")
    print(f"  john --format=Raw-SHA256 {OUT_DIR}/sha256_hashes.txt")
    if bcrypt:
        print(f"  john --format=bcrypt {OUT_DIR}/bcrypt_hashes.txt")
    print("Time each run (e.g. with `time john ...`), record results in results_template.csv,")
    print("then run plot_results.py to generate charts for your writeup.")


if __name__ == "__main__":
    main()
