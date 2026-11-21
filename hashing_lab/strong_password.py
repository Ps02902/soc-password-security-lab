#!/usr/bin/env python3
"""Strong password generator using the OS's cryptographically secure RNG."""
import argparse
import math
import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"


def generate_password(length=20, use_symbols=True):
    """Random password; guarantees at least one of each character class."""
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if use_symbols:
        pools.append(SYMBOLS)
    alphabet = "".join(pools)

    if length < len(pools):
        raise ValueError(f"Length must be at least {len(pools)}")

    # One guaranteed char from each pool, rest from the full alphabet
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(alphabet) for _ in range(length - len(pools))]
    secrets.SystemRandom().shuffle(chars)  # remove predictable ordering
    return "".join(chars), len(alphabet)


def entropy_bits(length, alphabet_size):
    return length * math.log2(alphabet_size)


def generate_passphrase(wordlist_path, words=6):
    """Diceware-style passphrase from a wordlist file (one word per line)."""
    with open(wordlist_path) as f:
        wordlist = [w.strip() for w in f if w.strip()]
    phrase = "-".join(secrets.choice(wordlist) for _ in range(words))
    return phrase, words * math.log2(len(wordlist))


def main():
    parser = argparse.ArgumentParser(description="Strong password generator")
    parser.add_argument("-l", "--length", type=int, default=20)
    parser.add_argument("--no-symbols", action="store_true")
    parser.add_argument("--wordlist", help="Path to wordlist for passphrase mode")
    parser.add_argument("--words", type=int, default=6)
    args = parser.parse_args()

    if args.wordlist:
        secret, bits = generate_passphrase(args.wordlist, args.words)
    else:
        secret, size = generate_password(args.length, not args.no_symbols)
        bits = entropy_bits(args.length, size)

    print(f"Generated : {secret}")
    print(f"Entropy   : ~{bits:.0f} bits")
    if bits < 60:
        print("Rating    : Weak - increase length")
    elif bits < 80:
        print("Rating    : Decent")
    elif bits < 100:
        print("Rating    : Strong")
    else:
        print("Rating    : Excellent (infeasible to brute-force)")


if __name__ == "__main__":
    main()
