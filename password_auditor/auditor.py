#!/usr/bin/env python3
"""
Password Auditor
- Checks a password against the Have I Been Pwned Pwned Passwords API
  using k-anonymity (only the first 5 chars of the SHA-1 hash ever leave
  your machine - the full password and full hash never go over the wire).
- Flags common weak patterns heuristically (sequential chars, keyboard
  walks, repeated chars, common words).

Usage:
    python3 auditor.py "SomePassword123!"
    python3 auditor.py --file passwords.txt   # one password per line
"""
import argparse
import hashlib
import re
import sys
import urllib.request

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"

COMMON_WORDS = {
    "password", "letmein", "qwerty", "dragon", "football", "monkey",
    "admin", "welcome", "login", "princess", "abc123",
}

KEYBOARD_WALKS = [
    "qwerty", "asdf", "zxcv", "qazwsx", "1qaz", "qwertyuiop",
]


def check_hibp(password):
    """Returns the number of times this password has appeared in known
    breaches, using k-anonymity so the real password never leaves the
    machine. Returns None if the lookup failed (e.g. no network)."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        req = urllib.request.Request(
            HIBP_RANGE_URL.format(prefix=prefix),
            headers={"User-Agent": "soc-password-auditor"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()
    except Exception as e:
        print(f"  [!] HIBP lookup failed: {e}", file=sys.stderr)
        return None

    for line in body.splitlines():
        line_suffix, count = line.split(":")
        if line_suffix == suffix:
            return int(count)
    return 0


def check_patterns(password):
    """Heuristic weak-pattern checks. Returns a list of warning strings."""
    warnings = []
    lower = password.lower()

    if len(password) < 12:
        warnings.append(f"Short password ({len(password)} chars) - aim for 16+")

    if lower in COMMON_WORDS or any(w in lower for w in COMMON_WORDS):
        warnings.append("Contains a common dictionary word")

    if any(walk in lower for walk in KEYBOARD_WALKS):
        warnings.append("Contains a keyboard-walk pattern (e.g. qwerty, asdf)")

    if re.search(r"(.)\1{2,}", password):
        warnings.append("Contains 3+ repeated characters in a row")

    # sequential ascending/descending runs of 4+ (digits or letters)
    seq = "abcdefghijklmnopqrstuvwxyz0123456789"
    for i in range(len(lower) - 3):
        chunk = lower[i:i + 4]
        if chunk in seq or chunk[::-1] in seq:
            warnings.append(f"Contains a sequential run: '{chunk}'")
            break

    if re.fullmatch(r"[a-zA-Z]+\d{1,4}", password):
        warnings.append("Matches common 'Word + short number' pattern (e.g. Spring2024)")

    if not warnings:
        warnings.append(None)  # marker for "no pattern issues found"
    return [w for w in warnings if w]


def audit_one(password, check_breach=True):
    print(f"\nPassword: {'*' * len(password)} ({len(password)} chars)")

    pattern_warnings = check_patterns(password)
    if pattern_warnings:
        for w in pattern_warnings:
            print(f"  [WARN] {w}")
    else:
        print("  [OK] No obvious weak patterns detected")

    if check_breach:
        count = check_hibp(password)
        if count is None:
            print("  [?] Breach check unavailable")
        elif count > 0:
            print(f"  [BREACH] Seen {count:,} times in known data breaches - do not use")
        else:
            print("  [OK] Not found in known breach data")


def main():
    parser = argparse.ArgumentParser(description="Audit password strength + breach exposure")
    parser.add_argument("password", nargs="?", help="Password to check")
    parser.add_argument("--file", help="File with one password per line")
    parser.add_argument("--no-breach-check", action="store_true",
                         help="Skip the HIBP network lookup (offline pattern check only)")
    args = parser.parse_args()

    if not args.password and not args.file:
        parser.error("Provide a password or --file")

    if args.password:
        audit_one(args.password, check_breach=not args.no_breach_check)

    if args.file:
        with open(args.file) as f:
            for line in f:
                pw = line.strip()
                if pw:
                    audit_one(pw, check_breach=not args.no_breach_check)


if __name__ == "__main__":
    main()
