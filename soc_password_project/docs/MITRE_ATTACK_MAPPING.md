# MITRE ATT&CK Mapping: T1110 Brute Force

This project maps to **T1110 - Brute Force** (Credential Access tactic),
specifically:

| Sub-technique | Name | Where it shows up in this project |
|---|---|---|
| T1110.001 | Password Guessing | `simulate_ssh_attack.py` models repeated single-guess attempts against one account |
| T1110.002 | Password Cracking | `hashing_lab/` - cracking stolen password *hashes* offline with John the Ripper, the core demo of this project |
| T1110.003 | Password Spraying | The simulated attacker trying many usernames with few passwords each, detected via the "distinct_users per IP" logic in `detect_bruteforce.py` |
| T1110.004 | Credential Stuffing | Not directly simulated here, but `password_auditor.py`'s HIBP check is the defensive counter: it identifies passwords already exposed in breaches that attackers reuse for stuffing |

## Why hash choice matters (T1110.002 in practice)

The hashing lab demonstrates *why* T1110.002 succeeds or fails depending on
defender choices, not just attacker effort:

- **Fast hashes (MD5, SHA-256)**: designed for speed, so an attacker with a
  GPU can attempt billions of guesses per second. A weak password behind
  MD5 can fall in seconds.
- **Slow/adaptive hashes (bcrypt, Argon2)**: deliberately expensive per
  guess (tunable work factor), so the same password can take orders of
  magnitude longer to crack even though the *password itself* didn't change.

This is the single most important mitigation a defender controls and the
main variable this project measures and documents with real numbers from
your own lab.

## Detection (Analytic coverage)

| Data Source | ATT&CK Data Component | Detection in this project |
|---|---|---|
| Authentication logs | Logon Session Creation / User Account Authentication | `detect_bruteforce.py`, Wazuse rule `100100`/`100101`, Splunk SPL searches 1-3 |

Detection logic implemented:
1. **Volume-based**: N+ failed logins from one source IP within a time window (classic brute force).
2. **Breadth-based**: many distinct usernames from one source IP in a window (password spraying signal, lower volume per account to avoid simple lockout thresholds).
3. **Correlation / escalation**: a flagged failure burst immediately followed by a success from the same IP - the highest-confidence signal that a brute force attempt worked, and the one that should page a human immediately.

## Mitigations (ATT&CK M-series)

| Mitigation | ID | Applied how |
|---|---|---|
| Account Use Policies (lockout/throttling) | M1036 | Recommended action in detection output: lock/throttle after burst threshold |
| Multi-factor Authentication | M1032 | Noted as the strongest practical defense - brute-forcing the password alone no longer grants access |
| Password Policies | M1027 | What `strong_password.py` / `password_auditor.py` directly enforce: length, entropy, breach-exposure checks |
| Audit | - | `password_auditor.py` against HIBP is a periodic audit control for already-deployed credentials |

## Suggested resume/portfolio phrasing

> "Built an end-to-end brute-force attack & detection lab mapped to MITRE
> ATT&CK T1110: generated and hashed passwords across MD5/SHA-256/bcrypt,
> benchmarked crack times with John the Ripper, simulated SSH brute-force
> and password-spraying activity, and wrote detection logic (Python +
> equivalent Wazuh/Splunk rules) that correctly flagged attacks and
> escalated on likely successful compromise."
