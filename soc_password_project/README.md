# Password Security Lab: Generation, Cracking, and Brute-Force Detection

A self-contained lab covering password security from both sides: how to
generate/audit strong credentials, how hash choice affects real
cracking time (John the Ripper), and how to detect brute-force attacks
against them. Mapped to **MITRE ATT&CK T1110 (Brute Force)**.

## Project structure

```
soc_password_project/
├── hashing_lab/
│   ├── strong_password.py     # secure password generator (secrets module)
│   ├── generate_hashes.py     # builds weak/medium/strong password set, hashes with MD5/SHA-256/bcrypt
│   └── plot_results.py        # charts crack-time results after you run John/Hashcat
├── password_auditor/
│   └── auditor.py             # checks passwords against HIBP (k-anonymity) + weak-pattern heuristics
├── brute_force_detection/
│   ├── simulate_ssh_attack.py # generates a synthetic auth.log with an injected brute-force burst
│   ├── detect_bruteforce.py   # Python detection logic (volume + spraying + success-after-burst)
│   ├── wazuh_rule_example.xml # the same detection logic as a Wazuh custom rule
│   └── splunk_spl_example.txt # the same detection logic as Splunk SPL searches
└── docs/
    └── MITRE_ATTACK_MAPPING.md
```

## How to run it end to end

### 1. Generate passwords and hashes
```bash
cd hashing_lab
pip install bcrypt --break-system-packages
python3 generate_hashes.py
```
This writes `output/md5_hashes.txt`, `sha256_hashes.txt`, `bcrypt_hashes.txt`,
and a `results_template.csv` to fill in.

### 2. Crack them with John the Ripper (in your own isolated VM)
```bash
time john --format=Raw-MD5 output/md5_hashes.txt
time john --format=Raw-SHA256 output/sha256_hashes.txt
time john --format=bcrypt output/bcrypt_hashes.txt
```
Record each run's wall-clock time against the matching rows in
`results_template.csv` (rename it to `results.csv`), then:
```bash
pip install matplotlib --break-system-packages
python3 plot_results.py
```
This produces `chart_time_by_algorithm.png` and `chart_entropy_vs_time.png`
for your writeup.

### 3. Audit a password against real breach data
```bash
cd ../password_auditor
python3 auditor.py "MyCandidatePassword123!"
```

### 4. Simulate and detect a brute-force attack
```bash
cd ../brute_force_detection
python3 simulate_ssh_attack.py
python3 detect_bruteforce.py output/auth.log
```
Compare the Python output against the equivalent logic in
`wazuh_rule_example.xml` and `splunk_spl_example.txt` to see the same
detection expressed in three different tools.

## What to put in your writeup/README on GitHub

- A table of your actual crack times per algorithm (from step 2) - the
  core finding: identical passwords, wildly different crack times
  depending purely on hashing algorithm.
- Screenshots of the detection script flagging the simulated attack.
- The MITRE mapping from `docs/MITRE_ATTACK_MAPPING.md`.
- A short "lessons learned" section: why MFA matters even when passwords
  are strong, why slow hashes matter even when passwords are weak, and
  why detection matters as a second layer when prevention fails.

## Safety note

Only run John the Ripper, Hashcat, or any brute-force simulation against
systems and credentials you own or have explicit written permission to
test, inside an isolated lab/VM. `simulate_ssh_attack.py` only ever
generates synthetic log text - it never touches a real SSH service.
