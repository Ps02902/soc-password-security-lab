#!/usr/bin/env python3
"""
Generates a synthetic SSH auth.log containing normal login traffic plus an
injected brute-force burst, in the real OpenSSH log format, so you can
practice writing detection logic/rules against it without touching a real
system. (For a fuller lab, replay this file's lines into Wazuh/Splunk/ELK,
or - with permission, in an isolated VM only - run Hydra/Medusa against a
test SSH server and capture the real log.)

Usage:
    python3 simulate_ssh_attack.py
"""
import datetime
import os
import random

OUT_FILE = os.path.join(os.path.dirname(__file__), "output", "auth.log")
USERS = ["alice", "bob", "deploy", "backup"]
NORMAL_IPS = ["10.0.0.15", "10.0.0.22", "10.0.0.31"]
ATTACKER_IP = "203.0.113.77"
ATTACKER_USERS = ["root", "admin", "test", "user", "oracle", "postgres", "ubuntu"]


def fmt(ts):
    return ts.strftime("%b %d %H:%M:%S")


def main():
    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    lines = []
    t = datetime.datetime.now() - datetime.timedelta(hours=2)

    # Normal background traffic: occasional legitimate logins, a few typos
    for _ in range(40):
        t += datetime.timedelta(seconds=random.randint(30, 400))
        ip = random.choice(NORMAL_IPS)
        user = random.choice(USERS)
        if random.random() < 0.9:
            lines.append(f"{fmt(t)} myhost sshd[1234]: Accepted password for {user} from {ip} port {random.randint(30000,60000)} ssh2")
        else:
            lines.append(f"{fmt(t)} myhost sshd[1234]: Failed password for {user} from {ip} port {random.randint(30000,60000)} ssh2")

    # Injected brute-force burst: one IP, many users, many rapid failures
    burst_start = t + datetime.timedelta(seconds=60)
    t2 = burst_start
    for _ in range(150):
        t2 += datetime.timedelta(seconds=random.uniform(0.5, 3))
        user = random.choice(ATTACKER_USERS)
        lines.append(f"{fmt(t2)} myhost sshd[5678]: Failed password for {user} from {ATTACKER_IP} port {random.randint(30000,60000)} ssh2")
    # one lucky hit at the end, as attackers sometimes get in
    t2 += datetime.timedelta(seconds=2)
    lines.append(f"{fmt(t2)} myhost sshd[5678]: Accepted password for root from {ATTACKER_IP} port {random.randint(30000,60000)} ssh2")

    # A bit more normal traffic after
    for _ in range(10):
        t2 += datetime.timedelta(seconds=random.randint(30, 400))
        ip = random.choice(NORMAL_IPS)
        user = random.choice(USERS)
        lines.append(f"{fmt(t2)} myhost sshd[1234]: Accepted password for {user} from {ip} port {random.randint(30000,60000)} ssh2")

    with open(OUT_FILE, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Wrote {len(lines)} log lines to {OUT_FILE}")
    print(f"Injected brute-force burst from {ATTACKER_IP} starting around {fmt(burst_start)}")


if __name__ == "__main__":
    main()
