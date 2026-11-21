#!/usr/bin/env python3
"""
Parses an OpenSSH-style auth.log and flags brute-force activity:
  - Many failed logins from one source IP within a short time window
  - Many *distinct usernames* from one source IP (password spraying /
    account enumeration signal)
  - A failed-login burst immediately followed by a success (likely
    successful brute force - highest severity)

This mirrors the logic you'd put in a Wazuh custom rule or a Splunk/SPL
correlation search; see wazuh_rule_example.xml and splunk_spl_example.txt
in this folder for the equivalents in those tools.

Usage:
    python3 detect_bruteforce.py output/auth.log
"""
import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime

LOG_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Accepted|Failed)\s+password\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)

FAILED_THRESHOLD = 10        # failed attempts from one IP...
WINDOW_SECONDS = 60          # ...within this many seconds
DISTINCT_USER_THRESHOLD = 5  # distinct usernames from one IP = spraying signal


def parse_log(path):
    events = []
    year = datetime.now().year
    with open(path) as f:
        for line in f:
            m = LOG_PATTERN.match(line)
            if not m:
                continue
            ts = datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
            events.append({
                "ts": ts, "result": m.group("result"),
                "user": m.group("user"), "ip": m.group("ip"),
            })
    return sorted(events, key=lambda e: e["ts"])


def detect(events):
    alerts = []
    failed_by_ip = defaultdict(list)   # ip -> list of (ts, user)

    for e in events:
        if e["result"] == "Failed":
            failed_by_ip[e["ip"]].append((e["ts"], e["user"]))

    for ip, attempts in failed_by_ip.items():
        attempts.sort()
        # sliding window scan
        for i in range(len(attempts)):
            window = [a for a in attempts[i:] if (a[0] - attempts[i][0]).total_seconds() <= WINDOW_SECONDS]
            if len(window) >= FAILED_THRESHOLD:
                distinct_users = len(set(u for _, u in window))
                alerts.append({
                    "type": "BRUTE_FORCE",
                    "ip": ip,
                    "start": window[0][0], "end": window[-1][0],
                    "failed_count": len(window),
                    "distinct_users": distinct_users,
                    "severity": "HIGH" if distinct_users >= DISTINCT_USER_THRESHOLD else "MEDIUM",
                })
                break  # one alert per IP is enough for this simple demo

    # check for success shortly after a flagged burst -> compromise signal
    successes = [e for e in events if e["result"] == "Accepted"]
    for alert in alerts:
        for s in successes:
            if s["ip"] == alert["ip"] and 0 <= (s["ts"] - alert["end"]).total_seconds() <= 30:
                alert["type"] = "BRUTE_FORCE_LIKELY_SUCCESSFUL"
                alert["severity"] = "CRITICAL"
                alert["compromised_user"] = s["user"]
                alert["success_time"] = s["ts"]

    return alerts


def print_alerts(alerts):
    if not alerts:
        print("No brute-force patterns detected.")
        return
    for a in alerts:
        print(f"\n[{a['severity']}] {a['type']} from {a['ip']}")
        print(f"  Window: {a['start']} -> {a['end']}  ({a['failed_count']} failed attempts, {a['distinct_users']} distinct usernames)")
        if a["type"] == "BRUTE_FORCE_LIKELY_SUCCESSFUL":
            print(f"  !! Followed by a SUCCESSFUL login as '{a['compromised_user']}' at {a['success_time']}")
            print("  Recommended action: disable/rotate credentials for that account, block source IP, review session activity")
        else:
            print("  Recommended action: block source IP, monitor for continued attempts")


def main():
    parser = argparse.ArgumentParser(description="Detect brute-force patterns in an SSH auth.log")
    parser.add_argument("logfile", nargs="?", default="output/auth.log")
    args = parser.parse_args()

    try:
        events = parse_log(args.logfile)
    except FileNotFoundError:
        print(f"Log file not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsed {len(events)} auth events from {args.logfile}")
    alerts = detect(events)
    print_alerts(alerts)


if __name__ == "__main__":
    main()
