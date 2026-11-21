#!/usr/bin/env python3
"""
Plot crack-time results after you've run John the Ripper / Hashcat and
filled in output/results_template.csv (renamed to results.csv).

Usage:
    pip install matplotlib --break-system-packages
    python3 plot_results.py
"""
import csv
import os

import matplotlib.pyplot as plt

OUT_DIR = os.path.join(os.path.dirname(__file__), "output")
RESULTS_FILE = os.path.join(OUT_DIR, "results.csv")


def load_results():
    with open(RESULTS_FILE) as f:
        return list(csv.DictReader(f))


def plot_time_by_algorithm(rows):
    by_algo = {}
    for r in rows:
        if not r["time_to_crack_seconds"]:
            continue
        by_algo.setdefault(r["algorithm"], []).append(float(r["time_to_crack_seconds"]))

    fig, ax = plt.subplots()
    algos = list(by_algo.keys())
    avgs = [sum(v) / len(v) for v in by_algo.values()]
    ax.bar(algos, avgs)
    ax.set_ylabel("Avg time to crack (seconds, log scale)")
    ax.set_yscale("log")
    ax.set_title("Crack Time by Hashing Algorithm")
    fig.savefig(os.path.join(OUT_DIR, "chart_time_by_algorithm.png"), dpi=150, bbox_inches="tight")
    print("Saved chart_time_by_algorithm.png")


def plot_time_by_entropy(rows):
    fig, ax = plt.subplots()
    for algo in sorted(set(r["algorithm"] for r in rows)):
        xs, ys = [], []
        for r in rows:
            if r["algorithm"] == algo and r["time_to_crack_seconds"]:
                xs.append(float(r["entropy_bits"]))
                ys.append(float(r["time_to_crack_seconds"]) + 0.001)
        if xs:
            ax.scatter(xs, ys, label=algo)
    ax.set_xlabel("Password entropy (bits)")
    ax.set_ylabel("Time to crack (seconds, log scale)")
    ax.set_yscale("log")
    ax.set_title("Entropy vs Crack Time")
    ax.legend()
    fig.savefig(os.path.join(OUT_DIR, "chart_entropy_vs_time.png"), dpi=150, bbox_inches="tight")
    print("Saved chart_entropy_vs_time.png")


def main():
    if not os.path.exists(RESULTS_FILE):
        print(f"Expected {RESULTS_FILE} - copy results_template.csv there and fill it in first.")
        return
    rows = load_results()
    plot_time_by_algorithm(rows)
    plot_time_by_entropy(rows)


if __name__ == "__main__":
    main()
