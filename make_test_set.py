#!/usr/bin/env python3
"""
make_10k_test_set.py

Create a CSV test file containing 5000 safe and 5000 phishing URLs:
 - safe_sample.txt     -> label 1
 - phishing_sample.txt -> label -1

If a file has fewer than 5000 unique URLs, the script will oversample
(with replacement) to reach 5000 and warn you.
"""

import argparse
import csv
import random
import sys
from pathlib import Path

DEFAULT_PER_CLASS = 5000

def read_urls(path: Path):
    if not path.exists():
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        lines = [ln.strip() for ln in f]
    urls = [u for u in lines if u and not u.startswith("#")]
    # dedupe preserving order
    seen = set()
    dedup = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            dedup.append(u)
    return dedup

def sample_fixed(urls, k, rng):
    """
    Return exactly k URLs.
    - If len(urls) >= k: sample without replacement.
    - If len(urls) == 0: returns empty list (caller will handle)
    - If len(urls) < k: sample with replacement (oversample duplicates) and warn.
    """
    n = len(urls)
    if n == 0:
        return []
    if n >= k:
        return rng.sample(urls, k)
    # oversample with replacement
    print(f"Warning: only {n} unique URLs available but {k} requested. Will oversample with replacement.", file=sys.stderr)
    picks = []
    for _ in range(k):
        picks.append(rng.choice(urls))
    return picks

def main():
    p = argparse.ArgumentParser(description="Create CSV with N safe and N phishing URLs.")
    p.add_argument("--safe", default="safe_sample.txt", help="Path to safe URLs (one per line).")
    p.add_argument("--phish", default="phishing_sample.txt", help="Path to phishing URLs (one per line).")
    p.add_argument("--out", default="test_10k_urls.csv", help="Output CSV file path.")
    p.add_argument("--per-class", type=int, default=DEFAULT_PER_CLASS, help=f"Number of URLs per class (default {DEFAULT_PER_CLASS}).")
    p.add_argument("--seed", type=int, default=42, help="Random seed for reproducible sampling.")
    p.add_argument("--label-safe", type=int, default=1, help="Label for safe URLs (default 1).")
    p.add_argument("--label-phish", type=int, default=-1, help="Label for phishing URLs (default -1).")
    args = p.parse_args()

    rng = random.Random(args.seed)

    safe_urls = read_urls(Path(args.safe))
    phish_urls = read_urls(Path(args.phish))

    if not safe_urls:
        print("ERROR: no safe URLs found (or file missing/empty). Aborting.", file=sys.stderr)
        sys.exit(1)
    if not phish_urls:
        print("ERROR: no phishing URLs found (or file missing/empty). Aborting.", file=sys.stderr)
        sys.exit(1)

    k = max(1, args.per_class)

    sampled_safe = sample_fixed(safe_urls, k, rng)
    sampled_phish = sample_fixed(phish_urls, k, rng)

    # combine and shuffle
    combined = [(u, args.label_safe) for u in sampled_safe] + [(u, args.label_phish) for u in sampled_phish]
    rng.shuffle(combined)

    # write CSV
    out_path = Path(args.out)
    with out_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["url", "label"])
        for url, label in combined:
            writer.writerow([url, label])

    print(f"Wrote {len(combined)} rows to {out_path} (per-class={k}, seed={args.seed}).")

if __name__ == "__main__":
    main()
