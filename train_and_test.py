#!/usr/bin/env python3
"""
Phishing URL Detection — TRAIN + TEST SPLIT (30 features)
✅ Loads from safe_sample.txt / phishing_sample.txt
✅ Uses your feature_extractor.py
✅ Extracts 30 features
✅ Multithreaded + auto-save every 500 URLs
✅ Trains and saves Random Forest model
✅ Counts total URLs and HTTP/HTTPS distribution
"""

import os
import re
import sys
import time
import joblib
import logging
import pandas as pd
import numpy as np
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from feature_extraction.feature_extractor import extract_url_features
from sklearn.model_selection import train_test_split

# ------------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------------
SEED = 42
np.random.seed(SEED)
SAVE_INTERVAL = 500

PHISHING_FILE = "phishing_sample.txt"
SAFE_FILE = "safe_sample.txt"

TRAIN_PER_CLASS = 20000
TEST_PER_CLASS = 5000

TRAIN_OUTPUT = "train_30features.csv"
TEST_OUTPUT = "test_30features.csv"
MODEL_PATH = "trained_models/randomForest_final.pkl"

os.makedirs("trained_models", exist_ok=True)
logging.basicConfig(filename="train_errors.log", level=logging.ERROR)

# ------------------------------------------------------------------
# FEATURES (must match extractor)
# ------------------------------------------------------------------
EXPECTED_FEATURES = [
    'url_having_ip', 'url_length', 'url_short', 'having_at_symbol', 'doubleSlash',
    'prefix_suffix', 'sub_domain', 'SSLfinal_State', 'domain_registration', 'favicon',
    'port', 'https_token', 'request_url', 'url_of_anchor', 'Links_in_tags',
    'sfh', 'email_submit', 'abnormal_url', 'redirect', 'on_mouseover',
    'rightClick', 'popup', 'iframe', 'age_of_domain', 'check_dns',
    'web_traffic', 'page_rank', 'google_index', 'links_pointing', 'statistical'
]

# ------------------------------------------------------------------
# UTILITIES
# ------------------------------------------------------------------
def is_valid_url(url):
    return bool(re.match(r"^https?://", url.strip(), re.IGNORECASE))

def count_urls(filepath):
    """Count total lines, valid URLs, and http/https split"""
    total_lines = 0
    valid_urls = 0
    http_count = 0
    https_count = 0

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            total_lines += 1
            url = line.strip()
            if is_valid_url(url):
                valid_urls += 1
                if url.startswith("https://"):
                    https_count += 1
                elif url.startswith("http://"):
                    http_count += 1

    return {
        "total_lines": total_lines,
        "valid_urls": valid_urls,
        "http_count": http_count,
        "https_count": https_count
    }

def load_urls(filepath, limit):
    urls = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if url and is_valid_url(url):
                urls.append(url)
            if len(urls) >= limit:
                break
    return urls

class ProgressBar:
    def __init__(self, total, desc):
        self.pbar = tqdm(total=total, desc=desc, ncols=80, file=sys.stdout)
        self.start = time.time()

    def update(self):
        self.pbar.update(1)

    def close(self, failed=0):
        self.pbar.close()
        print(f"✅ Done | Failed: {failed} | Time: {time.time() - self.start:.1f}s")

# ------------------------------------------------------------------
# 1. DATASET SUMMARY
# ------------------------------------------------------------------
print("\n=== PHASE 1: DATASET SUMMARY ===")

safe_stats = count_urls(SAFE_FILE)
phish_stats = count_urls(PHISHING_FILE)

print(f"\n📊 SAFE DATA SUMMARY ({SAFE_FILE})")
print(f"  Total lines:   {safe_stats['total_lines']:,}")
print(f"  Valid URLs:    {safe_stats['valid_urls']:,}")
print(f"  HTTPS URLs:    {safe_stats['https_count']:,}")
print(f"  HTTP URLs:     {safe_stats['http_count']:,}")

print(f"\n📊 PHISHING DATA SUMMARY ({PHISHING_FILE})")
print(f"  Total lines:   {phish_stats['total_lines']:,}")
print(f"  Valid URLs:    {phish_stats['valid_urls']:,}")
print(f"  HTTPS URLs:    {phish_stats['https_count']:,}")
print(f"  HTTP URLs:     {phish_stats['http_count']:,}")

# ------------------------------------------------------------------
# 2. LOAD URLS
# ------------------------------------------------------------------
print("\n=== PHASE 2: LOAD URLS ===")
phishing_urls = load_urls(PHISHING_FILE, TRAIN_PER_CLASS + TEST_PER_CLASS)
safe_urls = load_urls(SAFE_FILE, TRAIN_PER_CLASS + TEST_PER_CLASS)

print(f"Loaded {len(phishing_urls):,} phishing and {len(safe_urls):,} safe URLs")

# Randomly split phishing URLs
train_phish, test_phish = train_test_split(
    phishing_urls, train_size=TRAIN_PER_CLASS, test_size=TEST_PER_CLASS, random_state=SEED
)

# Randomly split safe URLs
train_safe, test_safe = train_test_split(
    safe_urls, train_size=TRAIN_PER_CLASS, test_size=TEST_PER_CLASS, random_state=SEED
)

print(f"Training set: {len(train_phish)} phishing, {len(train_safe)} safe")
print(f"Testing set:  {len(test_phish)} phishing, {len(test_safe)} safe")

train_urls = train_phish + train_safe
train_labels = [1] * len(train_phish) + [0] * len(train_safe)
test_urls = test_phish + test_safe
test_labels = [1] * len(test_phish) + [0] * len(test_safe)

# ------------------------------------------------------------------
# 3. FEATURE EXTRACTION (MULTITHREAD)
# ------------------------------------------------------------------
def extract_batch(urls, labels, output_file, phase):
    data = []
    failed = 0
    total = len(urls)
    cpu_cores = min(32, max(1, os.cpu_count() - 1))
    print(f"[{phase}] Using {cpu_cores} threads")

    if os.path.exists(output_file):
        existing = pd.read_csv(output_file)
        start = len(existing)
        print(f"🟡 Resuming from {start:,} already processed URLs")
        data = existing.values.tolist()
        urls, labels = urls[start:], labels[start:]
    else:
        start = 0

    progress = ProgressBar(len(urls), phase)

    def process(url, label):
        try:
            feats = extract_url_features(url)
            row = [feats.get(f, 0) for f in EXPECTED_FEATURES] + [label]
            return row
        except Exception as e:
            logging.error(f"Failed for {url}: {e}")
            return None

    try:
        with ThreadPoolExecutor(max_workers=cpu_cores) as executor:
            futures = {executor.submit(process, url, label): (url, label)
                       for url, label in zip(urls, labels)}

            for i, future in enumerate(as_completed(futures), 1):
                row = future.result()
                if row:
                    data.append(row)
                else:
                    failed += 1
                progress.update()

                if i % SAVE_INTERVAL == 0:
                    pd.DataFrame(data, columns=EXPECTED_FEATURES + ["Label"]).to_csv(output_file, index=False)
                    print(f"💾 Auto-saved {i:,}/{total:,} in {phase}")

    except KeyboardInterrupt:
        print("\n🟥 Interrupted — saving progress...")
    finally:
        progress.close(failed)
        pd.DataFrame(data, columns=EXPECTED_FEATURES + ["Label"]).to_csv(output_file, index=False)
        print(f"✅ Saved {output_file} ({len(data):,} rows)")

# ------------------------------------------------------------------
# 4. TRAIN AND TEST
# ------------------------------------------------------------------
print("\n=== PHASE 3: FEATURE EXTRACTION (TRAIN) ===")
extract_batch(train_urls, train_labels, TRAIN_OUTPUT, "TRAIN")

print("\n=== PHASE 4: FEATURE EXTRACTION (TEST) ===")
extract_batch(test_urls, test_labels, TEST_OUTPUT, "TEST")

print("\n=== PHASE 5: TRAINING MODEL ===")
train_df = pd.read_csv(TRAIN_OUTPUT)
X_train = train_df.drop("Label", axis=1)
y_train = train_df["Label"]

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    random_state=SEED,
    n_jobs=-1
)
model.fit(X_train, y_train)
joblib.dump(model, MODEL_PATH)
print(f"✅ Model saved to {MODEL_PATH}")

print("\n=== PHASE 6: TESTING MODEL ===")
test_df = pd.read_csv(TEST_OUTPUT)
X_test = test_df.drop("Label", axis=1)
y_test = test_df["Label"]

y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"\n🎯 Accuracy: {acc:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\n✅ Training + Testing completed successfully!")
