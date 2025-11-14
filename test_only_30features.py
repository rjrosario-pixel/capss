#!/usr/bin/env python3
"""
Phishing URL detection — TEST ONLY (30 features)
✅ Uses your existing feature_extractor.py
✅ Extracts 30 features
✅ Evaluates a pre-trained Random Forest model
✅ Auto-saves every 200 URLs (resume-safe)
"""

import os
import re
import sys
import time
import pandas as pd
import numpy as np
import joblib
import logging
from tqdm import tqdm
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from concurrent.futures import ThreadPoolExecutor, as_completed
from feature_extraction.feature_extractor import extract_url_features

# ------------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------------
SEED = 42
np.random.seed(SEED)

PHISHING_FILE = 'phishing_sample.txt'
SAFE_FILE     = 'safe_sample.txt'

TEST_PER_CLASS = 5000
OUTPUT_TEST = 'test_30features.csv'
MODEL_PATH  = 'trained_models/randomForest_final.pkl'
SAVE_INTERVAL = 200  # auto-save every 200 processed URLs

logging.basicConfig(filename='test_errors.log', level=logging.ERROR)

# ------------------------------------------------------------------
# EXACT FEATURE ORDER (must match your extractor)
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
def is_valid_url(url: str) -> bool:
    return bool(re.match(r'^https?://', url.strip(), re.IGNORECASE))

class ProgressReporter:
    """Progress bar for each phase"""
    def __init__(self, phase, total):
        self.phase = phase
        self.pbar = tqdm(total=total, desc=f"[{phase}]", ncols=80, file=sys.stdout)
        self.start = time.time()

    def update(self):
        self.pbar.update(1)

    def close(self, failed=0):
        self.pbar.close()
        elapsed = time.time() - self.start
        print(f"[{self.phase}] Done | Failed: {failed:,} | Time: {elapsed:.1f}s")

# ------------------------------------------------------------------
# 1. LOAD MODEL
# ------------------------------------------------------------------
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"❌ Model not found at {MODEL_PATH}")

print(f"✅ Loaded model from: {MODEL_PATH}")
model = joblib.load(MODEL_PATH)

# ------------------------------------------------------------------
# 2. LOAD TEST URLS
# ------------------------------------------------------------------
print("\n=== PHASE 1: LOAD TEST URLS ===")
phishing_urls, safe_urls = [], []

with open(PHISHING_FILE, 'r', encoding='utf-8') as f:
    for line in f:
        url = line.strip()
        if url and is_valid_url(url):
            phishing_urls.append(url)

with open(SAFE_FILE, 'r', encoding='utf-8') as f:
    for line in f:
        url = line.strip()
        if url and is_valid_url(url):
            safe_urls.append(url)

phishing_urls = phishing_urls[:TEST_PER_CLASS]
safe_urls = safe_urls[:TEST_PER_CLASS]

test_urls = phishing_urls + safe_urls
test_labels = [1] * len(phishing_urls) + [0] * len(safe_urls)
print(f"Loaded {len(test_urls):,} total test URLs")

# ------------------------------------------------------------------
# 3. EXTRACT FEATURES (MULTITHREADED)
# ------------------------------------------------------------------
print("\n=== PHASE 2: FEATURE EXTRACTION ===")
cpu_cores = max(1, os.cpu_count() - 1)
print(f"Using {cpu_cores} CPU threads")

# Resume if partial file exists
if os.path.exists(OUTPUT_TEST):
    existing = pd.read_csv(OUTPUT_TEST)
    processed_urls = len(existing)
    print(f"🟡 Resuming from {processed_urls:,} already processed URLs...")
else:
    existing = pd.DataFrame(columns=EXPECTED_FEATURES + ['Label'])
    processed_urls = 0

remaining_urls = test_urls[processed_urls:]
remaining_labels = test_labels[processed_urls:]

reporter = ProgressReporter("TEST-EXTRACT", len(remaining_urls))
data = existing.values.tolist()
failed = 0
processed = 0

def process_url(url, label):
    try:
        feats = extract_url_features(url)
        row = [feats.get(f, 0) for f in EXPECTED_FEATURES] + [label]
        return row
    except Exception as e:
        logging.error(f"Failed for {url}: {e}")
        return None

try:
    with ThreadPoolExecutor(max_workers=cpu_cores) as executor:
        futures = {executor.submit(process_url, url, label): (url, label)
                   for url, label in zip(remaining_urls, remaining_labels)}

        for future in as_completed(futures):
            row = future.result()
            if row:
                data.append(row)
            else:
                failed += 1

            processed += 1
            reporter.update()

            # Auto-save every SAVE_INTERVAL
            if processed % SAVE_INTERVAL == 0:
                temp_df = pd.DataFrame(data, columns=EXPECTED_FEATURES + ['Label'])
                temp_df.to_csv(OUTPUT_TEST, index=False)
                print(f"💾 Auto-saved at {processed:,} processed URLs")

except KeyboardInterrupt:
    print("\n🟥 Interrupted by user — saving progress...")
finally:
    reporter.close(failed)
    df_final = pd.DataFrame(data, columns=EXPECTED_FEATURES + ['Label'])
    df_final.to_csv(OUTPUT_TEST, index=False)
    print(f"✅ Progress saved to {OUTPUT_TEST}")

# ------------------------------------------------------------------
# 4. EVALUATE MODEL
# ------------------------------------------------------------------
print("\n=== PHASE 3: EVALUATION ===")
df = pd.read_csv(OUTPUT_TEST)
X_test = df.drop('Label', axis=1)
y_test = df['Label']

y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"\n🎯 Accuracy: {acc:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\n✅ Testing completed successfully!")
