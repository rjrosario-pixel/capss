# prepare_dataset.py

import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
from feature_extraction.feature_extractor import extract_url_features as extract_features

# --- Load Safe URLs ---
with open("safe_sample.txt", "r", encoding="utf-8", errors="ignore") as f:
    safe_urls = [line.strip() for line in f if line.strip()]

# --- Load Phishing URLs ---
with open("phishing_sample.txt", "r", encoding="utf-8", errors="ignore") as f:
    phish_urls = [line.strip() for line in f if line.strip()]

# --- Prepare Data ---
total = len(safe_urls) + len(phish_urls)
print(f"Processing {len(safe_urls)} safe URLs and {len(phish_urls)} phishing URLs...")

def process_url(url, label):
    """Extract features from a URL with label (-1 = safe, 1 = phish)."""
    try:
        feats = extract_features(url)
        feats["label"] = label
        feats["url"] = url
        return feats
    except Exception as e:
        print(f"[{'SAFE' if label == -1 else 'PHISH'}] Error {url}: {e}")
        return None

data = []
processed = 0

# --- Run in Parallel ---
with ThreadPoolExecutor(max_workers=12) as executor:  # adjust based on CPU cores
    futures = []
    for url in safe_urls:
        futures.append(executor.submit(process_url, url, -1))
    for url in phish_urls:
        futures.append(executor.submit(process_url, url, 1))

    for future in as_completed(futures):
        result = future.result()
        if result:
            data.append(result)

        processed += 1
        # Print every 1000 URLs (much faster than printing every time)
        if processed % 1000 == 0 or processed == total:
            percent = (processed / total) * 100
            print(f"Progress: {percent:.2f}% ({processed}/{total})")

# --- Save Dataset ---
df = pd.DataFrame(data)
df.to_csv("dataset.csv", index=False)
print(f"\n✅ Dataset saved to dataset.csv with {len(df)} samples")
