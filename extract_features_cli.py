import pandas as pd
import argparse
import sys
import os
import joblib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from feature_extraction.feature_extractor import extract_url_features

# Suppress noisy WHOIS logs
logging.getLogger("whois").setLevel(logging.CRITICAL)

CACHE_FILE = "features_cache.pkl"

# =========================
#  Feature Extraction Function
# =========================
def url_to_features(url, cache):
    """Extract features for one URL, using cache if available."""
    if url in cache:
        return cache[url]

    try:
        feats = extract_url_features(url)
        feats['url'] = url
        cache[url] = feats
        return feats
    except Exception as e:
        print(f"\n⚠️ Error extracting from {url}: {e}")
        empty = {k: 0 for k in [
            'url_having_ip','url_length','url_short','having_at_symbol','doubleSlash',
            'prefix_suffix','sub_domain','SSLfinal_State','domain_registration','favicon',
            'port','https_token','request_url','url_of_anchor','Links_in_tags','sfh',
            'email_submit','abnormal_url','redirect','on_mouseover','rightClick','popup',
            'iframe','age_of_domain','check_dns','web_traffic','page_rank','google_index',
            'links_pointing','statistical'
        ]}
        empty['url'] = url
        cache[url] = empty
        return empty


# =========================
#  Main CLI
# =========================
def main():
    parser = argparse.ArgumentParser(description="Parallel URL Feature Extractor for Phishing Detection")
    parser.add_argument("--input", required=True, help="Input CSV file with 'url' column")
    parser.add_argument("--output", required=True, help="Output CSV file with features")
    parser.add_argument("--workers", type=int, default=16, help="Number of parallel threads (default: 16)")
    parser.add_argument("--cache", action="store_true", help="Enable feature caching")
    args = parser.parse_args()

    # --- Load cache if exists ---
    cache = {}
    if args.cache and os.path.exists(CACHE_FILE):
        print(f"🗂️ Loading existing cache from {CACHE_FILE} ...")
        cache = joblib.load(CACHE_FILE)
        print(f"✅ Cache loaded: {len(cache)} URLs cached")

    # --- Load URLs ---
    df = pd.read_csv(args.input)
    if 'url' not in df.columns:
        print("❌ Error: input CSV must contain a 'url' column.")
        sys.exit(1)

    urls = df['url'].tolist()
    print(f"✅ Loaded {len(urls)} URLs from {args.input}")

    # --- Parallel Feature Extraction ---
    print(f"⚙️ Extracting features using {args.workers} workers...")
    results = []
    total = len(urls)

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(url_to_features, url, cache): url for url in urls}
        for i, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            percent = (i / total) * 100
            sys.stdout.write(f"\rProgress: {percent:.2f}% ({i}/{total})")
            sys.stdout.flush()

    print("\n✅ Feature extraction complete.")

    # --- Save cache ---
    if args.cache:
        joblib.dump(cache, CACHE_FILE)
        print(f"💾 Cache updated: {len(cache)} entries saved to {CACHE_FILE}")

    # --- Save results ---
    features_df = pd.DataFrame(results)
    features_df.to_csv(args.output, index=False)
    print(f"📁 Features saved to {args.output}")
    print("✅ All tasks completed successfully.")


if __name__ == "__main__":
    main()
