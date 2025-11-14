import pandas as pd
import argparse
import joblib
import sys
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from sklearn.metrics import f1_score, accuracy_score, precision_score, recall_score, confusion_matrix
from feature_extraction.feature_extractor import extract_url_features

# Suppress WHOIS logs
logging.getLogger("whois").setLevel(logging.CRITICAL)

CACHE_FILE = "features_cache.pkl"


# =========================
#  Feature Extraction with Cache
# =========================
def url_to_features(url, cache):
    """Extract features for a URL, using cached values if available."""
    if url in cache:
        return cache[url]

    try:
        feats = extract_url_features(url)
        columns = [
            'url_having_ip','url_length','url_short','having_at_symbol','doubleSlash',
            'prefix_suffix','sub_domain','SSLfinal_State','domain_registration','favicon',
            'port','https_token','request_url','url_of_anchor','Links_in_tags','sfh',
            'email_submit','abnormal_url','redirect','on_mouseover','rightClick','popup',
            'iframe','age_of_domain','check_dns','web_traffic','page_rank','google_index',
            'links_pointing','statistical'
        ]
        feature_vector = [feats.get(c, 0) for c in columns]
        cache[url] = feature_vector  # ✅ Save to memory cache
        return feature_vector
    except Exception as e:
        print(f"\n⚠️ Error extracting features from {url}: {e}")
        cache[url] = [0] * 30
        return cache[url]


# =========================
#  Main Program
# =========================
def main():
    parser = argparse.ArgumentParser(description="Phishing Detection Tester with Caching & Parallel Processing")
    parser.add_argument("--csv", required=True, help="CSV file with URLs and optional 'label' column")
    parser.add_argument("--model", required=True, help="Trained Random Forest model (.pkl)")
    parser.add_argument("--out", required=True, help="Output CSV file for predictions")
    parser.add_argument("--html", required=False, help="Output HTML report (optional)")
    parser.add_argument("--workers", type=int, default=8, help="Number of parallel threads")
    parser.add_argument("--cache", action="store_true", help="Enable caching (recommended)")
    args = parser.parse_args()

    # --- Load cache if exists ---
    cache = {}
    if args.cache and os.path.exists(CACHE_FILE):
        print(f"🗂️ Loading existing cache from {CACHE_FILE} ...")
        cache = joblib.load(CACHE_FILE)
        print(f"✅ Cache loaded: {len(cache)} URLs cached")

    # --- Load CSV ---
    df = pd.read_csv(args.csv)
    if 'url' not in df.columns:
        print("❌ Error: CSV must contain a 'url' column.")
        sys.exit(1)
    urls = df['url'].tolist()
    labels = df['label'].tolist() if 'label' in df.columns else None
    print(f"✅ Loaded {len(urls)} URLs from {args.csv}")

    # --- Load Model ---
    model = joblib.load(args.model)
    print(f"✅ Model loaded from {args.model}")

    # --- Parallel Extraction ---
    print(f"🧠 Extracting features using {args.workers} workers...")
    features = []
    total = len(urls)

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(url_to_features, url, cache): url for url in urls}
        for i, future in enumerate(as_completed(futures), 1):
            features.append(future.result())
            percent = (i / total) * 100
            sys.stdout.write(f"\rProgress: {percent:.2f}% ({i}/{total})")
            sys.stdout.flush()

    print("\n✅ Feature extraction complete.")

    # --- Save cache ---
    if args.cache:
        joblib.dump(cache, CACHE_FILE)
        print(f"💾 Cache updated: {len(cache)} entries saved to {CACHE_FILE}")

    # --- Predict ---
    print("🤖 Predicting...")
    preds = model.predict(features)
    df['prediction'] = preds
    df.to_csv(args.out, index=False)
    print(f"📁 Results saved to {args.out}")

    # --- Metrics ---
    if labels is not None:
        f1 = f1_score(labels, preds)
        accuracy = accuracy_score(labels, preds)
        precision = precision_score(labels, preds)
        recall = recall_score(labels, preds)
        cm = confusion_matrix(labels, preds, labels=[1, -1])

        print("\n=== 🧾 Evaluation Metrics ===")
        print(f"Accuracy : {accuracy:.4f}")
        print(f"Precision: {precision:.4f}")
        print(f"Recall   : {recall:.4f}")
        print(f"F1 Score : {f1:.4f}")
        print("\nConfusion Matrix (labels: 1=Phish, -1=Safe):")
        print(cm)

    # --- Optional HTML ---
    if args.html:
        print("📝 Generating HTML report...")
        html = """<!DOCTYPE html><html><head>
<meta charset="UTF-8">
<title>Phishing Detection Results</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; background: #fafafa; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
th { background-color: #333; color: white; }
tr:nth-child(even){background-color: #f9f9f9;}
.safe { color: green; font-weight: bold; }
.phish { color: red; font-weight: bold; }
</style></head><body>
<h2>Phishing URL Predictions</h2>
<table><tr><th>URL</th><th>Prediction</th></tr>
"""
        for url, pred in zip(urls, preds):
            if pred == 1:
                cls, label = "phish", "Phishing 🕷️"
            else:
                cls, label = "safe", "Safe ✅"
            html += f"<tr><td>{url}</td><td class='{cls}'>{label}</td></tr>\n"
        html += "</table></body></html>"
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"📄 HTML report saved to {args.html}")

    print("\n✅ All tasks completed successfully.")


if __name__ == "__main__":
    main()
