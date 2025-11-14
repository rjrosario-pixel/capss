import pandas as pd
import joblib
from urllib.parse import urlparse
import re
import sys
from joblib import Parallel, delayed

# --- Load URLs ---
def load_sample(file_path, limit=10000):
    urls = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= limit:
                break
            url = line.strip()
            if url:
                urls.append(url)
    return urls

safe_urls = load_sample("safe_sample.txt", 1000)
phishing_urls = load_sample("phishing_sample.txt", 1000)

df_test = pd.DataFrame({
    'url': safe_urls + phishing_urls,
    'label': [-1]*len(safe_urls) + [1]*len(phishing_urls)
})

# --- Load model ---
model = joblib.load("trained_models/randomForest_final.pkl")
feature_names = model.feature_names_in_

# --- Feature extraction (no network calls) ---
def extract_url_features_local(url):
    hostname = urlparse(url).hostname or ''
    return {
        'url_having_ip': 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,
        'url_length': 1 if len(url) > 75 else 0.5 if 54 <= len(url) <= 75 else 0,
        'url_short': 1 if re.search(r"bit\.ly|tinyurl|goo\.gl|t\.co", url) else 0,
        'having_at_symbol': 1 if '@' in url else 0,
        'doubleSlash': 1 if url.rfind('//') > 7 else 0,
        'prefix_suffix': 1 if '-' in hostname else 0,
        'sub_domain': 0 if hostname.count('.')==1 else 0.5 if hostname.count('.')==2 else 1,
        'SSLfinal_State': 0,
        'domain_registration': 0,
        'favicon': 0,
        'port': 1 if urlparse(url).port not in [None,80,443] else 0,
        'https_token': 1 if 'https' in hostname else 0,
        'request_url': 0,
        'url_of_anchor': 0,
        'Links_in_tags': 0,
        'sfh': 0,
        'email_submit': 0,
        'abnormal_url': 0 if hostname else 1,
        'redirect': 1 if url.count('//') <= 1 else 0.5 if url.count('//')<4 else 0,
        'on_mouseover': 0,
        'rightClick': 0,
        'popup': 0,
        'iframe': 0,
        'age_of_domain': 0,
        'check_dns': 0,  # skip network call
        'web_traffic': 0,
        'page_rank': 0,
        'google_index': 0,
        'links_pointing': 0,
        'statistical': 0
    }

# --- Extract features in parallel (safe on Windows) ---
X_list = Parallel(n_jobs=-1)(delayed(extract_url_features_local)(u) for u in df_test['url'])

# --- Print progress after extraction ---
total = len(X_list)
for i, _ in enumerate(X_list, 1):
    percent = (i/total)*100
    sys.stdout.write(f"\rProgress: {percent:.1f}%")
    sys.stdout.flush()
print("\nFeature extraction completed.")

# --- Prepare DataFrame ---
X_test = pd.DataFrame(X_list).reindex(columns=feature_names, fill_value=0).astype(float)
y_true = df_test['label'].values

# --- Predict ---
y_pred = model.predict(X_test)

# --- Metrics ---
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
accuracy = accuracy_score(y_true, y_pred)
precision = precision_score(y_true, y_pred, pos_label=1, zero_division=0)
recall = recall_score(y_true, y_pred, pos_label=1, zero_division=0)
f1 = f1_score(y_true, y_pred, pos_label=1, zero_division=0)
cm = confusion_matrix(y_true, y_pred)

print(f"Accuracy: {accuracy*100:.2f}%")
print(f"Precision: {precision*100:.2f}%")
print(f"Recall: {recall*100:.2f}%")
print(f"F1 Score: {f1*100:.2f}%")
print("Confusion Matrix:\n", cm)
