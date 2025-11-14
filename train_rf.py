import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import sys
import math

# --- Feature names ---
FEATURE_NAMES = [
    'url_having_ip', 'url_length', 'url_short', 'having_at_symbol', 'doubleSlash',
    'prefix_suffix', 'sub_domain', 'SSLfinal_State', 'domain_registration', 'favicon',
    'port', 'https_token', 'request_url', 'url_of_anchor', 'Links_in_tags', 'sfh',
    'email_submit', 'abnormal_url', 'redirect', 'on_mouseover', 'rightClick', 'popup',
    'iframe', 'age_of_domain', 'check_dns', 'web_traffic', 'page_rank', 'google_index',
    'links_pointing', 'statistical'
]

print("🚀 Starting Random Forest training...\n")

# Step 1: Load dataset
print("📂 Loading dataset...")
df = pd.read_csv("dataset.csv")

# Rename numeric columns if needed
if list(df.columns[:30]) == [str(i) for i in range(30)]:
    df.columns = FEATURE_NAMES + ["label"]

if "label" not in df.columns:
    raise ValueError("❌ Dataset must have a 'label' column")

X = df[FEATURE_NAMES]
y = df["label"]

# Step 2: Train/test split
print("✂️ Splitting dataset...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Step 3: Training with percentage updates
print("🌲 Training Random Forest...")
n_estimators = 200
clf = RandomForestClassifier(
    n_estimators=n_estimators,
    max_depth=None,
    random_state=42,
    n_jobs=-1,
    warm_start=True  # 👈 allows incremental training
)

batch_size = 20
total_batches = math.ceil(n_estimators / batch_size)

for idx in range(total_batches):
    clf.set_params(n_estimators=(idx + 1) * batch_size)
    clf.fit(X_train, y_train)

    percent = int(((idx + 1) / total_batches) * 100)
    sys.stdout.write(f"\rTraining progress: {percent}%")
    sys.stdout.flush()

print("\n✅ Training complete!")

# Step 4: Evaluate
print("\n📊 Evaluating model...")
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))

# Step 5: Save
print("💾 Saving model...")
joblib.dump(clf, "trained_models/randomForest_final.pkl")
print("🎉 Model saved to trained_models/randomForest_final.pkl")
