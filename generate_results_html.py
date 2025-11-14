#!/usr/bin/env python3
"""
PHISHING DETECTION RESULTS → HTML REPORT (DUAL FORMAT: 0.9834 (98.34%))
"""

import pandas as pd
import joblib
import os
import numpy as np
from datetime import datetime
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# --------------------------------------------------------------
# CONFIG
# --------------------------------------------------------------
TEST_CSV = 'test_30features.csv'
MODEL_PATH = 'trained_models/randomForest_final.pkl'
OUTPUT_HTML = 'phishing_detection_report.html'

# --------------------------------------------------------------
# LOAD MODEL AND DATA
# --------------------------------------------------------------
print("Loading model...")
rfc = joblib.load(MODEL_PATH)

print("Loading test data...")
df = pd.read_csv(TEST_CSV)
X_test = df.drop('Label', axis=1)
y_test = df['Label']

# --------------------------------------------------------------
# PREDICT AND COMPUTE METRICS
# --------------------------------------------------------------
print("Predicting...")
y_pred = rfc.predict(X_test)

# Add predictions to dataframe
df['Predicted'] = y_pred

# Find indexes (row numbers) of FP and FN
fp_index = df[(df['Label'] == 0) & (df['Predicted'] == 1)].index
fn_index = df[(df['Label'] == 1) & (df['Predicted'] == 0)].index

print("False Positives (row indices):", fp_index.tolist())
print("False Negatives (row indices):", fn_index.tolist())

# Ensure correct label order: 0 = Safe, 1 = Phishing
cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
tn, fp, fn, tp = cm.ravel()

acc = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred, target_names=['Safe', 'Phishing'], output_dict=True)

precision_phish = report['Phishing']['precision']
recall_phish = report['Phishing']['recall']
f1_phish = report['Phishing']['f1-score']

# Top 10 features
importances = rfc.feature_importances_
feat_names = X_test.columns
top_idx = importances.argsort()[::-1][:10]
top_features = [(feat_names[i], importances[i]) for i in top_idx]

# --------------------------------------------------------------
# HELPER: DUAL FORMAT 0.xxxx (xx.xx%)
# --------------------------------------------------------------
def dual_fmt(val):
    return f"{val:.4f} ({val*100:.2f}%)"

# --------------------------------------------------------------
# GENERATE HTML REPORT
# --------------------------------------------------------------
def generate_html():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Detection Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --primary: #2c3e50;
            --success: #27ae60;
            --danger: #e74c3c;
            --warning: #f39c12;
            --light: #ecf0f1;
            --dark: #34495e;
            --gray: #95a5a6;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            color: #333;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1000px;
            margin: auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        header {{
            background: var(--primary);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        header h1 {{
            margin: 0;
            font-size: 2.2em;
        }}
        .badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 50px;
            font-weight: bold;
            font-size: 1.1em;
        }}
        .acc-badge {{
            background: {('#27ae60' if acc >= 0.98 else '#f39c12')};
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
        }}
        .card {{
            background: var(--light);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .card h3 {{
            margin: 0 0 10px 0;
            color: var(--primary);
            font-size: 1em;
        }}
        .card .value {{
            font-size: 1.6em;
            font-weight: bold;
            color: var(--dark);
            font-family: monospace;
        }}
        .card .label {{
            font-size: 0.85em;
            color: var(--gray);
            margin-top: 5px;
        }}
        .cm-heatmap {{
            padding: 30px;
            text-align: center;
        }}
        canvas {{
            max-width: 400px;
            margin: 0 auto;
            display: block;
        }}
        .features {{
            padding: 30px;
        }}
        .feature-bar {{
            display: flex;
            align-items: center;
            margin: 12px 0;
        }}
        .feature-name {{
            width: 220px;
            font-weight: 500;
        }}
        .bar-container {{
            flex: 1;
            height: 20px;
            background: #ddd;
            border-radius: 10px;
            overflow: hidden;
            margin: 0 15px;
        }}
        .bar {{
            height: 100%;
            background: var(--primary);
            border-radius: 10px;
        }}
        .bar-value {{
            width: 100px;
            text-align: right;
            font-weight: bold;
            color: var(--dark);
            font-family: monospace;
        }}
        footer {{
            text-align: center;
            padding: 20px;
            color: #777;
            font-size: 0.9em;
        }}
        .success {{ color: var(--success); }}
        .danger {{ color: var(--danger); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Phishing Detection Report</h1>
            <p>Generated on {timestamp}</p>
            <div class="badge acc-badge">Accuracy: {dual_fmt(acc)}</div>
        </header>

        <div class="metrics">
            <div class="card"><h3>Total Tested</h3><div class="value">{len(y_test):,}</div></div>
            <div class="card"><h3>Precision</h3><div class="value success">{dual_fmt(precision_phish)}</div><div class="label">True pos / Predicted phishing</div></div>
            <div class="card"><h3>Recall</h3><div class="value success">{dual_fmt(recall_phish)}</div><div class="label">True pos / Actual phishing</div></div>
            <div class="card"><h3>F1-Score</h3><div class="value success">{dual_fmt(f1_phish)}</div><div class="label">Harmonic mean of P&R</div></div>
            <div class="card"><h3>True Positives</h3><div class="value success">{tp:,}</div></div>
            <div class="card"><h3>False Positives</h3><div class="value danger">{fp}</div></div>
            <div class="card"><h3>False Negatives</h3><div class="value danger">{fn}</div></div>
            <div class="card"><h3>True Negatives</h3><div class="value success">{tn:,}</div></div>
        </div>

        <div class="cm-heatmap">
            <h2>Confusion Matrix</h2>
            <canvas id="cmChart"></canvas>
        </div>

        <div class="features">
            <h2>Top 10 Most Important Features</h2>
    """

    for name, imp in top_features:
        html += f"""
            <div class="feature-bar">
                <div class="feature-name">{name.replace('_', ' ').title()}</div>
                <div class="bar-container"><div class="bar" style="width: {imp*100:.2f}%"></div></div>
                <div class="bar-value">{dual_fmt(imp)}</div>
            </div>
        """

    html += f"""
        </div>
        <footer>
            Model: Random Forest | Features: 33 | Test Set: {len(y_test):,} URLs
        </footer>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const ctx = document.getElementById('cmChart').getContext('2d');
            new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: ['True Safe', 'True Phishing'],
                    datasets: [
                        {{
                            label: 'Predicted Safe',
                            data: [{tn}, {fn}],
                            backgroundColor: '#27ae60'
                        }},
                        {{
                            label: 'Predicted Phishing',
                            data: [{fp}, {tp}],
                            backgroundColor: '#e74c3c'
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    indexAxis: 'y',
                    plugins: {{
                        tooltip: {{
                            callbacks: {{
                                label: ctx => `${{ctx.dataset.label}}: ${{ctx.raw}}`
                            }}
                        }},
                        legend: {{ position: 'top' }}
                    }},
                    scales: {{
                        x: {{
                            stacked: true,
                            title: {{ display: true, text: 'Count' }}
                        }},
                        y: {{
                            stacked: true,
                            title: {{ display: true, text: 'Actual Label' }}
                        }}
                    }}
                }}
            }});
        }});
    </script>
</body>
</html>
"""
    return html

# --------------------------------------------------------------
# SAVE HTML
# --------------------------------------------------------------
print("Generating HTML report...")
html_content = generate_html()
with open(OUTPUT_HTML, 'w', encoding='utf-8') as f:
    f.write(html_content)

print(f"✅ HTML report saved: {OUTPUT_HTML}")
print(f"📂 Open in browser: file://{os.path.abspath(OUTPUT_HTML)}")
