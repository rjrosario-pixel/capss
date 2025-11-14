import pandas as pd

df = pd.read_csv("test.csv")
print("✅ Columns in test.csv:", len(df.columns))
print(df.columns.tolist())
