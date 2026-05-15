import pandas as pd
import os
import sys
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# -------------------------------
# FIX IMPORT PATH
# -------------------------------

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.features import extract_features


# -------------------------------
# LOAD DATASETS
# -------------------------------

print("Loading datasets...")

df1 = pd.read_csv("phishing_site_urls.csv", encoding="latin-1")
df1.columns = ["url", "label"]
df1["label"] = df1["label"].map({"good": 0, "bad": 1})

df2 = pd.read_csv("data.csv")

print("Columns in data.csv:", df2.columns)

# Standardize columns
if "url" in df2.columns and "label" in df2.columns:
    df2 = df2[["url", "label"]]
else:
    df2.columns = ["url", "label"]

# Convert labels
df2["label"] = df2["label"].apply(
    lambda x: 1 if str(x).lower() in ["bad", "phishing", "malicious", "1"] else 0
)

# -------------------------------
# MERGE + CLEAN
# -------------------------------

df = pd.concat([df1, df2], ignore_index=True)
df = df.dropna()

# 🔥 LIMIT DATASET (FAST TRAINING)
df = df.sample(n=10000, random_state=42).reset_index(drop=True)

print("Total samples:", len(df))


# -------------------------------
# FEATURE EXTRACTION
# -------------------------------

print("Extracting features...")

X = []
y = df["label"].tolist()

for i, url in enumerate(df["url"]):
    try:
        features = extract_features(url, use_advanced=False)

        if len(features) != 12:
            features = [0] * 12

    except Exception as e:
        print(f"Error at index {i}: {e}")
        features = [0] * 12

    X.append(features)

    if i % 1000 == 0:
        print(f"Processed {i}/{len(df)}")

X = pd.DataFrame(X)


# -------------------------------
# TRAIN-TEST SPLIT
# -------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    stratify=y,
    random_state=42
)


# -------------------------------
# MODEL TRAINING
# -------------------------------

print("Training model...")

model = RandomForestClassifier(
    n_estimators=150,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)


# -------------------------------
# EVALUATION
# -------------------------------

y_pred = model.predict(X_test)

print("\nMODEL PERFORMANCE:\n")
print(classification_report(y_test, y_pred))


# -------------------------------
# SAVE MODEL
# -------------------------------

model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
joblib.dump(model, model_path)

print(f"\nModel saved at: {model_path}")