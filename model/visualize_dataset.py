import pandas as pd
import numpy as np
import os
import sys
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.gridspec import GridSpec

# Fix import path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from backend.features import extract_features

# =======================================
# CONFIGURATION
# =======================================
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "visualizations")
os.makedirs(OUTPUT_DIR, exist_ok=True)

FEATURE_NAMES = [
    "URL Length", "Dot Count", "IP Presence", "Special Chars",
    "Digit Count", "Suspicious Keywords", "HTTPS", "Subdomain Count",
    "URL Entropy", "Domain Age", "DNS Record", "SSL Valid"
]

# Set visual style
plt.style.use('dark_background')
COLORS = {
    "safe": "#00f0ff",
    "phishing": "#ff3366",
    "accent": "#a855f7",
    "bg": "#0a0a1a",
    "grid": "#1a1a3a"
}


# =======================================
# LOAD & PREPARE DATA
# =======================================
print("Loading datasets...")

df1 = pd.read_csv(os.path.join(os.path.dirname(__file__), "phishing_site_urls.csv"), encoding="latin-1")
df1.columns = ["url", "label"]
df1["label"] = df1["label"].map({"good": 0, "bad": 1})

df2 = pd.read_csv(os.path.join(os.path.dirname(__file__), "data.csv"))
if "url" in df2.columns and "label" in df2.columns:
    df2 = df2[["url", "label"]]
else:
    df2.columns = ["url", "label"]

df2["label"] = df2["label"].apply(
    lambda x: 1 if str(x).lower() in ["bad", "phishing", "malicious", "1"] else 0
)

df = pd.concat([df1, df2], ignore_index=True).dropna()
df = df.sample(n=10000, random_state=42).reset_index(drop=True)

print(f"Total samples: {len(df)}")


# =======================================
# EXTRACT FEATURES
# =======================================
print("Extracting features (this may take a minute)...")

X = []
for i, url in enumerate(df["url"]):
    try:
        features = extract_features(url, use_advanced=False)
        if len(features) != 12:
            features = [0] * 12
    except:
        features = [0] * 12
    X.append(features)
    if i % 2000 == 0:
        print(f"  Processed {i}/{len(df)}")

feature_df = pd.DataFrame(X, columns=FEATURE_NAMES)
feature_df["Label"] = df["label"].values

print("Feature extraction complete!\n")


# =======================================
# CHART 1: CLASS DISTRIBUTION
# =======================================
print("Generating Chart 1: Class Distribution...")

fig, ax = plt.subplots(figsize=(8, 6), facecolor=COLORS["bg"])
ax.set_facecolor(COLORS["bg"])

counts = df["label"].value_counts().sort_index()
bars = ax.bar(
    ["Legitimate (0)", "Phishing (1)"],
    counts.values,
    color=[COLORS["safe"], COLORS["phishing"]],
    edgecolor="white",
    linewidth=0.5,
    width=0.5
)

for bar, count in zip(bars, counts.values):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 100,
            f'{count:,}', ha='center', va='bottom', fontsize=14, fontweight='bold', color='white')

ax.set_title("Dataset Class Distribution", fontsize=18, fontweight='bold', pad=20, color='white')
ax.set_ylabel("Number of Samples", fontsize=13, color='white')
ax.grid(axis='y', alpha=0.2, color=COLORS["grid"])
ax.spines[['top', 'right']].set_visible(False)

plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "1_class_distribution.png"), dpi=150, bbox_inches='tight')
plt.close()


# =======================================
# CHART 2: URL LENGTH DISTRIBUTION
# =======================================
print("Generating Chart 2: URL Length Distribution...")

fig, ax = plt.subplots(figsize=(10, 6), facecolor=COLORS["bg"])
ax.set_facecolor(COLORS["bg"])

legit_lengths = feature_df[feature_df["Label"] == 0]["URL Length"]
phish_lengths = feature_df[feature_df["Label"] == 1]["URL Length"]

ax.hist(legit_lengths, bins=60, alpha=0.6, color=COLORS["safe"], label="Legitimate", edgecolor='none')
ax.hist(phish_lengths, bins=60, alpha=0.6, color=COLORS["phishing"], label="Phishing", edgecolor='none')

ax.set_title("URL Length Distribution by Class", fontsize=18, fontweight='bold', pad=20, color='white')
ax.set_xlabel("URL Length (characters)", fontsize=13, color='white')
ax.set_ylabel("Frequency", fontsize=13, color='white')
ax.legend(fontsize=12, framealpha=0.3)
ax.grid(axis='y', alpha=0.2, color=COLORS["grid"])
ax.spines[['top', 'right']].set_visible(False)

plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "2_url_length_distribution.png"), dpi=150, bbox_inches='tight')
plt.close()


# =======================================
# CHART 3: FEATURE CORRELATION HEATMAP
# =======================================
print("Generating Chart 3: Feature Correlation Heatmap...")

fig, ax = plt.subplots(figsize=(12, 10), facecolor=COLORS["bg"])
ax.set_facecolor(COLORS["bg"])

corr = feature_df[FEATURE_NAMES].corr()
mask = np.triu(np.ones_like(corr, dtype=bool))

cmap = sns.diverging_palette(250, 10, as_cmap=True)
sns.heatmap(
    corr, mask=mask, cmap=cmap, center=0,
    annot=True, fmt=".2f", linewidths=0.5,
    square=True, ax=ax,
    cbar_kws={"shrink": 0.8, "label": "Correlation"},
    annot_kws={"size": 9}
)

ax.set_title("Feature Correlation Heatmap", fontsize=18, fontweight='bold', pad=20, color='white')

plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "3_correlation_heatmap.png"), dpi=150, bbox_inches='tight')
plt.close()


# =======================================
# CHART 4: FEATURE IMPORTANCE (Random Forest)
# =======================================
print("Generating Chart 4: Feature Importance...")

try:
    model_path = os.path.join(os.path.dirname(__file__), "model.pkl")
    model = joblib.load(model_path)
    importances = model.feature_importances_

    fig, ax = plt.subplots(figsize=(10, 7), facecolor=COLORS["bg"])
    ax.set_facecolor(COLORS["bg"])

    sorted_idx = np.argsort(importances)
    colors = plt.cm.cool(np.linspace(0.2, 0.9, len(sorted_idx)))

    ax.barh(
        [FEATURE_NAMES[i] for i in sorted_idx],
        importances[sorted_idx],
        color=colors,
        edgecolor='white',
        linewidth=0.3,
        height=0.6
    )

    for i, (idx, imp) in enumerate(zip(sorted_idx, importances[sorted_idx])):
        ax.text(imp + 0.005, i, f'{imp:.3f}', va='center', fontsize=10, color='white')

    ax.set_title("Random Forest Feature Importance", fontsize=18, fontweight='bold', pad=20, color='white')
    ax.set_xlabel("Importance Score", fontsize=13, color='white')
    ax.grid(axis='x', alpha=0.2, color=COLORS["grid"])
    ax.spines[['top', 'right']].set_visible(False)

    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "4_feature_importance.png"), dpi=150, bbox_inches='tight')
    plt.close()

except Exception as e:
    print(f"  Skipped (model not found): {e}")


# =======================================
# CHART 5: FEATURE BOX PLOTS
# =======================================
print("Generating Chart 5: Feature Box Plots...")

key_features = ["URL Length", "Dot Count", "Special Chars", "Digit Count", "URL Entropy", "Subdomain Count"]

fig, axes = plt.subplots(2, 3, figsize=(16, 10), facecolor=COLORS["bg"])
axes = axes.flatten()

for i, feat in enumerate(key_features):
    ax = axes[i]
    ax.set_facecolor(COLORS["bg"])

    data_legit = feature_df[feature_df["Label"] == 0][feat]
    data_phish = feature_df[feature_df["Label"] == 1][feat]

    bp = ax.boxplot(
        [data_legit, data_phish],
        labels=["Legitimate", "Phishing"],
        patch_artist=True,
        widths=0.5,
        medianprops=dict(color='white', linewidth=2),
        whiskerprops=dict(color='white'),
        capprops=dict(color='white'),
        flierprops=dict(marker='o', markerfacecolor=COLORS["accent"], markersize=3, alpha=0.4)
    )

    bp['boxes'][0].set_facecolor(COLORS["safe"])
    bp['boxes'][0].set_alpha(0.6)
    bp['boxes'][1].set_facecolor(COLORS["phishing"])
    bp['boxes'][1].set_alpha(0.6)

    ax.set_title(feat, fontsize=13, fontweight='bold', color='white')
    ax.grid(axis='y', alpha=0.2, color=COLORS["grid"])
    ax.spines[['top', 'right']].set_visible(False)

fig.suptitle("Feature Distribution: Legitimate vs Phishing", fontsize=18, fontweight='bold', color='white', y=1.02)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "5_feature_boxplots.png"), dpi=150, bbox_inches='tight')
plt.close()


# =======================================
# CHART 6: ENTROPY DISTRIBUTION
# =======================================
print("Generating Chart 6: Entropy Distribution...")

fig, ax = plt.subplots(figsize=(10, 6), facecolor=COLORS["bg"])
ax.set_facecolor(COLORS["bg"])

legit_ent = feature_df[feature_df["Label"] == 0]["URL Entropy"]
phish_ent = feature_df[feature_df["Label"] == 1]["URL Entropy"]

ax.hist(legit_ent, bins=50, alpha=0.6, color=COLORS["safe"], label="Legitimate", edgecolor='none')
ax.hist(phish_ent, bins=50, alpha=0.6, color=COLORS["phishing"], label="Phishing", edgecolor='none')

ax.axvline(legit_ent.mean(), color=COLORS["safe"], linestyle='--', linewidth=2, label=f'Legit Mean: {legit_ent.mean():.2f}')
ax.axvline(phish_ent.mean(), color=COLORS["phishing"], linestyle='--', linewidth=2, label=f'Phish Mean: {phish_ent.mean():.2f}')

ax.set_title("URL Entropy Distribution (Shannon)", fontsize=18, fontweight='bold', pad=20, color='white')
ax.set_xlabel("Entropy Value", fontsize=13, color='white')
ax.set_ylabel("Frequency", fontsize=13, color='white')
ax.legend(fontsize=11, framealpha=0.3)
ax.grid(axis='y', alpha=0.2, color=COLORS["grid"])
ax.spines[['top', 'right']].set_visible(False)

plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "6_entropy_distribution.png"), dpi=150, bbox_inches='tight')
plt.close()


# =======================================
# DONE
# =======================================
print(f"\n✅ All visualizations saved to: {OUTPUT_DIR}")
print("Files generated:")
for f in sorted(os.listdir(OUTPUT_DIR)):
    print(f"  📊 {f}")
