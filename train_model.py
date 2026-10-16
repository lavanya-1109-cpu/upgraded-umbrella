
from pathlib import Path

import sys
import matplotlib.pyplot as plt
from sklearn.metrics import precision_score, recall_score, f1_score
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# Allow this file to import feature_extraction.py
sys.path.insert(0, str(Path(__file__).resolve().parent))
from feature_extraction import extract_features

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "dataset" / "phishing_url_dataset.csv"
MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"

print("Loading dataset...")
df = pd.read_csv(DATASET_PATH)

# Clean column names and identify URL/Label columns
df.columns = df.columns.str.strip()
column_map = {col.lower(): col for col in df.columns}

if "url" not in column_map or "label" not in column_map:
    raise ValueError(
        f"Expected URL and Label columns. Found: {df.columns.tolist()}"
    )

df = df.rename(columns={
    column_map["url"]: "URL",
    column_map["label"]: "Label"
})

df = df[["URL", "Label"]].dropna()
df["URL"] = df["URL"].astype(str).str.strip()
df = df[df["URL"] != ""].drop_duplicates(subset="URL")

df["Label"] = pd.to_numeric(df["Label"], errors="coerce")
df = df[df["Label"].isin([0, 1])]
df["Label"] = df["Label"].astype(int)

print("Usable rows:", len(df))
print("Extracting URL features...")

X = pd.DataFrame(
    [extract_features(url) for url in df["URL"]]
)
y = df["Label"]

print("Feature extraction complete.")
print("Training model...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)

print("\n--- MODEL EVALUATION ---")
print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")

print("\nClassification report:")
print(classification_report(
    y_test,
    predictions,
    labels=[0, 1],
    target_names=["Phishing", "Legitimate"],
    zero_division=0
))

print("Confusion matrix (rows = actual, columns = predicted):")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))

# Save model and feature names for the web application
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

joblib.dump({
    "model": model,
    "feature_names": list(X.columns)
}, MODEL_PATH)

print(f"\nModel saved successfully at: {MODEL_PATH}")

# ---------- SAVE EVALUATION GRAPHS ----------

REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Confusion matrix: 0 = Phishing, 1 = Legitimate
cm = confusion_matrix(y_test, predictions, labels=[0, 1])

fig, ax = plt.subplots(figsize=(7, 5))
image = ax.imshow(cm, cmap="Blues")

ax.set_title("PhishGuard - Confusion Matrix")
ax.set_xlabel("Predicted label")
ax.set_ylabel("Actual label")
ax.set_xticks([0, 1], ["Phishing", "Legitimate"])
ax.set_yticks([0, 1], ["Phishing", "Legitimate"])

for i in range(2):
    for j in range(2):
        ax.text(
            j, i, f"{cm[i, j]:,}",
            ha="center", va="center",
            color="white" if cm[i, j] > cm.max() / 2 else "black",
            fontsize=12
        )

fig.colorbar(image, ax=ax)
fig.tight_layout()
fig.savefig(REPORTS_DIR / "confusion_matrix.png", dpi=200)
plt.close(fig)

# Metrics specifically for phishing (label 0)
phishing_precision = precision_score(
    y_test, predictions, pos_label=0, zero_division=0
)
phishing_recall = recall_score(
    y_test, predictions, pos_label=0, zero_division=0
)
phishing_f1 = f1_score(
    y_test, predictions, pos_label=0, zero_division=0
)

metric_names = ["Precision", "Recall", "F1-score"]
metric_values = [
    phishing_precision,
    phishing_recall,
    phishing_f1
]

fig, ax = plt.subplots(figsize=(7, 5))
bars = ax.bar(metric_names, metric_values)
ax.set_title("Phishing Detection Performance")
ax.set_ylabel("Score")
ax.set_ylim(0, 1.05)

for bar, value in zip(bars, metric_values):
    ax.text(
        bar.get_x() + bar.get_width() / 2,
        value + 0.02,
        f"{value:.3f}",
        ha="center"
    )

fig.tight_layout()
fig.savefig(REPORTS_DIR / "phishing_metrics.png", dpi=200)
plt.close(fig)

# Save results as a text file
with open(REPORTS_DIR / "evaluation_report.txt", "w", encoding="utf-8") as file:
    file.write("PHISHGUARD MODEL EVALUATION\n")
    file.write(f"Accuracy: {accuracy_score(y_test, predictions):.4f}\n")
    file.write(f"Phishing precision: {phishing_precision:.4f}\n")
    file.write(f"Phishing recall: {phishing_recall:.4f}\n")
    file.write(f"Phishing F1-score: {phishing_f1:.4f}\n")
    file.write("\nConfusion matrix (actual rows, predicted columns):\n")
    file.write(str(cm))
    file.write("\n\n")
    file.write(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Phishing", "Legitimate"],
        zero_division=0
    ))

print("\nEvaluation files saved in the reports folder.")
print("Phishing precision:", round(phishing_precision, 4))
print("Phishing recall:", round(phishing_recall, 4))
print("Phishing F1-score:", round(phishing_f1, 4))

