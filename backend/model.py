import joblib
import os
import shap
from features import extract_features


# =========================
# LOAD MODEL
# =========================
def load_model():
    try:
        base_dir = os.path.dirname(os.path.dirname(__file__))  # project root
        model_path = os.path.join(base_dir, "model", "model.pkl")

        model = joblib.load(model_path)
        print("Model loaded from:", model_path)

        return model

    except Exception as e:
        print("Error loading model:", e)
        raise


# =========================
# PREDICT FUNCTION
# =========================
def predict_url(model, url):
    try:
        # Extract features (IMPORTANT: keep consistent with training)
        features = extract_features(url, use_advanced=False)

        prediction = model.predict([features])[0]
        confidence = model.predict_proba([features])[0].max()

        # Convert numeric → readable label
        label = "Phishing" if prediction == 1 else "Legitimate"

        return label, confidence

    except Exception as e:
        print("Prediction error:", e)
        raise


# =========================
# EXPLAINABILITY (SHAP)
# =========================
import numpy as np

def explain_prediction(model, url):
    try:
        features = extract_features(url, use_advanced=False)
        features_array = np.array(features).reshape(1, -1)

        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(features_array)

        # 🔥 HANDLE DIFFERENT SHAP OUTPUTS
        if isinstance(shap_values, list):
            shap_output = shap_values[1][0]

        else:
            # YOUR CASE: array of [class0, class1]
            shap_output = [val[1] for val in shap_values[0]]

        return shap_output, features

    except Exception as e:
        print("SHAP explanation error:", e)
        raise