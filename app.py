import numpy as np
import joblib
import xgboost as xgb
from flask import Flask, request, jsonify
from sklearn.preprocessing import StandardScaler
import traceback

# Load the trained model and scaler
model = joblib.load("xgboost_ddos.pkl")
scaler = joblib.load("scaler.pkl")

# Define Flask app
app = Flask(__name__)

# Define required features
required_features = ["Flow Duration", "Total_Bytes", "Average Packet Size", "Packet_Count"]

def preprocess_input(data):
    try:
        # Compute additional features
        data["Total_Bytes"] = data.get("Total Length of Fwd Packets", 0) + data.get("Total Length of Bwd Packets", 0)
        data["Packet_Count"] = data.get("Total Fwd Packets", 0) + data.get("Total Backward Packets", 0)

        # Ensure all required features exist
        missing_features = [feat for feat in required_features if feat not in data]
        if missing_features:
            return {"error": f"Missing features: {', '.join(missing_features)}"}

        # Extract required features
        features = [data[feat] for feat in required_features]

        # Scale features
        features_scaled = scaler.transform([features])
        return features_scaled
    except Exception as e:
        return {"error": str(e)}

@app.route("/predict", methods=["POST"])
def predict():
    try:
        # Parse JSON request
        data = request.json

        # Preprocess input
        processed_data = preprocess_input(data)
        if isinstance(processed_data, dict) and "error" in processed_data:
            return jsonify(processed_data), 400

        features_scaled = processed_data

        # Get model output
        logit = model.predict(features_scaled)[0]
        probability = model.predict_proba(features_scaled)[0][1]  # Probability of DDoS

        # Print logit for debugging
        print(f"Feature scaled: {features_scaled}")
        print(f"Logit Output: {logit}")
        print(f"Probability: {probability}")

        # Make prediction based on probability
        prediction = "DDoS Attack Detected" if probability > 0.4 else "Normal Traffic"

        return jsonify({
            "prediction": prediction,
            "probability": float(probability)  # Ensure JSON compatibility
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)

