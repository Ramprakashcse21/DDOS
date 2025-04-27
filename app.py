import numpy as np
import joblib
import xgboost as xgb
from flask import Flask, request, jsonify
from sklearn.preprocessing import StandardScaler
import traceback
import sqlite3
from datetime import datetime, date
from flask import Flask, render_template
import json
import html
from collections import Counter

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

# Create table once
conn = sqlite3.connect('attacks.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS blocked_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        flow_duration REAL,
        total_Bytes REAL,
        average_packet_size INTEGER,
        packet_count INTEGER,
        prediction TEXT,
        timestamp TEXT
    )
''')
conn.commit()

# Insert whenever attack detected
def store_attack(flow_duration, total_Bytes, average_packet_size, packet_count, prediction):
    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO blocked_requests (flow_duration, total_Bytes, average_packet_size, packet_count, prediction, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (flow_duration, total_Bytes, average_packet_size, packet_count, prediction, str(datetime.now())))
    conn.commit()

@app.route("/predict", methods=["POST"])
def predict():
    try:
        # Parse JSON request
        data = request.json

        # Preprocess input
        processed_data = preprocess_input(data)
        if isinstance(processed_data, dict) and "error" in processed_data:
            return jsonify(processed_data), 400

        # Check if this request is already in blocked list
        conn = sqlite3.connect('attacks.db')
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM blocked_requests 
            WHERE flow_duration=? AND total_Bytes=? AND average_packet_size=? AND packet_count=?
        ''', (data["Flow Duration"], data["Total_Bytes"], data["Average Packet Size"], data["Packet_Count"]))

        blocked = cursor.fetchone()
        conn.close()

        if blocked:
            return jsonify({
                "prediction": "Request Blocked (Previously Detected Attack)"
            }), 403

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

        if prediction == "DDoS Attack Detected":
           store_attack(data["Flow Duration"], data["Total_Bytes"], data["Average Packet Size"], data["Packet_Count"], prediction) 

        return jsonify({
            "prediction": prediction,
            "probability": float(probability)  # Ensure JSON compatibility
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route("/attacks", methods=["GET"])
def get_attacks():
    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM blocked_requests')
    rows = cursor.fetchall()
    conn.close()
    
    attacks = []
    for row in rows:
        attacks.append({
            'id': row[0],
            'flow_duration': row[1],
            'total_Bytes': row[2],
            'average_packet_size': row[3],
            'packet_count': row[4],
            'prediction': row[5],
            'timestamp': row[6]
        })
    
    return jsonify(attacks)

@app.route('/dashboard')
def dashboard():
    # Get start and end date from URL, or use today's date
    start_date = request.args.get('start') or date.today().isoformat()
    end_date = request.args.get('end') or date.today().isoformat()

    # SQL query to filter by date
    query = "SELECT timestamp FROM blocked_requests WHERE DATE(timestamp) BETWEEN ? AND ?"
    params = (start_date, end_date)

    # Fetch data
    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    # Format each timestamp to hourly buckets (12hr AM/PM format)
    grouped_times = []
    for row in rows:
        try:
            dt = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            dt = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
        grouped_times.append(dt.strftime("%Y-%m-%d %I %p"))

    # Count frequency per hour
    counts = Counter(grouped_times)
    sorted_times = sorted(counts.keys())
    occurrences = [counts[t] for t in sorted_times]

    return render_template("dashboard.html",
                           labels=json.dumps(sorted_times),
                           values=json.dumps(occurrences),
                           start=start_date,
                           end=end_date)
import os

@app.route('/dashboard-path')
def dashboardPath():
    template_path = os.path.abspath(os.path.join('templates', 'dashboard.html'))
    print("Looking for dashboard.html at:", template_path)
    return render_template("dashboard.html")


if __name__ == "__main__":
    app.run(debug=True)
