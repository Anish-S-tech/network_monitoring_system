#!/usr/bin/env python3
"""
train_ml.py - example pipeline to train an IsolationForest on traffic features.
Assumes you have CSV with columns matching config.yaml ml.features
"""
import os, pickle
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from utils import load_config

cfg = load_config("config.yaml")
ml_cfg = cfg.get("ml", {})
model_path = os.path.join(os.path.dirname(__file__), ml_cfg.get("model_path", "./models/isolation_forest.pkl"))
features = ml_cfg.get("features", ["pkt_rate","avg_pkt_size"])

os.makedirs(os.path.dirname(model_path), exist_ok=True)

# load dataset
# Expect file ./data/features.csv with feature columns
df = pd.read_csv("./data/features.csv")
X = df[features].values

# standardize
scaler = StandardScaler()
Xs = scaler.fit_transform(X)

# train
model = IsolationForest(n_estimators=200, contamination=0.01, random_state=42)
model.fit(Xs)

# save model and scaler together
with open(model_path, "wb") as f:
    pickle.dump((model, scaler), f)

print("Saved model to", model_path)
