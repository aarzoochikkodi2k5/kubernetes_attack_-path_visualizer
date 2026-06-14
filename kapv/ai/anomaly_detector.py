# ai/anomaly_detector.py

"""
REACTIVE AI: Isolation Forest for anomalous node detection.

Problem: We don't know what "attack" looks like in advance (no labels).
Isolation Forest is an UNSUPERVISED anomaly detector. It works by:
  - Randomly partitioning the feature space
  - Anomalies require FEWER splits to isolate (they're outliers)
  - Score close to 1 = anomaly; close to 0 = normal

Security interpretation:
A node that is structurally unlike all others is EITHER:
  (a) a misconfiguration anomaly — should be investigated
  (b) a compromised node behaving unusually

This makes KAPV REACTIVE: even without pre-defined attack signatures,
it flags structurally unusual nodes in real-time.
"""

import numpy as np
from typing import Dict, List

def detect_anomalous_nodes(G, feature_data: np.ndarray, node_ids: List[str]) -> Dict:
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        raise ImportError("Required packages missing. Install them using: pip install scikit-learn")

    scaler = StandardScaler()
    X = scaler.fit_transform(feature_data)

    iso = IsolationForest(
        n_estimators  = 200,
        contamination = 0.1,    # Assume 10% of nodes are anomalous
        random_state  = None,
    )
    iso.fit(X)

    scores     = iso.decision_function(X)   # More negative = more anomalous
    predictions = iso.predict(X)            # -1 = anomaly, 1 = normal

    # Normalise to [0, 1] anomaly score (1 = most anomalous)
    anomaly_scores = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)

    results = {
        node_ids[i]: {
            "anomaly_score":    round(float(anomaly_scores[i]), 4),
            "is_anomaly":       bool(predictions[i] == -1),
            "raw_score":        round(float(scores[i]), 4),
        }
        for i in range(len(node_ids))
    }

    anomalies = {k: v for k, v in results.items() if v["is_anomaly"]}
    anomalies_sorted = sorted(anomalies.items(), key=lambda x: x[1]["anomaly_score"], reverse=True)

    return {
        "all_scores":       results,
        "anomaly_count":    len(anomalies),
        "top_anomalies":    anomalies_sorted[:10],
    }