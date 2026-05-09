# ai/temporal_analyzer.py

"""
PREDICTIVE AI: Graph delta analysis + trend forecasting.

Two capabilities:
1. DIFF: Compare two graph snapshots and surface NEW attack paths.
   This is REACTIVE to changes — alerts when cluster changes create risk.

2. TREND FORECASTING: Use a simple regression over risk score history
   to PREDICT which nodes will become high-risk in the next N days.
   This is PREDICTIVE — anticipates risk before it materialises.

In a production system, this would run on a cron job every 15 minutes,
storing snapshots to a time-series database (e.g., InfluxDB or Prometheus).
"""

import networkx as nx
import numpy as np
from typing import Dict, List, Optional
from datetime import datetime


def diff_graphs(G_old: nx.DiGraph, G_new: nx.DiGraph) -> Dict:
    """
    Structural diff between two cluster snapshots.
    Identifies: new nodes, removed nodes, new edges, removed edges,
    and — most critically — NEW ATTACK PATHS that didn't exist before.
    """
    old_nodes = set(G_old.nodes())
    new_nodes = set(G_new.nodes())
    old_edges = set(G_old.edges())
    new_edges = set(G_new.edges())

    added_nodes   = new_nodes - old_nodes
    removed_nodes = old_nodes - new_nodes
    added_edges   = new_edges - old_edges
    removed_edges = old_edges - new_edges

    # Check if any added edges create NEW paths to crown jewels
    crown_jewels = [n for n, d in G_new.nodes(data=True) if d.get("crown", False)]
    entry_points = [n for n, d in G_new.nodes(data=True) if d.get("entry", False)]

    new_attack_paths = []
    for ep in entry_points:
        for cj in crown_jewels:
            # Check if path existed before
            old_reachable = nx.has_path(G_old, ep, cj) if ep in G_old and cj in G_old else False
            new_reachable = nx.has_path(G_new, ep, cj) if ep in G_new and cj in G_new else False

            if new_reachable and not old_reachable:
                path = nx.shortest_path(G_new, ep, cj, weight="weight")
                new_attack_paths.append({
                    "source":   ep,
                    "target":   cj,
                    "path":     path,
                    "severity": "CRITICAL — New attack path created by cluster change!",
                })

    return {
        "snapshot_time":    datetime.utcnow().isoformat(),
        "added_nodes":      list(added_nodes),
        "removed_nodes":    list(removed_nodes),
        "added_edges":      [f"{u}→{v}" for u, v in added_edges],
        "removed_edges":    [f"{u}→{v}" for u, v in removed_edges],
        "new_attack_paths": new_attack_paths,
        "alert_level":      "CRITICAL" if new_attack_paths else "CLEAR",
    }


def forecast_node_risk(
    risk_history: Dict[str, List[float]],
    forecast_days: int = 7
) -> Dict:
    """
    Given a time series of risk scores per node (e.g., collected daily),
    fit a linear regression and forecast future risk.

    This is PREDICTIVE: it flags nodes whose risk is TRENDING UPWARD
    even if they are currently below the alert threshold.

    Example risk_history:
    {
        "pod-frontend": [3.1, 3.4, 3.8, 4.2, 4.7],  # trending up → ALERT
        "pod-backend":  [5.0, 5.0, 5.1, 4.9, 5.0],  # stable → OK
    }
    """
    try:
        from sklearn.linear_model import LinearRegression
    except ImportError:
        raise ImportError("Required packages missing. Install them using: pip install scikit-learn")

    forecasts = {}
    for node, history in risk_history.items():
        if len(history) < 2:
            continue

        X = np.arange(len(history)).reshape(-1, 1)
        y = np.array(history)

        model = LinearRegression()
        model.fit(X, y)

        # Forecast next N days
        future_X = np.arange(len(history), len(history) + forecast_days).reshape(-1, 1)
        future_y = model.predict(future_X)

        slope = float(model.coef_[0])
        projected_risk = float(future_y[-1])

        forecasts[node] = {
            "current_risk":     history[-1],
            "slope":            round(slope, 4),
            "projected_risk":   round(projected_risk, 2),
            "trend":            "RISING" if slope > 0.1 else "FALLING" if slope < -0.1 else "STABLE",
            "alert":            projected_risk >= 8.0,
        }

    rising = {k: v for k, v in forecasts.items() if v["alert"]}

    return {
        "forecasts":         forecasts,
        "at_risk_nodes":     list(rising.keys()),
        "forecast_days":     forecast_days,
    }