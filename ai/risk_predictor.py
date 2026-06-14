# ai/risk_predictor.py

"""
Supervised Learning: Predict which nodes are HIGH RISK based on 
structural graph features — even if their static risk_score is low.

Why this matters:
A node with risk_score=3 that has HIGH degree centrality, is in a cycle, 
and has 3 CVEs is ACTUALLY more dangerous than the score suggests.
ML captures this compound effect.

Model: Gradient Boosted Trees (XGBoost) — handles tabular features well,
produces feature importances, and is interpretable via SHAP.
"""

import networkx as nx
import numpy as np
from typing import Dict, List, Tuple
import warnings
warnings.filterwarnings("ignore")

def extract_node_features(G: nx.DiGraph) -> Tuple[np.ndarray, List[str], List[str]]:
    """
    Extract graph-structural + domain features for each node.
    
    Features:
    1. in_degree              — how many nodes point to this node
    2. out_degree             — how many nodes this node can reach
    3. risk_score             — static score from cluster metadata
    4. num_cves               — count of known CVEs
    5. is_misconfig_neighbor  — has misconfigured edges
    6. pagerank               — structural importance
    7. clustering_coef        — local graph density (undirected)
    8. in_edge_avg_cvss       — average CVSS of incoming edges
    9. is_in_cycle            — participates in a permission cycle
    10. namespace_entropy     — is the node in a high-traffic namespace?
    """
    pr = nx.pagerank(G, weight="weight")
    UG = G.to_undirected()
    cc = nx.clustering(UG)

    # Precompute cycles
    cycle_nodes = set()
    for cycle in nx.simple_cycles(G):
        cycle_nodes.update(cycle)

    feature_matrix = []
    node_ids = []
    feature_names = [
        "in_degree", "out_degree", "risk_score", "num_cves",
        "misconfig_edge", "pagerank", "clustering_coef",
        "avg_in_cvss", "in_cycle", "out_edge_weight_avg"
    ]

    for node in G.nodes():
        d = G.nodes[node]
        in_edges  = list(G.in_edges(node, data=True))
        out_edges = list(G.out_edges(node, data=True))

        in_cvss = ([e[2].get("cvss", 0) for e in in_edges])
        out_w   = ([e[2].get("weight", 0) for e in out_edges])
        misconfig = any(e[2].get("misconfig", False) for e in in_edges + out_edges)

        features = [
            G.in_degree(node),
            G.out_degree(node),
            d.get("risk_score", d.get("risk", 0)),
            len(d.get("cves", [])),
            int(misconfig),
            pr.get(node, 0),
            cc.get(node, 0),
            np.mean(in_cvss) if in_cvss else 0,
            int(node in cycle_nodes),
            np.mean(out_w) if out_w else 0,
        ]
        feature_matrix.append(features)
        node_ids.append(node)

    return np.array(feature_matrix), node_ids, feature_names


def train_risk_model(G: nx.DiGraph) -> Dict:
    """
    Since we have no labelled training data (it's a new cluster), 
    we use a SELF-SUPERVISED approach:

    Label = 1 (HIGH RISK) if:
        - node is crown jewel, OR
        - node is in a detected cycle AND risk_score > 6, OR
        - node has CVEs AND betweenness > median betweenness

    This generates pseudo-labels from graph structure itself,
    then trains a classifier to generalise to unseen nodes.
    
    In production: replace pseudo-labels with security analyst annotations.
    """
    try:
        import xgboost as xgb
        from sklearn.preprocessing import StandardScaler
        from sklearn.model_selection import cross_val_score
    except ImportError:
        raise ImportError("Required packages missing. Install them using: pip install xgboost scikit-learn")

    X, node_ids, feature_names = extract_node_features(G)

    # Generate pseudo-labels
    bc = nx.betweenness_centrality(G)
    bc_median = np.median(list(bc.values()))
    cycle_nodes = set(n for c in nx.simple_cycles(G) for n in c)

    y = []
    for node in node_ids:
        d = G.nodes[node]
        is_crown     = d.get("crown", False)
        risk         = d.get("risk_score", d.get("risk", 0))
        has_cves     = len(d.get("cves", [])) > 0
        in_cycle     = node in cycle_nodes
        high_between = bc.get(node, 0) > bc_median

        label = int(
            is_crown or
            (in_cycle and risk > 6) or
            (has_cves and high_between)
        )
        y.append(label)

    y = np.array(y)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = xgb.XGBClassifier(
        n_estimators    = 100,
        max_depth       = 4,
        learning_rate   = 0.1,
        use_label_encoder = False,
        eval_metric     = "logloss",
        random_state    = 42,
    )
    model.fit(X_scaled, y)

    # Cross-validation accuracy
    scores = cross_val_score(model, X_scaled, y, cv=3, scoring="f1")

    # Predict risk for all nodes
    proba = model.predict_proba(X_scaled)[:, 1]
    predictions = {
        node_ids[i]: {
            "predicted_risk_proba": round(float(proba[i]), 4),
            "label": int(y[i]),
            "features": dict(zip(feature_names, X[i].tolist())),
        }
        for i in range(len(node_ids))
    }

    # Feature importances
    importances = dict(zip(feature_names, model.feature_importances_.tolist()))

    return {
        "model":            model,
        "scaler":           scaler,
        "predictions":      predictions,
        "cv_f1_mean":       round(float(np.mean(scores)), 4),
        "feature_names":    feature_names,
        "feature_importances": importances,
        "top_predicted_risks": sorted(
            predictions.items(),
            key=lambda x: x[1]["predicted_risk_proba"],
            reverse=True
        )[:10],
    }