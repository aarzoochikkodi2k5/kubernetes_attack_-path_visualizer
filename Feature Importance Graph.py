import matplotlib.pyplot as plt

features = [
    'avg_in_cvss',
    'num_cves',
    'in_cycle',
    'misconfig_edge',
    'pagerank',
    'closeness',
    'betweenness',
    'out_edge_weight_avg',
    'risk_score',
    'clustering_coef'
]

importance = [
    0.2859,
    0.2022,
    0.1382,
    0.1247,
    0.0845,
    0.0310,
    0.0302,
    0.0219,
    0.0206,
    0.0169
]

plt.figure(figsize=(10,6))
plt.barh(features, importance)
plt.xlabel("Importance Score")
plt.title("XGBoost Feature Importance")
plt.tight_layout()
plt.show()