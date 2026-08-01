import matplotlib.pyplot as plt

nodes = [
    "pod-ci-runner",
    "pod-ci-runner-2",
    "pod-frontend",
    "pod-frontend-2",
    "db-analytics",
    "db-production",
    "pod-queue",
    "role-pod-exec",
    "pod-api-server",
    "role-ci-deploy"
]

risk = [
    0.9962,
    0.9961,
    0.9948,
    0.9706,
    0.9575,
    0.9352,
    0.9228,
    0.9141,
    0.8837,
    0.8114
]

plt.figure(figsize=(12,6))
plt.plot(nodes, risk, marker='o')
plt.xticks(rotation=45)
plt.ylabel("Predicted Risk Probability")
plt.xlabel("Kubernetes Nodes")
plt.title("XGBoost Predicted Risk Scores")
plt.grid(True)
plt.tight_layout()
plt.show()