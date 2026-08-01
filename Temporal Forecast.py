import matplotlib.pyplot as plt
import numpy as np

nodes = ['lb-frontend', 'user-ci-bot', 'pod-frontend', 'pod-ci-runner',
         'sa-ci', 'role-secret-reader', 'role-pod-exec', 'clusterrole-admin',
         'role-ci-deploy', 'secret-db-creds', 'secret-api-key',
         'secret-ci-token', 'db-production', 'db-analytics', 'secret-master-key']

current   = [8.44, 7.26, 8.21, 8.83, 9.50, 7.63, 9.28, 10.37,
             8.51, 10.32, 8.72, 9.42, 10.64, 9.28, 10.08]
projected = [9.69, 9.76, 9.47, 10.76, 9.72, 10.01, 10.78, 10.88,
             10.07, 11.69, 10.41, 9.71, 11.55, 10.55, 9.71]

x = np.arange(len(nodes))

fig, ax = plt.subplots(figsize=(13, 5))

ax.plot(x, current,   'o-',  color='#1f77b4', linewidth=2,
        markersize=6, label='Current Risk Score')
ax.plot(x, projected, 's--', color='#d62728', linewidth=2,
        markersize=6, label='Projected Risk (7 days)')

ax.fill_between(x, current, projected,
                where=[p > c for p, c in zip(projected, current)],
                alpha=0.12, color='#d62728', label='Rising zone')

ax.axhline(y=10, color='gray', linestyle=':', linewidth=1.2, alpha=0.7)
ax.text(14.2, 10.05, 'Critical threshold', fontsize=8, color='gray')

ax.set_xticks(x)
ax.set_xticklabels(nodes, rotation=40, ha='right', fontsize=9)
ax.set_ylabel('Risk Score', fontsize=12)
ax.set_xlabel('Kubernetes Nodes', fontsize=12)
ax.set_title('Temporal Risk Forecast — Current vs Projected Risk (7-Day)',
             fontsize=13, fontweight='bold')
ax.set_ylim(6, 13)
ax.legend(fontsize=10)
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.set_facecolor('#f9f9f9')
fig.patch.set_facecolor('white')

plt.tight_layout()
plt.savefig('fig7_temporal.png', dpi=200, bbox_inches='tight')
plt.show()