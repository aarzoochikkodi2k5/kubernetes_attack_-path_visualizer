import matplotlib.pyplot as plt
from matplotlib.patches import Patch

nodes  = ['role-pod-exec', 'db-production', 'sa-ci', 'pod-ci-runner',
          'sa-backend', 'db-analytics', 'secret-master-key',
          'secret-ci-token', 'role-ci-deploy', 'secret-db-creds']
scores = [0.0913, 0.0888, 0.0878, 0.0830, 0.0743,
          0.0566, 0.0482, 0.0471, 0.0452, 0.0347]

colors = ['#d62728' if s >= 0.085 else
          '#ff7f0e' if s >= 0.045 else
          '#1f77b4' for s in scores]

fig, ax = plt.subplots(figsize=(9, 6))
bars = ax.barh(nodes[::-1], scores[::-1], color=colors[::-1],
               edgecolor='white', linewidth=0.5, height=0.6)

for bar, score in zip(bars, scores[::-1]):
    ax.annotate(f'{score:.4f}',
                xy=(bar.get_width(), bar.get_y() + bar.get_height()/2),
                xytext=(3, 0), textcoords="offset points",
                ha='left', va='center', fontsize=9)

ax.set_xlabel('PageRank Score', fontsize=12)
ax.set_title('Security PageRank — Top 10 Critical Nodes', fontsize=13, fontweight='bold')
ax.set_xlim(0, 0.115)
ax.grid(axis='x', linestyle='--', alpha=0.5)
ax.set_facecolor('#f9f9f9')
fig.patch.set_facecolor('white')

legend_elements = [Patch(facecolor='#d62728', label='Critical (>0.085)'),
                   Patch(facecolor='#ff7f0e', label='High (0.045–0.085)'),
                   Patch(facecolor='#1f77b4', label='Medium (<0.045)')]
ax.legend(handles=legend_elements, fontsize=9, loc='lower right')

plt.tight_layout()
plt.savefig('fig6_pagerank.png', dpi=200, bbox_inches='tight')
plt.show()