import matplotlib.pyplot as plt
import numpy as np

metrics = ['Attack paths\ndetected', 'Privilege\ncycles',
           'Misconfigs\nfound', 'XGBoost\naccuracy (%)', 'Anomalies\ndetected']

kapv       = [8,  2, 29, 95, 3]
kubebench  = [0,  0, 12,  0, 0]
genkubesec = [0,  0, 18,  0, 0]

x = np.arange(len(metrics))
width = 0.26

fig, ax = plt.subplots(figsize=(10, 5))

b1 = ax.bar(x - width, kapv,       width, label='KAPV (ours)',
            color='#d62728', edgecolor='white', linewidth=0.5)
b2 = ax.bar(x,         kubebench,  width, label='kube-bench',
            color='#7f7f7f', edgecolor='white', linewidth=0.5)
b3 = ax.bar(x + width, genkubesec, width, label='GenKubeSec',
            color='#bcbd22', edgecolor='white', linewidth=0.5)

for bars in [b1, b2, b3]:
    for bar in bars:
        h = bar.get_height()
        if h > 0:
            ax.annotate(f'{int(h)}',
                        xy=(bar.get_x() + bar.get_width()/2, h),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=9)

ax.set_xlabel('Detection Metric', fontsize=12)
ax.set_ylabel('Count / Accuracy (%)', fontsize=12)
ax.set_title('KAPV vs Baseline Tools — Detection Capability Comparison',
             fontsize=13, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(metrics, fontsize=10)
ax.legend(fontsize=10)
ax.set_ylim(0, 110)
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.set_facecolor('#f9f9f9')
fig.patch.set_facecolor('white')

plt.tight_layout()
plt.savefig('fig8_comparison.png', dpi=200, bbox_inches='tight')
plt.show()