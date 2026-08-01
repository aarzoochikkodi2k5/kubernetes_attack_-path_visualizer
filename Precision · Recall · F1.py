import matplotlib.pyplot as plt
import numpy as np

labels = ['Safe (0)', 'Risky (1)', 'Macro avg', 'Weighted avg']
precision = [1.00, 0.75, 0.88, 0.96]
recall    = [0.94, 1.00, 0.97, 0.95]
f1        = [0.97, 0.86, 0.91, 0.95]

x = np.arange(len(labels))
width = 0.25

fig, ax = plt.subplots(figsize=(9, 5))

b1 = ax.bar(x - width, precision, width, label='Precision', color='#1f77b4', edgecolor='white', linewidth=0.5)
b2 = ax.bar(x,         recall,    width, label='Recall',    color='#ff7f0e', edgecolor='white', linewidth=0.5)
b3 = ax.bar(x + width, f1,        width, label='F1-Score',  color='#2ca02c', edgecolor='white', linewidth=0.5)

for bars in [b1, b2, b3]:
    for bar in bars:
        ax.annotate(f'{bar.get_height():.2f}',
                    xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                    xytext=(0, 3), textcoords="offset points",
                    ha='center', va='bottom', fontsize=9)

ax.set_xlabel('Class', fontsize=12)
ax.set_ylabel('Score', fontsize=12)
ax.set_title('Precision, Recall and F1-Score by Class — XGBoost', fontsize=13, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(labels, fontsize=11)
ax.set_ylim(0, 1.12)
ax.legend(fontsize=10)
ax.grid(axis='y', linestyle='--', alpha=0.5)
ax.set_facecolor('#f9f9f9')
fig.patch.set_facecolor('white')
plt.tight_layout()
plt.savefig('fig5_precision_recall_f1.png', dpi=200, bbox_inches='tight')
plt.show()