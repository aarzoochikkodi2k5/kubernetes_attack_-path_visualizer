import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np

cm = np.array([
    [16,1],
    [0,3]
])

sns.heatmap(
    cm,
    annot=True,
    fmt='d',
    xticklabels=['Safe','Risky'],
    yticklabels=['Safe','Risky']
)

plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix")
plt.show()