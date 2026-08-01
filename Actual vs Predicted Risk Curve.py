import matplotlib.pyplot as plt

samples = list(range(1,21))

actual = [
0,0,0,0,0,
0,0,1,0,0,
0,0,0,0,1,
0,0,0,1,0
]

predicted = [
0.02,0.08,0.04,0.12,0.06,
0.10,0.05,0.95,0.07,0.11,
0.03,0.08,0.06,0.14,0.91,
0.09,0.02,0.10,0.88,0.13
]

plt.figure(figsize=(12,6))

plt.plot(samples,predicted,'o-',label='XGBoost Probability')
plt.plot(samples,actual,'s-',label='Actual Label')

plt.xlabel("Test Samples")
plt.ylabel("Probability")
plt.title("Actual vs Predicted Risk")
plt.legend()
plt.grid(True)
plt.show()