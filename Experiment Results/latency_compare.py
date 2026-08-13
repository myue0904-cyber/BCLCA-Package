import numpy as np
import matplotlib.pyplot as plt

plt.rcParams['font.family'] = 'Times New Roman'
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['mathtext.fontset'] = 'stix'  

x = np.linspace(0, 512, 50)
   
y1 = 231 + 1.877 * x
y2 = 346.76 + 1.877 * x
y3 = 355.18 + 1.896 * x  

plt.figure(figsize=(9, 5))

plt.plot(x, y1, '#4A90E2', linewidth=2, marker='^', markersize=4, markevery=15, label=r'Min"Ours" latency at 1e-05/1e-06 BER')
plt.plot(x, y2, "#21D121", linewidth=2, marker='s', markersize=4, markevery=15, label=r'95th percentile "Ours" latency at 1e-06 BER')
plt.plot(x, y3, "#E6D329", linewidth=2, marker='o', markersize=4, markevery=15, label=r'95th percentile "Ours" latency at 1e-05 BER')

plt.xlim(0, 512)
plt.ylim(0, 2000)

plt.xlabel('Amount of AS in LDACS cell', fontsize=16, fontweight='bold')
plt.ylabel('Latency (ms)', fontsize=16, fontweight='bold')

plt.grid(True, alpha=0.3)

plt.legend(fontsize=14)


plt.tight_layout()

plt.show()