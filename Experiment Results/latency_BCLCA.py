import numpy as np
import matplotlib.pyplot as plt

plt.rcParams['font.family'] = 'Times New Roman'
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['mathtext.fontset'] = 'stix'  

x = np.linspace(0, 512, 100)


y1 = 397.35 + 3.7529 * x


y2_c3 = 643.08 + 5.67 * x  
y3 = 336.85 + 1.87713 * x    
y_proposed = 339.76 + 1.877 * x  

plt.figure(figsize=(9, 5))

plt.plot(x, y1, 'o-', color='#4A90E2', linewidth=2, markersize=6, markevery=15, label=r'95th percentile "SGH$^{[12]}$" latency at 1e-06 BER')
plt.plot(x, y2_c3, 'd-', color='#E24A4A', linewidth=2, markersize=6, markevery=15, label=r'95th percentile "PQSH$^{[15]}$" latency at 1e-06 BER')
plt.plot(x, y3, 'x-', color="#D4C117", linewidth=2, markersize=6, markevery=15, label=r'95th percentile "SLL$^{[16]}$" latency at 1e-06 BER')
plt.plot(x, y_proposed, 'v-', color="#4AE24A", linewidth=2, markersize=6, markevery=15, label=r'95th percentile "Ours" latency at 1e-06 BER')

plt.xlim(0, 512)
plt.ylim(0, 4500)


plt.xlabel('Amount of AS in LDACS cell', fontsize=16, fontweight='bold')
plt.ylabel('Latency (ms)', fontsize=16, fontweight='bold')


plt.grid(True, alpha=0.3)

plt.legend(fontsize=14)

plt.tight_layout()

plt.show()