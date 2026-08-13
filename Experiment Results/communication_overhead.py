import matplotlib.pyplot as plt
import numpy as np

plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman']
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['mathtext.fontset'] = 'stix'

schemes = ['SGH$^{[12]}$', 'PQSH$^{[15]}$', 'SLL$^{[16]}$', 'Ours']
costs = [6291, 46572, 4321, 2720]
colors = ["#BED6F3",  "#D8BFF5", "#F3EEBF", "#C1F1C1"]

fig, ax = plt.subplots(figsize=(9, 5))

positions = [0, 1.5, 3.0, 4.5]
widths = [0.6, 0.6, 0.6, 0.6]

bars = []
for pos, cost, color, w in zip(positions, costs, colors, widths):
    bar = ax.bar(pos, cost, width=w, color=color, edgecolor='black', linewidth=1)
    bars.append(bar)

for pos, cost in zip(positions, costs):
    offset = 600 if cost > 40000 else 1000
    ax.text(pos, cost + offset, str(cost), ha='center', va='bottom', fontsize=14, fontweight='bold')

line_x = positions
line_y = costs
ax.plot(line_x, line_y, 'k--', linewidth=2, alpha=0.7)

ax.set_xlabel('Scheme', fontsize=16, fontweight='bold')
ax.set_ylabel('Communication Overhead (bits)', fontsize=16, fontweight='bold')

ax.set_xticks(positions)
ax.set_xticklabels(schemes, fontsize=13)

max_cost = max(costs)
ax.set_ylim(0, max_cost * 1.12)
ax.set_yticks(np.arange(0, max_cost + 5000, 5000))

ax.grid(True, axis='y', alpha=0.3)

plt.tight_layout()

plt.show()
