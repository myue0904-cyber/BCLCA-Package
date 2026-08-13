import matplotlib.pyplot as plt
import numpy as np

plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman']
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['mathtext.fontset'] = 'stix'

schemes = ['SGH$^{[12]}$', 'PQSH$^{[15]}$', 'SLL$^{[16]}$', 'Ours']

costs = [220.8, 186, 115.2, 108]
colors = ["#BED6F3", "#D8BFF5", "#F3EEBF", "#C1F1C1"]
positions = [0, 1.5, 3.0, 4.5]
widths = [0.6, 0.6, 0.6, 0.6]    

fig, ax = plt.subplots(figsize=(9, 5))


bars = []
for pos, cost, w, color in zip(positions, costs, widths, colors):
    bar = ax.bar(pos, cost, width=w, color=color, edgecolor='black', linewidth=0.8)
    bars.append(bar)

offset = 4
for pos, cost in zip(positions, costs):
    label = f"{cost:.1f}".rstrip('0').rstrip('.') if isinstance(cost, float) and cost % 1 != 0 else str(int(cost))
    ax.text(pos, cost + offset, label, ha='center', va='bottom', fontsize=12, fontweight='bold')

ax.plot(positions, costs, 'k--', linewidth=1.5, alpha=0.6, zorder=2) 

ax.set_xlabel('Scheme', fontsize=14, fontweight='bold')
ax.set_ylabel('Computation time (µs)', fontsize=14, fontweight='bold')

ax.set_xticks(positions)
ax.set_xticklabels(schemes, fontsize=11, rotation=0)

y_max = max(costs) + offset * 2
ax.set_ylim(0, y_max)
ax.set_yticks(np.arange(0, 300, 50))   
ax.tick_params(axis='y', labelsize=11)

ax.grid(axis='y', linestyle='--', alpha=0.3, color='gray')

ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_linewidth(0.8)
ax.spines['bottom'].set_linewidth(0.8)

ax.text(1.9, -10, 'Group in [15]', ha='center', va='top', fontsize=10, color='gray',
        transform=ax.get_xaxis_transform())

plt.tight_layout()

plt.show()
