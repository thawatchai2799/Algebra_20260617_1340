# -*- coding: utf-8 -*-
"""Figure: the worked normalization example of Section 7, drawn to scale."""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

fig, ax = plt.subplots(figsize=(7.2, 4.8), dpi=1200)
for (x0, w) in [(0, 22), (23, 77)]:
    ax.add_patch(Rectangle((x0, 0), w, 100, facecolor='0.93', edgecolor='black', lw=1.3, zorder=1))
for (x0, w) in [(0, 22), (23, 27)]:
    ax.add_patch(Rectangle((x0, 0), w, 50, facecolor='0.62', edgecolor='black', lw=1.0, zorder=2))
ax.add_patch(Rectangle((0, 0), 50, 50, fill=False, edgecolor='#1f4e9c', lw=2.0, ls=(0, (5, 3)), zorder=4))
ax.add_patch(Rectangle((22, 50), 1, 50, facecolor='#d95f5f', alpha=0.55, edgecolor='#a01f1f', lw=1.6, ls=(0, (3, 2)), zorder=4))

ax.annotate('r1: NACL denies p = 22 for s \u2208 [0,255]\n(drawn up to s = 100)', xy=(22.5, 38), xytext=(55, 33),
            fontsize=9.5, ha='left', va='center', arrowprops=dict(arrowstyle='->', lw=1.0))
ax.annotate('m2 \u2014 dead: m2 \u2229 A(N) = \u2205', xy=(23.0, 66), xytext=(33, 70),
            fontsize=9.5, ha='left', va='center', color='#a01f1f',
            arrowprops=dict(arrowstyle='->', lw=1.1, color='#a01f1f'))
ax.annotate('m1 (SG allow)', xy=(49.6, 42), xytext=(58, 55),
            fontsize=9.5, ha='left', va='center', color='#1f4e9c',
            arrowprops=dict(arrowstyle='->', lw=1.2, color='#1f4e9c'))
ax.annotate('\u03a6 (two disjoint boxes) = N* = G*', xy=(36.5, 20), xytext=(56, 24),
            fontsize=9.5, ha='left', va='center', arrowprops=dict(arrowstyle='->', lw=1.2))
ax.text(3, 94, 'r2 (NACL allow): the whole frame', fontsize=9.5)
ax.text(8, 76, 'A(N)', fontsize=11, style='italic')
ax.text(82, 76, 'A(N)', fontsize=11, style='italic')
ax.text(9, 41, '\u03a6', fontsize=13, style='italic', weight='bold')
ax.text(34, 41, '\u03a6', fontsize=13, style='italic', weight='bold')
ax.set_xlim(0, 100); ax.set_ylim(0, 100)
ax.set_xticks([0, 22, 50, 100]); ax.set_yticks([0, 50, 100])
ax.set_xlabel('destination port p', fontsize=11)
ax.set_ylabel('source s', fontsize=11)
plt.tight_layout()
plt.savefig('worked_example.png', dpi=1200)
plt.savefig('worked_example.pdf')
print('saved')
