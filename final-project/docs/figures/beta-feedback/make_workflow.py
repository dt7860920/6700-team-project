"""Scan workflow with each outside-tester issue (#27-#67) pinned to the stage it traces to.

Same look as 1a_theme_lollipop_classic.png (make_charts.py). Usage: python make_workflow.py OUT_DIR
"""
import sys
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)

# ---- team classic palette ----
BG, C_INDIGO, C_NAVY, C_TINT = "#FFF8F0", "#1D1F68", "#102542", "#E9EEF6"

# ---- data: (stage, where in the code, issue theme at that stage, issues) ----
STAGES = [
    ("Gradio UI / HTTP API", "ui.py · api.py", "Validation and labels", (29, 41, 58, 59, 60)),
    ("Scan service", "service.py · allowlist, bounded queue", "Limits and access", (34, 46, 61)),
    ("Preflight", "analyzer.py · checks executor, not model", "Model outage", (48, 49, 50, 52, 53, 55, 56, 57)),
    ("Ingest", "ingest.py · clone repo or write snippet.py", "Python-only snippets", (35, 43)),
    ("SAST shortlist", "sast.py · Semgrep, regex fallback", "Missed sinks", (27, 33, 38)),
    ("Agent analysis", "orchestrator.py · planner + analyst", "Wrong dismissals", (30, 44, 65, 66, 67)),
    ("Verify", "analyzer.py · pass-through, never verifies", "Verified label mismatch", (62, 63, 64)),
    ("Filter and summarize", "analyzer.py · min_rung, max_findings", "Misleading empty results", (28, 31, 39, 40, 45, 51, 54)),
    ("Scan store", "store.py · in memory, ids shared across scans", "Id collision, memory only", (32, 37, 42)),
]
UNMAPPED = (36,)  # docs: not tied to a pipeline stage
assert sum(len(s[3]) for s in STAGES) + len(UNMAPPED) == 40

plt.rcParams.update({
    "font.family": "Helvetica Neue", "font.size": 11, "text.color": C_NAVY,
    "figure.facecolor": BG, "axes.facecolor": BG, "savefig.facecolor": BG,
})

n = len(STAGES)
fig, ax = plt.subplots(figsize=(10, 8.6))
ax.set_xlim(0, 100); ax.set_ylim(-0.55, n - 0.45)
ax.axis("off")

BOX_X, BOX_W, BOX_H = 0, 41, 0.72
HEAD_X, LABEL_X = 50, 54

for i, (stage, where, theme, issues) in enumerate(STAGES):
    y = n - 1 - i
    # stage box
    ax.add_patch(FancyBboxPatch((BOX_X, y - BOX_H / 2), BOX_W, BOX_H,
                                boxstyle="round,pad=0,rounding_size=0.12", mutation_aspect=1 / 8,
                                fc=C_TINT, ec=C_NAVY, lw=0.8, zorder=2))
    ax.text(BOX_X + 2, y + 0.12, stage, va="center", fontsize=11.5, fontweight="bold", color=C_NAVY, zorder=3)
    ax.text(BOX_X + 2, y - 0.16, where, va="center", fontsize=9, color=C_NAVY, alpha=0.7, zorder=3)
    # flow arrow to the next stage
    if i < n - 1:
        ax.add_patch(FancyArrowPatch((BOX_W / 2, y - BOX_H / 2), (BOX_W / 2, y - 1 + BOX_H / 2),
                                     arrowstyle="-|>", mutation_scale=11, color=C_NAVY, lw=1.1,
                                     shrinkA=1, shrinkB=1, zorder=1))
    # lollipop stem + head carrying the issue count
    ax.plot([BOX_X + BOX_W, HEAD_X], [y, y], color=C_INDIGO, lw=2.5, solid_capstyle="butt", zorder=2)
    ax.scatter(HEAD_X, y, s=420, c=C_INDIGO, edgecolors=BG, linewidths=2, zorder=3)
    ax.text(HEAD_X, y, str(len(issues)), ha="center", va="center", fontsize=10, color=BG, fontweight="bold", zorder=4)
    # theme + the issues behind it
    ax.text(LABEL_X, y + 0.12, theme, va="center", fontsize=11.5, fontweight="bold", color=C_NAVY)
    ax.text(LABEL_X, y - 0.16, "  ".join(f"#{k}" for k in sorted(issues)), va="center", fontsize=9,
            color=C_NAVY, alpha=0.7)

fig.tight_layout(rect=(0, 0.03, 1, 0.9))
x0 = ax.get_position().x0
fig.text(x0, 0.965, "Where tester issues land in the scan pipeline", fontsize=15, fontweight="bold", color=C_NAVY, va="top")
fig.text(x0, 0.925, "A scan runs top to bottom; each circle counts the outside-tester issues that trace to that stage",
         fontsize=10.5, color=C_NAVY, alpha=0.7, va="top")
fig.text(x0, 0.02, f"39 of 40 issues shown; {', '.join(f'#{k}' for k in UNMAPPED)} (missing user brief) is docs-only.",
         fontsize=9, color=C_NAVY, alpha=0.7, va="bottom")
fig.savefig(OUT / "7_workflow_issue_map.png", dpi=200); plt.close(fig)
print("wrote", OUT / "7_workflow_issue_map.png")
