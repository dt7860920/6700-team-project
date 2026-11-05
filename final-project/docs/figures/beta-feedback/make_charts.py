"""Four charts summarizing outside beta-tester feedback (GitHub issues #27-#67)."""
import sys
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import FancyBboxPatch

OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)

# ---- palette (team: floral white / navy / indigo / crimson; validated) ----
BG = "#FFF8F0"
INK = "#102542"
MUTED = "#5A6478"
GRID = "#E4DDD3"
BUG, DESIGN, OBS = "#B3001B", "#3D3FA8", "#2E86C1"
TYPE_COLORS = {"Bug": BUG, "Design question": DESIGN, "Observation": OBS}

# ---- data ----
THEMES = [
    "Model endpoint outage",
    "Missed / wrongly dismissed vulns",
    "Data, access & persistence",
    "Contradictory labels",
    "API validation & limits",
    "Misleading empty results",
    "Docs",
]
THEME = {}
for n in (48, 49, 50, 52, 53, 55, 56, 57): THEME[n] = THEMES[0]
for n in (27, 66, 67, 38, 33, 65, 35): THEME[n] = THEMES[1]
for n in (37, 61, 42, 32, 60, 43, 59): THEME[n] = THEMES[2]
for n in (64, 63, 62, 30, 58, 44): THEME[n] = THEMES[3]
for n in (29, 41, 39, 45, 34, 46): THEME[n] = THEMES[4]
for n in (28, 31, 40, 51, 54): THEME[n] = THEMES[5]
THEME[36] = THEMES[6]

BUGS = {48, 49, 50, 27, 66, 67, 38, 65, 28, 40, 64, 63, 30, 29, 41, 39, 37}
OBSERVATIONS = {51, 52}
def kind(n): return "Bug" if n in BUGS else "Observation" if n in OBSERVATIONS else "Design question"

TESTERS = [  # (login, first issue, last issue, date filed)
    ("normangw", 27, 36, "Nov 2"),
    ("kenqin0221", 37, 46, "Nov 3"),
    ("hz475-byte", 48, 57, "Nov 4"),
    ("pangy8869898", 58, 67, "Nov 5"),
]
def tester(n):
    for login, lo, hi, _ in TESTERS:
        if lo <= n <= hi: return login

ISSUES = sorted(THEME)
assert len(ISSUES) == 40
TYPES = list(TYPE_COLORS)

plt.rcParams.update({
    "font.family": "Helvetica Neue", "font.size": 11, "text.color": INK,
    "axes.labelcolor": MUTED, "xtick.color": MUTED, "ytick.color": INK,
    "figure.facecolor": BG, "axes.facecolor": BG, "savefig.facecolor": BG,
})

def frame(ax, title, subtitle):
    ax.set_title(title, loc="left", fontsize=15, fontweight="bold", color=INK, pad=28)
    ax.text(0, 1.02, subtitle, transform=ax.transAxes, fontsize=10.5, color=MUTED, va="bottom")
    for s in ("top", "right", "left"): ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(axis="y", length=0, pad=8)
    ax.tick_params(axis="x", length=0)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)

def rbar(ax, y, left, width, h, color, round_end):
    """Horizontal bar segment; the outer data-end gets a small rounded cap."""
    gap = 0.06  # surface gap between stacked segments
    w = max(width - gap, 0.01)
    ax.add_patch(plt.Rectangle((left, y - h / 2), w, h, fc=color, ec="none"))

def legend(ax, items, y=1.0):
    handles = [plt.Rectangle((0, 0), 1, 1, fc=c, ec="none") for _, c in items]
    ax.legend(handles, [l for l, _ in items], loc="lower right", bbox_to_anchor=(1, y), ncol=len(items),
              frameon=False, fontsize=10, handlelength=1, handleheight=1, borderaxespad=0.2, labelcolor=INK)

# ---------------- 1. volume by theme ----------------
counts = {t: sum(THEME[n] == t for n in ISSUES) for t in THEMES}
order = sorted(THEMES, key=lambda t: counts[t])
fig, ax = plt.subplots(figsize=(10, 5.2))
for i, t in enumerate(order):
    rbar(ax, i, 0, counts[t], 0.6, DESIGN, True)
    ax.text(counts[t] + 0.12, i, str(counts[t]), va="center", fontsize=11, color=INK, fontweight="bold")
ax.set_yticks(range(len(order)), order)
ax.set_xlim(0, 9.2); ax.set_ylim(-0.6, len(order) - 0.4)
ax.set_xlabel("Issues")
frame(ax, "What testers wrote about", "40 issues from 4 outside beta testers, grouped by theme")
fig.tight_layout(); fig.savefig(OUT / "1_feedback_by_theme.png", dpi=200); plt.close(fig)

# ---------------- 2. type within each theme ----------------
fig, ax = plt.subplots(figsize=(10, 5.4))
for i, t in enumerate(order):
    left = 0
    segs = [(k, sum(THEME[n] == t and kind(n) == k for n in ISSUES)) for k in TYPES]
    segs = [(k, v) for k, v in segs if v]
    for j, (k, v) in enumerate(segs):
        rbar(ax, i, left, v, 0.6, TYPE_COLORS[k], j == len(segs) - 1)
        if v >= 1:
            ax.text(left + (v - 0.06) / 2, i, str(v), ha="center", va="center", fontsize=9.5, color="white", fontweight="bold")
        left += v
ax.set_yticks(range(len(order)), order)
ax.set_xlim(0, 9.2); ax.set_ylim(-0.6, len(order) - 0.4)
ax.set_xlabel("Issues")
frame(ax, "Bugs vs. design questions by theme",
      f"{len(BUGS)} bugs, {sum(kind(n)=='Design question' for n in ISSUES)} design questions, {len(OBSERVATIONS)} observations")
legend(ax, [(k, c) for k, c in TYPE_COLORS.items()], y=1.075)
fig.tight_layout(); fig.savefig(OUT / "2_type_by_theme.png", dpi=200); plt.close(fig)

# ---------------- 3. type per tester ----------------
fig, ax = plt.subplots(figsize=(10, 4.2))
rows = list(reversed(TESTERS))
for i, (login, lo, hi, day) in enumerate(rows):
    left = 0
    segs = [(k, sum(tester(n) == login and kind(n) == k for n in ISSUES)) for k in TYPES]
    segs = [(k, v) for k, v in segs if v]
    for j, (k, v) in enumerate(segs):
        rbar(ax, i, left, v, 0.58, TYPE_COLORS[k], j == len(segs) - 1)
        ax.text(left + (v - 0.06) / 2, i, str(v), ha="center", va="center", fontsize=9.5, color="white", fontweight="bold")
        left += v
ax.set_yticks(range(len(rows)), [f"{l}  ·  {d}" for l, _, _, d in rows])
for lbl in ax.get_yticklabels(): lbl.set_linespacing(1.4)
ax.set_xlim(0, 10.3); ax.set_ylim(-0.6, len(rows) - 0.4)
ax.set_xlabel("Issues")
frame(ax, "Feedback per tester", "Each tester filed 10 issues on a single day, Nov 2–5")
legend(ax, [(k, c) for k, c in TYPE_COLORS.items()], y=1.09)
fig.tight_layout(); fig.savefig(OUT / "3_type_by_tester.png", dpi=200); plt.close(fig)

# ---------------- 4. tester x theme heatmap ----------------
cols = [t for t in reversed(order)]  # largest theme first
logins = [l for l, *_ in TESTERS]
M = [[sum(tester(n) == l and THEME[n] == t for n in ISSUES) for t in cols] for l in logins]
cmap = LinearSegmentedColormap.from_list("indigo", ["#F3EFF8", "#9A9CD8", "#3D3FA8", "#1D1F68"])
fig, ax = plt.subplots(figsize=(11, 4.4))
vmax = max(max(r) for r in M)
for r, row in enumerate(M):
    for c, v in enumerate(row):
        fc = BG if v == 0 else cmap(0.2 + 0.8 * v / vmax)
        ax.add_patch(FancyBboxPatch((c + 0.04, r + 0.06), 0.92, 0.88, boxstyle="round,pad=0,rounding_size=0.06",
                                    fc=fc, ec=GRID if v == 0 else "none", lw=0.8))
        ax.text(c + 0.5, r + 0.5, "–" if v == 0 else str(v), ha="center", va="center", fontsize=12,
                color=MUTED if v == 0 else ("white" if v >= 3 else INK), fontweight="bold")
ax.set_xlim(0, len(cols)); ax.set_ylim(len(logins), 0)
wrap = {t: t.replace(" / ", " /\n").replace(", access", ",\naccess").replace("access & persistence","access & persistence").replace(" & ", " &\n").replace("Model endpoint ", "Model endpoint\n")
            .replace("Contradictory ", "Contradictory\n").replace("Misleading ", "Misleading\n") for t in cols}
ax.set_xticks([c + 0.5 for c in range(len(cols))], [wrap[t] for t in cols], fontsize=9.5, color=INK)
ax.set_yticks([r + 0.5 for r in range(len(logins))], logins)
ax.xaxis.tick_top()
for s in ax.spines.values(): s.set_visible(False)
ax.tick_params(length=0)
fig.tight_layout(rect=(0, 0, 1, 0.86))
x0 = ax.get_position().x0
fig.text(x0, 0.95, "Who reported what", fontsize=15, fontweight="bold", color=INK, va="top")
fig.text(x0, 0.885, "Issues per tester per theme; darker = more", fontsize=10.5, color=MUTED, va="top")
fig.savefig(OUT / "4_tester_by_theme.png", dpi=200); plt.close(fig)
# ---------------- 5. one circle per issue ----------------
from matplotlib.patches import Circle
from matplotlib.lines import Line2D
fig, ax = plt.subplots(figsize=(10, 5.6))
rows5 = list(reversed(order))  # largest theme on top
for r, t in enumerate(rows5):
    nums = sorted((n for n in ISSUES if THEME[n] == t), key=lambda n: (TYPES.index(kind(n)), n))
    for c, n in enumerate(nums):
        ax.add_patch(Circle((c, -r), 0.42, fc=TYPE_COLORS[kind(n)], ec=BG, lw=2))
        ax.text(c, -r, f"#{n}", ha="center", va="center", fontsize=8.5, color="white", fontweight="bold")
    ax.text(len(nums) - 0.35, -r, str(len(nums)), va="center", fontsize=11, color=INK, fontweight="bold")
ax.set_yticks([-r for r in range(len(rows5))], rows5)
ax.set_xticks([])
ax.set_xlim(-0.6, 8.6); ax.set_ylim(-len(rows5) + 0.4, 0.6)
ax.set_aspect("equal")
for sp in ax.spines.values(): sp.set_visible(False)
ax.tick_params(length=0, pad=10)
fig.tight_layout(rect=(0, 0, 1, 0.84))
x0 = ax.get_position().x0
fig.text(x0, 0.955, "Every issue, one circle", fontsize=15, fontweight="bold", color=INK, va="top")
fig.text(x0, 0.89, "40 outside-tester issues by theme; color shows the kind of feedback", fontsize=10.5, color=MUTED, va="top")
fig.legend([Line2D([], [], marker="o", ls="", ms=10, mfc=c, mec="none") for c in TYPE_COLORS.values()], TYPES,
           loc="upper right", bbox_to_anchor=(0.98, 0.965), ncol=3, frameon=False, fontsize=10, labelcolor=INK, handletextpad=0.3)
fig.savefig(OUT / "5_issue_circles.png", dpi=200); plt.close(fig)

# ---------------- 6. bubble matrix: tester x theme ----------------
fig, ax = plt.subplots(figsize=(11, 4.6))
SMAX = 3200  # marker area (pt^2) for the largest cell; area proportional to count
for r, row in enumerate(M):
    for c, v in enumerate(row):
        x, y = c + 0.5, r + 0.5
        if v == 0:
            ax.scatter(x, y, s=30, c=GRID, edgecolors="none", zorder=2)
            continue
        area = SMAX * v / vmax
        ax.scatter(x, y, s=area, c=DESIGN, edgecolors=BG, linewidths=2, zorder=2)
        if v >= 2:
            ax.text(x, y, str(v), ha="center", va="center", fontsize=11, color="white", fontweight="bold", zorder=3)
        else:
            ax.annotate(str(v), (x, y), xytext=((area ** 0.5) / 2 + 5, 0), textcoords="offset points",
                        ha="left", va="center", fontsize=11, color=INK, fontweight="bold")
ax.set_xlim(0, len(cols)); ax.set_ylim(len(logins), 0)
ax.set_xticks([c + 0.5 for c in range(len(cols))], [wrap[t] for t in cols], fontsize=9.5, color=INK)
ax.set_yticks([r + 0.5 for r in range(len(logins))], logins)
ax.xaxis.tick_top()
for sp in ax.spines.values(): sp.set_visible(False)
ax.tick_params(length=0)
fig.tight_layout(rect=(0, 0, 1, 0.86))
x0 = ax.get_position().x0
fig.text(x0, 0.95, "Who reported what", fontsize=15, fontweight="bold", color=INK, va="top")
fig.text(x0, 0.885, "Circle area = issues per tester per theme; small dot = none", fontsize=10.5, color=MUTED, va="top")
fig.savefig(OUT / "6_tester_by_theme_bubbles.png", dpi=200); plt.close(fig)

# ---------------- 1a-1d: iterations on "What testers wrote about" ----------------
MUTED_BAR = "#C9CAE8"
N = len(ISSUES)

# 1a. lollipop: thin stem + circle head
fig, ax = plt.subplots(figsize=(10, 5.2))
for i, t in enumerate(order):
    ax.plot([0, counts[t]], [i, i], color=DESIGN, lw=2.5, solid_capstyle="butt", zorder=2)
    ax.scatter(counts[t], i, s=420, c=DESIGN, edgecolors=BG, linewidths=2, zorder=3)
    ax.text(counts[t], i, str(counts[t]), ha="center", va="center", fontsize=10, color="white", fontweight="bold", zorder=4)
ax.set_yticks(range(len(order)), order)
ax.set_xlim(0, 9); ax.set_ylim(-0.6, len(order) - 0.4)
ax.set_xlabel("Issues")
frame(ax, "What testers wrote about", "40 issues from 4 outside beta testers, grouped by theme")
fig.tight_layout(); fig.savefig(OUT / "1a_theme_lollipop.png", dpi=200); plt.close(fig)

# 1b. highlight the top theme, takeaway as the title
fig, ax = plt.subplots(figsize=(10, 5.2))
top = order[-1]
for i, t in enumerate(order):
    ax.add_patch(plt.Rectangle((0, i - 0.3), counts[t], 0.6, fc=DESIGN if t == top else MUTED_BAR, ec="none"))
    ax.text(counts[t] + 0.12, i, str(counts[t]), va="center", fontsize=11, fontweight="bold",
            color=INK if t == top else MUTED)
ax.text(0.2, len(order) - 1, "Fix first: unblocks retesting of most other themes", va="center", fontsize=10.5, color="white")
ax.set_yticks(range(len(order)), order)
for lbl in ax.get_yticklabels():
    if lbl.get_text() != top: lbl.set_color(MUTED)
ax.set_xlim(0, 9.2); ax.set_ylim(-0.6, len(order) - 0.4)
ax.set_xlabel("Issues")
frame(ax, "The model outage drew the most feedback", "8 of 40 outside-tester issues trace back to the unreachable model endpoint")
fig.tight_layout(); fig.savefig(OUT / "1b_theme_highlight.png", dpi=200); plt.close(fig)

# 1c. share of total + the issue numbers behind each bar
fig, ax = plt.subplots(figsize=(11, 5.4))
for i, t in enumerate(order):
    ax.add_patch(plt.Rectangle((0, i - 0.3), counts[t], 0.6, fc=DESIGN, ec="none"))
    nums = ", ".join(f"#{n}" for n in sorted(n for n in ISSUES if THEME[n] == t))
    ax.text(counts[t] + 0.15, i + 0.06, f"{counts[t]}  ({counts[t] / N:.0%})", va="bottom", fontsize=10.5, color=INK, fontweight="bold")
    ax.text(counts[t] + 0.15, i - 0.04, nums, va="top", fontsize=8.5, color=MUTED)
ax.set_yticks(range(len(order)), order)
ax.set_xlim(0, 13.5); ax.set_ylim(-0.6, len(order) - 0.4)
ax.set_xticks([0, 2, 4, 6, 8])
ax.set_xlabel("Issues")
frame(ax, "What testers wrote about", "Count, share of all 40 issues, and the issues behind each theme")
fig.tight_layout(); fig.savefig(OUT / "1c_theme_with_issue_ids.png", dpi=200); plt.close(fig)

# 1d. vertical columns, slide-friendly
fig, ax = plt.subplots(figsize=(11, 5.6))
vorder = list(reversed(order))
short = {t: t.replace("Missed / wrongly dismissed vulns", "Missed /\ndismissed vulns").replace("Data, access & persistence", "Data, access\n& persistence")
            .replace("Model endpoint outage", "Model\nendpoint outage").replace("API validation & limits", "API validation\n& limits")
            .replace("Contradictory labels", "Contradictory\nlabels").replace("Misleading empty results", "Misleading\nempty results") for t in vorder}
for i, t in enumerate(vorder):
    ax.add_patch(plt.Rectangle((i - 0.32, 0), 0.64, counts[t], fc=DESIGN, ec="none"))
    ax.text(i, counts[t] + 0.15, str(counts[t]), ha="center", va="bottom", fontsize=12, color=INK, fontweight="bold")
ax.set_xticks(range(len(vorder)), [short[t] for t in vorder], fontsize=10, color=INK)
ax.set_xlim(-0.6, len(vorder) - 0.4); ax.set_ylim(0, 9.4)
ax.set_ylabel("Issues")
ax.set_title("What testers wrote about", loc="left", fontsize=15, fontweight="bold", color=INK, pad=28)
ax.text(0, 1.02, "40 issues from 4 outside beta testers, grouped by theme", transform=ax.transAxes, fontsize=10.5, color=MUTED, va="bottom")
for sp in ("top", "right", "left"): ax.spines[sp].set_visible(False)
ax.spines["bottom"].set_color(GRID)
ax.tick_params(length=0); ax.tick_params(axis="y", colors=MUTED)
ax.yaxis.grid(True, color=GRID, linewidth=0.8); ax.set_axisbelow(True)
fig.tight_layout(); fig.savefig(OUT / "1d_theme_columns.png", dpi=200); plt.close(fig)

# 1a-classic. lollipop in the team's classic palette (floral white / indigo / navy)
C_INDIGO, C_NAVY, C_TINT = "#1D1F68", "#102542", "#E9EEF6"
fig, ax = plt.subplots(figsize=(10, 5.2))
for i, t in enumerate(order):
    ax.plot([0, counts[t]], [i, i], color=C_INDIGO, lw=2.5, solid_capstyle="butt", zorder=2)
    ax.scatter(counts[t], i, s=420, c=C_INDIGO, edgecolors=BG, linewidths=2, zorder=3)
    ax.text(counts[t], i, str(counts[t]), ha="center", va="center", fontsize=10, color=BG, fontweight="bold", zorder=4)
ax.set_yticks(range(len(order)), order)
ax.set_xlim(0, 9); ax.set_ylim(-0.6, len(order) - 0.4)
ax.set_xlabel("Issues", color=C_NAVY)
ax.set_title("What testers wrote about", loc="left", fontsize=15, fontweight="bold", color=C_NAVY, pad=28)
ax.text(0, 1.02, "40 issues from 4 outside beta testers, grouped by theme", transform=ax.transAxes, fontsize=10.5, color=C_NAVY, alpha=0.7, va="bottom")
for sp in ("top", "right", "left"): ax.spines[sp].set_visible(False)
ax.spines["bottom"].set_color(C_TINT)
ax.tick_params(axis="y", length=0, pad=8, colors=C_NAVY)
ax.tick_params(axis="x", length=0, colors=C_NAVY)
ax.xaxis.grid(True, color=C_TINT, linewidth=1)
ax.set_axisbelow(True)
fig.tight_layout(); fig.savefig(OUT / "1a_theme_lollipop_classic.png", dpi=200); plt.close(fig)

print("wrote", *sorted(p.name for p in OUT.glob("*.png")))
