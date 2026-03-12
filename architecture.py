"""
Aegis — Smart Contract Vulnerability Scanner
architecture.py: Generates a clean, non-overlapping system architecture diagram.

Run:
    python architecture.py
Output:
    aegis_architecture.png
"""

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

# ─────────────────────────────────────────────
#  COLOUR PALETTE  (GitHub-dark theme)
# ─────────────────────────────────────────────
BG          = "#0D1117"
LANE_COLORS = ["#161B22", "#0D2137", "#0A1A2E", "#0E1E1A", "#0D1117", "#161B22"]
BOX_COLORS  = ["#1F6FEB", "#238636", "#6E40C9", "#9E6A03", "#CF222E", "#1F6FEB"]
ARROW_COL   = "#58A6FF"
TEXT_MAIN   = "#E6EDF3"
TEXT_DIM    = "#8B949E"
BORDER_DIM  = "#30363D"

# ─────────────────────────────────────────────
#  CANVAS
# ─────────────────────────────────────────────
FIG_W, FIG_H = 18, 22       # tall canvas — plenty of vertical room
fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
fig.patch.set_facecolor(BG)
ax.set_facecolor(BG)
ax.set_xlim(0, 18)
ax.set_ylim(0, 22)
ax.axis("off")

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def box(cx, cy, w, h, title, subtitle="", color="#1F6FEB",
        title_size=10, sub_size=8):
    """Draw a rounded, glowing box. No icon – purely text."""
    r = 0.12
    # fill
    ax.add_patch(FancyBboxPatch(
        (cx - w/2, cy - h/2), w, h,
        boxstyle=f"round,pad=0,rounding_size={r}",
        linewidth=0, facecolor=color, alpha=0.20, zorder=3))
    # border
    ax.add_patch(FancyBboxPatch(
        (cx - w/2, cy - h/2), w, h,
        boxstyle=f"round,pad=0,rounding_size={r}",
        linewidth=1.8, edgecolor=color, facecolor="none", alpha=0.85, zorder=4))
    # title
    ty = cy + (0.18 if subtitle else 0)
    ax.text(cx, ty, title, color=TEXT_MAIN, fontsize=title_size,
            fontweight="bold", fontfamily="DejaVu Sans",
            ha="center", va="center", zorder=5)
    if subtitle:
        ax.text(cx, cy - 0.22, subtitle, color=TEXT_DIM, fontsize=sub_size,
                fontfamily="DejaVu Sans",
                ha="center", va="center", zorder=5)


def swimlane(y_top, height, label, color):
    """Horizontal swimlane — drawn BEHIND everything."""
    ax.add_patch(mpatches.FancyBboxPatch(
        (0.2, y_top - height), 17.6, height,
        boxstyle="round,pad=0,rounding_size=0.1",
        linewidth=0.8, edgecolor=BORDER_DIM,
        facecolor=color, alpha=0.45, zorder=1))
    ax.text(0.45, y_top - 0.26, label, color=TEXT_DIM,
            fontsize=8.5, fontweight="bold", fontfamily="DejaVu Sans",
            va="top", ha="left", zorder=2)


def vline(x, y_start, y_end, label="", label_side="right"):
    """Straight vertical arrow — no box crossing."""
    ax.annotate("", xy=(x, y_end), xytext=(x, y_start),
                arrowprops=dict(arrowstyle="-|>", color=ARROW_COL,
                                lw=1.4, mutation_scale=12), zorder=6)
    if label:
        lx = x + 0.15 if label_side == "right" else x - 0.15
        ha = "left" if label_side == "right" else "right"
        my = (y_start + y_end) / 2
        ax.text(lx, my, label, color=ARROW_COL, fontsize=7.5,
                fontfamily="DejaVu Sans", va="center", ha=ha, zorder=7)


def hline(x_start, x_end, y, label=""):
    """Straight horizontal arrow."""
    ax.annotate("", xy=(x_end, y), xytext=(x_start, y),
                arrowprops=dict(arrowstyle="-|>", color=ARROW_COL,
                                lw=1.4, mutation_scale=12), zorder=6)
    if label:
        mx = (x_start + x_end) / 2
        ax.text(mx, y + 0.12, label, color=ARROW_COL, fontsize=7.5,
                fontfamily="DejaVu Sans", va="bottom", ha="center", zorder=7)


def elbow(x1, y1, x2, y2, via_x=None, via_y=None, label=""):
    """L-shaped or Z-shaped connector — no diagonal, avoids box overlap."""
    if via_x is not None:
        # Go horizontal to via_x, then vertical
        ax.plot([x1, via_x], [y1, y1], color=ARROW_COL, lw=1.4, zorder=6)
        ax.annotate("", xy=(x2, y2), xytext=(via_x, y1),
                    arrowprops=dict(arrowstyle="-|>", color=ARROW_COL,
                                    lw=1.4, mutation_scale=12,
                                    connectionstyle=f"arc3,rad=0"), zorder=6)
    elif via_y is not None:
        # Go vertical to via_y, then horizontal
        ax.plot([x1, x1], [y1, via_y], color=ARROW_COL, lw=1.4, zorder=6)
        ax.annotate("", xy=(x2, y2), xytext=(x1, via_y),
                    arrowprops=dict(arrowstyle="-|>", color=ARROW_COL,
                                    lw=1.4, mutation_scale=12,
                                    connectionstyle="arc3,rad=0"), zorder=6)
    if label:
        mx = (x1 + x2) / 2
        my = (y1 + y2) / 2
        ax.text(mx + 0.15, my, label, color=ARROW_COL, fontsize=7.5,
                fontfamily="DejaVu Sans", va="center", ha="left", zorder=7)


# ─────────────────────────────────────────────
#  TITLE
# ─────────────────────────────────────────────
ax.text(9, 21.5, "AEGIS  --  System Architecture",
        color=TEXT_MAIN, fontsize=20, fontweight="bold",
        fontfamily="DejaVu Sans", ha="center", va="center", zorder=10)
ax.text(9, 21.0, "Smart Contract Vulnerability Scanner  |  Kru Infosec",
        color=TEXT_DIM, fontsize=10,
        fontfamily="DejaVu Sans", ha="center", va="center", zorder=10)

# ─────────────────────────────────────────────
#  LAYER DEFINITIONS  (y_top = top edge of lane)
#
#  L0  User           20.5 -> 19.3   h=1.2
#  L1  Flask           19.0 -> 17.2   h=1.8
#  L2  Scanner Core    16.9 -> 15.1   h=1.8
#  L3  Detectors       14.8 -> 12.6   h=2.2
#  L4  Data/Findings   12.3 -> 10.8   h=1.5
#  L5  Report          10.5 ->  9.0   h=1.5
# ─────────────────────────────────────────────

# ── LAYER 0 – USER INTERFACE ──────────────────
swimlane(20.5, 1.2, "LAYER 0  |  USER INTERFACE", LANE_COLORS[0])
box(4.5, 19.95, 4.0, 0.70,
    "Browser / User",
    "Uploads .sol · views report",
    color=BOX_COLORS[0])
box(12.5, 19.95, 3.8, 0.70,
    "Sample Contracts",
    "reentrancy.sol  overflow.sol  safe.sol",
    color=BOX_COLORS[0])

# ── LAYER 1 – FLASK WEB APPLICATION ──────────
swimlane(19.0, 1.8, "LAYER 1  |  FLASK WEB APPLICATION   (app.py)", LANE_COLORS[1])
BOX_W1 = 3.4
BOX_H1 = 0.70
# 4 route boxes evenly spaced: centres at x = 2.2, 5.9, 9.6, 13.3
route_xs = [2.2, 5.9, 9.6, 13.3]
route_labels = ["GET  /", "POST  /scan", "GET  /report", "GET  /sample/<name>"]
route_subs   = ["Home page", "Upload & validate .sol", "Show scan results", "Load preset contract"]
for rx, rl, rs in zip(route_xs, route_labels, route_subs):
    box(rx, 18.15, BOX_W1, BOX_H1, rl, rs, color=BOX_COLORS[1])

# ── LAYER 2 – SCANNER CORE ───────────────────
swimlane(16.9, 1.8, "LAYER 2  |  SCANNER CORE", LANE_COLORS[2])
box(4.5, 16.05, 5.2, 0.70,
    "Parser  (parser.py)",
    "Extract: pragma · structs · SafeMath · line list",
    color=BOX_COLORS[2])
box(12.5, 16.05, 5.0, 0.70,
    "Engine  (engine.py)",
    "Run detectors · sort severity · calc risk score",
    color=BOX_COLORS[3])

# ── LAYER 3 – DETECTORS ──────────────────────
swimlane(14.8, 2.2, "LAYER 3  |  VULNERABILITY DETECTORS   (scanner/detectors/)", LANE_COLORS[3])
det_xs     = [2.3, 5.8, 9.3, 12.8]
det_names  = ["Reentrancy", "Integer Overflow", "tx.origin Auth", "Selfdestruct"]
det_subs   = ["ext call before\nstate update", "unchecked\narithmetic", "improper\nauthentication", "unprotected\ncontract kill"]
for dx, dn, ds in zip(det_xs, det_names, det_subs):
    box(dx, 13.82, 3.2, 1.22, dn, ds, color=BOX_COLORS[4], sub_size=7.5)

# ── LAYER 4 – DATA / FINDINGS ────────────────
swimlane(12.3, 1.5, "LAYER 4  |  DATA  &  FINDINGS", LANE_COLORS[4])
box(4.5, 11.62, 5.2, 0.72,
    "findings[]  (list of dicts)",
    "vuln_type · severity · line · description · fix",
    color=BOX_COLORS[3])
box(12.5, 11.62, 4.8, 0.72,
    "Risk Score  ->  Risk Level",
    "CRITICAL / HIGH / MEDIUM / LOW / SAFE",
    color=BOX_COLORS[3])

# ── LAYER 5 – REPORT & OUTPUT ────────────────
swimlane(10.5, 1.5, "LAYER 5  |  REPORT  &  OUTPUT   (report.py + templates/)", LANE_COLORS[5])
box(4.5, 9.82, 5.2, 0.72,
    "Report Formatter  (report.py)",
    "format_report()  ->  structured display dict",
    color=BOX_COLORS[0])
box(12.5, 9.82, 4.8, 0.72,
    "HTML Report  (report.html)",
    "Severity badges · findings table · risk gauge",
    color=BOX_COLORS[0])

# ─────────────────────────────────────────────
#  ARROWS  — connect ONLY bottom/top of adjacent layers
#  All arrows are straight vertical lines between lane edges,
#  positioned at the horizontal centre of the source/target box.
#  No arrow passes through any box.
# ─────────────────────────────────────────────

# L0 Browser  ──> L1 POST /scan  (both near x=4.5 / 5.9)
vline(4.5, 19.60, 18.51, label="upload .sol")

# L0 Samples  ──> L1 /sample route
vline(12.5, 19.60, 18.51, label="load sample")

# L1 POST /scan ──> L2 Parser   (x=5.9, avoiding box at 5.9->4.5 shift via elbow)
# Use a small horizontal leg so the arrow enters Parser from the top
ax.plot([5.9, 4.5], [17.80, 17.80], color=ARROW_COL, lw=1.4, zorder=6)
vline(4.5, 17.80, 16.41, label="source code")

# L1 /sample ──> L2 Engine  (x=13.3 -> 12.5)
ax.plot([13.3, 12.5], [17.80, 17.80], color=ARROW_COL, lw=1.4, zorder=6)
vline(12.5, 17.80, 16.41, label="source code")

# L2 Parser ──> L2 Engine  (horizontal, within same lane at y=16.05)
hline(7.1, 10.0, 16.05, label="parsed_ctx")

# L2 Engine ──> L3 Detectors  (fan-out: 4 lines from Engine bottom)
for dx in det_xs:
    # go from Engine bottom (x=12.5) out to each detector x via horizontal leg
    ax.plot([12.5, dx], [15.70, 15.70], color=ARROW_COL, lw=1.0, zorder=6,
            linestyle="--", alpha=0.6)
    vline(dx, 15.70, 14.43)

# L3 Detectors ──> L4 findings[]  (all funnel to findings box at x=4.5)
for dx in det_xs:
    ax.plot([dx, 4.5], [13.21, 13.21], color=ARROW_COL, lw=1.0, zorder=6,
            linestyle="--", alpha=0.6)
vline(4.5, 13.21, 11.99, label="findings")

# L4 findings[] ──> L4 Risk Score  (horizontal)
hline(7.1, 10.1, 11.62, label="aggregate")

# L4 findings[] ──> L5 Report Formatter
vline(4.5, 11.26, 10.19, label="pass findings")

# L4 Risk Score ──> L5 HTML Report
vline(12.5, 11.26, 10.19, label="risk level")

# L5 Report Formatter ──> L5 HTML Report  (horizontal)
hline(7.1, 10.1, 9.82, label="format_report()")

# L5 HTML Report ──> L1 GET /report  (feedback loop on RIGHT side, outside boxes)
# Route: up the right margin (x=17.2) from y=10.19 to y=18.15
ax.plot([14.9, 17.2], [9.82, 9.82],   color=ARROW_COL, lw=1.2, zorder=6, alpha=0.7)
ax.plot([17.2, 17.2], [9.82, 18.15],  color=ARROW_COL, lw=1.2, zorder=6, alpha=0.7)
ax.annotate("", xy=(11.15, 18.15), xytext=(17.2, 18.15),
            arrowprops=dict(arrowstyle="-|>", color=ARROW_COL,
                            lw=1.2, mutation_scale=11, alpha=0.7), zorder=6)
ax.text(17.35, 14.0, "session[report]", color=ARROW_COL, fontsize=7.5,
        fontfamily="DejaVu Sans", va="center", ha="left",
        rotation=90, zorder=7)

# L1 GET /report ──> L0 Browser  (response loop on LEFT side, outside boxes)
ax.plot([1.65, 0.25], [18.15, 18.15], color=ARROW_COL, lw=1.2, zorder=6, alpha=0.7)
ax.plot([0.25, 0.25], [18.15, 19.95],  color=ARROW_COL, lw=1.2, zorder=6, alpha=0.7)
ax.annotate("", xy=(2.5, 19.95), xytext=(0.25, 19.95),
            arrowprops=dict(arrowstyle="-|>", color=ARROW_COL,
                            lw=1.2, mutation_scale=11, alpha=0.7), zorder=6)
ax.text(0.10, 19.05, "HTML response", color=ARROW_COL, fontsize=7.5,
        fontfamily="DejaVu Sans", va="center", ha="right",
        rotation=90, zorder=7)

# ─────────────────────────────────────────────
#  LEGEND  (bottom of canvas — clear area)
# ─────────────────────────────────────────────
legend_y = 8.4
ax.text(1.2, legend_y, "LEGEND", color=TEXT_DIM, fontsize=9,
        fontweight="bold", fontfamily="DejaVu Sans", va="top")

legend_items = [
    (BOX_COLORS[0], "User / Report  (blue)"),
    (BOX_COLORS[1], "Flask Routes   (green)"),
    (BOX_COLORS[2], "Parser         (purple)"),
    (BOX_COLORS[3], "Engine / Data  (amber)"),
    (BOX_COLORS[4], "Detectors      (red)"),
]
for i, (col, lbl) in enumerate(legend_items):
    lx = 1.2 + i * 3.2
    ax.add_patch(mpatches.FancyBboxPatch(
        (lx, legend_y - 1.05), 0.45, 0.45,
        boxstyle="round,pad=0,rounding_size=0.05",
        linewidth=1.5, edgecolor=col, facecolor=col, alpha=0.35, zorder=8))
    ax.text(lx + 0.6, legend_y - 0.82, lbl, color=TEXT_MAIN, fontsize=8.5,
            fontfamily="DejaVu Sans", va="center", zorder=9)

# Arrow legend
ax.plot([1.2, 1.9], [legend_y - 1.7, legend_y - 1.7],
        color=ARROW_COL, lw=1.4, zorder=8)
ax.annotate("", xy=(1.9, legend_y - 1.7), xytext=(1.2, legend_y - 1.7),
            arrowprops=dict(arrowstyle="-|>", color=ARROW_COL, lw=1.4,
                            mutation_scale=11), zorder=8)
ax.text(2.0, legend_y - 1.7, "Data flow / call", color=TEXT_DIM, fontsize=8.5,
        fontfamily="DejaVu Sans", va="center", zorder=9)

ax.plot([5.5, 6.2], [legend_y - 1.7, legend_y - 1.7],
        color=ARROW_COL, lw=1.2, ls="--", alpha=0.7, zorder=8)
ax.text(6.3, legend_y - 1.7, "Fan-out / collect", color=TEXT_DIM, fontsize=8.5,
        fontfamily="DejaVu Sans", va="center", zorder=9)

# ─────────────────────────────────────────────
#  WATERMARK
# ─────────────────────────────────────────────
ax.text(17.7, 0.2, "Kru Infosec  (c) 2024",
        color=BORDER_DIM, fontsize=8, fontfamily="DejaVu Sans",
        ha="right", va="bottom", zorder=10)

# ─────────────────────────────────────────────
#  SAVE
# ─────────────────────────────────────────────
OUT = "aegis_architecture.png"
plt.savefig(OUT, dpi=180, bbox_inches="tight", facecolor=BG)
plt.close()
print("[OK] Saved -> " + OUT)
