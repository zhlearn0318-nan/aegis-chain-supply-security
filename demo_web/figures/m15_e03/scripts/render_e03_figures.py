from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


HERE = Path(__file__).resolve().parent
FIGURE_ROOT = HERE.parent
DEMO_ROOT = FIGURE_ROOT.parents[1]
SOURCE = DEMO_ROOT / "artifacts" / "experiment" / "2026-09-08-m15-e03-dynamic-round-ablation-v2" / "metrics.json"
STYLE = FIGURE_ROOT / "deepscientist-academic.mplstyle"

COLORS = ["#B8B2A7", "#6FA6A1", "#A33B32"]
HATCHES = ["", "", "//"]


def save(fig: plt.Figure, stem: str) -> None:
    fig.savefig(FIGURE_ROOT / f"{stem}.png", dpi=300, facecolor="white")
    fig.savefig(FIGURE_ROOT / f"{stem}.svg", facecolor="white")
    plt.close(fig)


def render_detection(metrics: dict) -> None:
    systems = metrics["systems"]
    categories = ["Risk non-allow", "Expected rule", "Original dyn. allow"]
    values = {
        name: [
            systems[name]["risk_non_allow_recall"] * 100,
            systems[name]["expected_dynamic_rule_recall"] * 100,
            systems[name]["original_dynamic_allow_rate"] * 100,
        ]
        for name in ("D0", "D1", "D3")
    }
    fig, ax = plt.subplots(figsize=(7.2, 3.2))
    x = np.arange(len(categories))
    width = 0.24
    for index, name in enumerate(("D0", "D1", "D3")):
        bars = ax.bar(
            x + (index - 1) * width,
            values[name],
            width,
            label=name,
            color=COLORS[index],
            hatch=HATCHES[index],
            edgecolor="white",
            linewidth=0.8,
            zorder=3,
        )
        for bar, value in zip(bars, values[name]):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                value + 2,
                f"{value:.0f}%",
                ha="center",
                va="bottom",
                fontsize=8.5,
                fontweight="bold" if name == "D3" else "normal",
                color="#7A2521" if name == "D3" else "#4B5563",
            )
    ax.set_title("Three rounds recover runtime risks missed by one round")
    ax.set_ylabel("Rate (%)")
    ax.set_xticks(x, categories)
    ax.set_ylim(0, 112)
    ax.legend(ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.18))
    ax.grid(axis="x", visible=False)
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    save(fig, "fig_e03_detection_ablation")


def render_latency(metrics: dict) -> None:
    systems = metrics["systems"]
    labels = ["D0\nstatic", "D1\ntypical", "D3\n3 rounds"]
    recall = [systems[name]["risk_non_allow_recall"] * 100 for name in ("D0", "D1", "D3")]
    p95 = [systems[name]["latency_ms"]["p95"] / 1000 for name in ("D0", "D1", "D3")]
    fig, ax = plt.subplots(figsize=(7.2, 3.2))
    ax.plot(p95, recall, color="#A33B32", marker="o", zorder=3)
    for index, (x, y, label) in enumerate(zip(p95, recall, labels)):
        offset = (-8, 8) if index == 2 else (5, 7)
        alignment = "right" if index == 2 else "left"
        ax.annotate(label.replace("\n", " "), (x, y), xytext=offset, textcoords="offset points", fontsize=9, ha=alignment)
    ax.axhline(100, color="#6FA6A1", linestyle="--", linewidth=1.2, label="Full risk non-allow")
    ax.set_title("Detection gain versus attributed P95 total latency")
    ax.set_xlabel("P95 total latency (s)")
    ax.set_ylabel("Controlled-risk non-allow (%)")
    ax.set_ylim(68, 103)
    ax.set_xlim(min(p95) - 0.8, max(p95) + 1.0)
    ax.legend(loc="lower right")
    fig.tight_layout()
    save(fig, "fig_e03_gain_latency")


def render_first_trigger(metrics: dict) -> None:
    counts = metrics["first_expected_rule_round"]
    labels = ["Typical", "Edge", "Adversarial", "Not detected"]
    values = [counts.get(key, 0) for key in ("typical", "edge", "adversarial", "not_detected")]
    fig, ax = plt.subplots(figsize=(7.2, 2.4))
    left = 0
    palette = ["#B8B2A7", "#6FA6A1", "#A33B32", "#D8D1C7"]
    for label, value, color in zip(labels, values, palette):
        if value:
            ax.barh([0], [value], left=left, color=color, label=label, height=0.45)
        left += value
    ax.set_title("First round containing the expected runtime rule (30 risk twins)")
    ax.set_xlabel("Controlled-risk twins")
    ax.set_yticks([])
    ax.set_xlim(0, 30)
    ax.text(15, 0, "Adversarial  30 / 30", ha="center", va="center", color="white", fontweight="bold")
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    save(fig, "fig_e03_first_trigger")


def main() -> None:
    plt.style.use(STYLE)
    payload = json.loads(SOURCE.read_text(encoding="utf-8"))
    metrics = payload["metrics"]
    render_detection(metrics)
    render_latency(metrics)
    render_first_trigger(metrics)
    print(f"rendered figures from {SOURCE}")


if __name__ == "__main__":
    main()
