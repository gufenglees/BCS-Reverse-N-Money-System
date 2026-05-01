"""
Simulation Visualization
=========================
Matplotlib-based visualization for MiroFish simulation results.
Generates time-series, distributions, and topology plots.
"""

from __future__ import annotations

import os
from typing import List, Tuple, Dict, Any, Optional
from dataclasses import dataclass

try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.colors import LinearSegmentedColormap
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

from metrics import SimulationMetrics, MetricsCollector


# ---------------------------------------------------------------------------
# Color scheme
# ---------------------------------------------------------------------------
BCS_COLORS = {
    "primary": "#2E86AB",
    "secondary": "#A23B72",
    "accent": "#F18F01",
    "success": "#C73E1D",
    "background": "#F7F7F7",
    "text": "#333333",
    "grid": "#DDDDDD",
}


def _check_matplotlib() -> bool:
    if not MATPLOTLIB_AVAILABLE:
        print("Warning: matplotlib not available. Install with: pip install matplotlib numpy")
        return False
    return True


# ---------------------------------------------------------------------------
# Plot: Throughput over time
# ---------------------------------------------------------------------------

def plot_throughput_over_time(metrics: MetricsCollector, output_path: Optional[str] = None) -> Optional[str]:
    """Plot transaction throughput (tx/s) over time."""
    if not _check_matplotlib():
        return None

    tp_data = metrics.get_throughput_over_time(bucket_seconds=1.0)
    if not tp_data:
        return None

    times = [t for t, _ in tp_data]
    throughputs = [tp for _, tp in tp_data]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.fill_between(times, throughputs, alpha=0.3, color=BCS_COLORS["primary"])
    ax.plot(times, throughputs, color=BCS_COLORS["primary"], linewidth=1.5)
    ax.axhline(y=np.mean(throughputs), color=BCS_COLORS["accent"], linestyle="--", label=f"Avg: {np.mean(throughputs):.1f} tx/s")
    ax.set_xlabel("Time (seconds)", fontsize=11, color=BCS_COLORS["text"])
    ax.set_ylabel("Throughput (tx/s)", fontsize=11, color=BCS_COLORS["text"])
    ax.set_title("Transaction Throughput Over Time", fontsize=13, fontweight="bold", color=BCS_COLORS["text"])
    ax.legend(loc="upper right")
    ax.grid(True, alpha=0.3, color=BCS_COLORS["grid"])
    ax.set_facecolor(BCS_COLORS["background"])
    fig.patch.set_facecolor("white")
    plt.tight_layout()

    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close()
        return output_path
    plt.show()
    return None


# ---------------------------------------------------------------------------
# Plot: Latency distribution
# ---------------------------------------------------------------------------

def plot_latency_distribution(metrics: MetricsCollector, output_path: Optional[str] = None) -> Optional[str]:
    """Plot latency histogram with percentile markers."""
    if not _check_matplotlib():
        return None

    latencies = metrics.tx_latencies_ms
    if not latencies:
        return None

    percentiles = metrics.get_latency_percentiles()

    fig, ax = plt.subplots(figsize=(10, 5))
    n, bins, patches = ax.hist(latencies, bins=50, color=BCS_COLORS["primary"], edgecolor="white", alpha=0.8)

    # Mark percentiles
    for p_name, p_val in percentiles.items():
        ax.axvline(x=p_val, color=BCS_COLORS["accent"] if p_name == "p50" else BCS_COLORS["secondary"],
                   linestyle="--", linewidth=1.5, label=f"{p_name.upper()}: {p_val:.1f} ms")

    ax.set_xlabel("Latency (ms)", fontsize=11, color=BCS_COLORS["text"])
    ax.set_ylabel("Frequency", fontsize=11, color=BCS_COLORS["text"])
    ax.set_title("Transaction Latency Distribution", fontsize=13, fontweight="bold", color=BCS_COLORS["text"])
    ax.legend(loc="upper right")
    ax.grid(True, alpha=0.3, color=BCS_COLORS["grid"])
    ax.set_facecolor(BCS_COLORS["background"])
    fig.patch.set_facecolor("white")
    plt.tight_layout()

    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close()
        return output_path
    plt.show()
    return None


# ---------------------------------------------------------------------------
# Plot: N distribution
# ---------------------------------------------------------------------------

def plot_n_distribution(agents_summary: Dict[str, Any], output_path: Optional[str] = None) -> Optional[str]:
    """Plot N currency distribution across agent types."""
    if not _check_matplotlib():
        return None

    # Gather balances by type
    balances_by_type: Dict[str, List[int]] = {}
    for role, agents in agents_summary.items():
        balances_by_type[role] = [a["balance"] for a in agents]

    if not any(balances_by_type.values()):
        return None

    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    axes = axes.flatten()

    for idx, (role, balances) in enumerate(balances_by_type.items()):
        if idx >= 4:
            break
        ax = axes[idx]
        if balances:
            ax.hist(balances, bins=20, color=BCS_COLORS["primary"], edgecolor="white", alpha=0.8)
            ax.axvline(x=np.mean(balances), color=BCS_COLORS["accent"], linestyle="--",
                       label=f"Mean: {np.mean(balances)/1e9:.2f} N")
        ax.set_title(f"{role.title()} N Balance Distribution", fontsize=11, fontweight="bold")
        ax.set_xlabel("Balance (nanoN)", fontsize=9)
        ax.set_ylabel("Count", fontsize=9)
        ax.legend(loc="upper right")
        ax.grid(True, alpha=0.3)
        ax.set_facecolor(BCS_COLORS["background"])

    plt.suptitle("N Currency Distribution by Agent Type", fontsize=14, fontweight="bold", color=BCS_COLORS["text"])
    plt.tight_layout(rect=[0, 0, 1, 0.96])

    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close()
        return output_path
    plt.show()
    return None


# ---------------------------------------------------------------------------
# Plot: Network topology
# ---------------------------------------------------------------------------

def plot_network_topology(nodes: List[str], edges: List[Tuple[str, str]],
                          output_path: Optional[str] = None) -> Optional[str]:
    """Plot network topology graph."""
    if not _check_matplotlib():
        return None

    # Simple force-directed-like layout using spring layout approximation
    node_positions: Dict[str, Tuple[float, float]] = {}
    n = len(nodes)

    # Circular layout as base
    for i, node in enumerate(nodes):
        angle = 2 * np.pi * i / n
        node_positions[node] = (np.cos(angle), np.sin(angle))

    # Simple spring relaxation
    for _ in range(50):
        new_positions = {}
        for node in nodes:
            x, y = node_positions[node]
            fx, fy = 0.0, 0.0
            for other in nodes:
                if other == node:
                    continue
                dx = node_positions[other][0] - x
                dy = node_positions[other][1] - y
                dist = max(0.1, np.sqrt(dx * dx + dy * dy))
                # Repulsion
                fx -= dx / (dist * dist) * 0.01
                fy -= dy / (dist * dist) * 0.01
            # Attraction for connected nodes
            for a, b in edges:
                if a == node:
                    fx += (node_positions[b][0] - x) * 0.05
                    fy += (node_positions[b][1] - y) * 0.05
                elif b == node:
                    fx += (node_positions[a][0] - x) * 0.05
                    fy += (node_positions[a][1] - y) * 0.05
            new_positions[node] = (x + fx, y + fy)
        node_positions = new_positions

    fig, ax = plt.subplots(figsize=(10, 10))

    # Draw edges
    for a, b in edges:
        x1, y1 = node_positions[a]
        x2, y2 = node_positions[b]
        ax.plot([x1, x2], [y1, y2], color=BCS_COLORS["grid"], alpha=0.5, linewidth=0.8)

    # Draw nodes
    for node, (x, y) in node_positions.items():
        ax.scatter(x, y, s=100, color=BCS_COLORS["primary"], zorder=5, edgecolors="white", linewidths=1)
        ax.text(x, y - 0.08, node.replace("node_", ""), ha="center", va="top", fontsize=7, color=BCS_COLORS["text"])

    ax.set_aspect("equal")
    ax.axis("off")
    ax.set_title("Network Topology", fontsize=13, fontweight="bold", color=BCS_COLORS["text"])
    fig.patch.set_facecolor("white")
    plt.tight_layout()

    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close()
        return output_path
    plt.show()
    return None


# ---------------------------------------------------------------------------
# Plot: Sync events timeline
# ---------------------------------------------------------------------------

def plot_sync_events(metrics: MetricsCollector, output_path: Optional[str] = None) -> Optional[str]:
    """Plot sync events timeline (partitions, failures, recoveries)."""
    if not _check_matplotlib():
        return None

    sync_events = metrics.sync_events
    offline_events = metrics.offline_events
    if not sync_events and not offline_events:
        return None

    fig, ax = plt.subplots(figsize=(12, 4))

    # Plot sync events
    for e in sync_events:
        ts = e.get("timestamp", 0)
        etype = e.get("event", "unknown")
        color = BCS_COLORS["success"] if etype == "partition" else BCS_COLORS["accent"]
        marker = "x" if etype == "partition" else "o"
        ax.scatter(ts, 1, color=color, marker=marker, s=100, zorder=5)

    # Plot offline events
    for e in offline_events:
        ts = e.get("timestamp", 0)
        etype = e.get("event", "unknown")
        color = BCS_COLORS["secondary"] if etype == "go_offline" else BCS_COLORS["primary"]
        marker = "v" if etype == "go_offline" else "^"
        y_pos = 0 if etype == "go_offline" else 2
        ax.scatter(ts, y_pos, color=color, marker=marker, s=80, zorder=5)

    # Legend
    legend_elements = [
        mpatches.Patch(color=BCS_COLORS["success"], label="Partition"),
        mpatches.Patch(color=BCS_COLORS["accent"], label="Sync"),
        mpatches.Patch(color=BCS_COLORS["secondary"], label="Go Offline"),
        mpatches.Patch(color=BCS_COLORS["primary"], label="Come Online"),
    ]
    ax.legend(handles=legend_elements, loc="upper right")
    ax.set_yticks([0, 1, 2])
    ax.set_yticklabels(["Offline", "Sync/Partition", "Online"])
    ax.set_xlabel("Time (epoch)", fontsize=11)
    ax.set_title("Sync Events Timeline", fontsize=13, fontweight="bold", color=BCS_COLORS["text"])
    ax.grid(True, alpha=0.3, color=BCS_COLORS["grid"])
    ax.set_facecolor(BCS_COLORS["background"])
    fig.patch.set_facecolor("white")
    plt.tight_layout()

    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close()
        return output_path
    plt.show()
    return None


# ---------------------------------------------------------------------------
# Generate comprehensive report
# ---------------------------------------------------------------------------

def generate_report(
    metrics: MetricsCollector,
    sim_metrics: SimulationMetrics,
    nodes: List[str],
    edges: List[Tuple[str, str]],
    agents_summary: Dict[str, Any],
    output_path: str,
) -> str:
    """
    Generate a comprehensive multi-panel report figure.

    Returns:
        Path to the saved PNG file.
    """
    if not _check_matplotlib():
        return ""

    fig = plt.figure(figsize=(16, 20))
    gs = fig.add_gridspec(4, 2, hspace=0.3, wspace=0.25)

    # Panel 1: Summary text
    ax1 = fig.add_subplot(gs[0, :])
    ax1.axis("off")
    summary_text = _format_summary(sim_metrics)
    ax1.text(0.05, 0.95, summary_text, transform=ax1.transAxes, fontsize=10,
             verticalalignment="top", fontfamily="monospace",
             bbox=dict(boxstyle="round", facecolor=BCS_COLORS["background"], alpha=0.8))
    ax1.set_title("BCS MiroFish Simulation Report", fontsize=16, fontweight="bold", pad=20)

    # Panel 2: Throughput
    ax2 = fig.add_subplot(gs[1, 0])
    tp_data = metrics.get_throughput_over_time(bucket_seconds=1.0)
    if tp_data:
        times = [t for t, _ in tp_data]
        tps = [tp for _, tp in tp_data]
        ax2.fill_between(times, tps, alpha=0.3, color=BCS_COLORS["primary"])
        ax2.plot(times, tps, color=BCS_COLORS["primary"], linewidth=1.2)
        ax2.axhline(y=np.mean(tps), color=BCS_COLORS["accent"], linestyle="--")
    ax2.set_xlabel("Time (s)")
    ax2.set_ylabel("Throughput (tx/s)")
    ax2.set_title("Throughput Over Time")
    ax2.grid(True, alpha=0.3)

    # Panel 3: Latency distribution
    ax3 = fig.add_subplot(gs[1, 1])
    if metrics.tx_latencies_ms:
        ax3.hist(metrics.tx_latencies_ms, bins=40, color=BCS_COLORS["primary"], edgecolor="white", alpha=0.8)
        p50 = np.percentile(metrics.tx_latencies_ms, 50)
        ax3.axvline(x=p50, color=BCS_COLORS["accent"], linestyle="--", label=f"P50: {p50:.1f}ms")
    ax3.set_xlabel("Latency (ms)")
    ax3.set_ylabel("Frequency")
    ax3.set_title("Latency Distribution")
    ax3.legend()
    ax3.grid(True, alpha=0.3)

    # Panel 4: N distribution
    ax4 = fig.add_subplot(gs[2, 0])
    all_balances = []
    for role, agents in agents_summary.items():
        balances = [a["balance"] / 1e9 for a in agents]
        all_balances.extend(balances)
    if all_balances:
        ax4.hist(all_balances, bins=30, color=BCS_COLORS["secondary"], edgecolor="white", alpha=0.8)
        ax4.axvline(x=np.mean(all_balances), color=BCS_COLORS["accent"], linestyle="--",
                    label=f"Mean: {np.mean(all_balances):.2f} N")
    ax4.set_xlabel("Balance (N)")
    ax4.set_ylabel("Count")
    ax4.set_title("N Currency Distribution")
    ax4.legend()
    ax4.grid(True, alpha=0.3)

    # Panel 5: Network topology
    ax5 = fig.add_subplot(gs[2, 1])
    if nodes and edges:
        # Simplified circular layout
        n = len(nodes)
        positions = {}
        for i, node in enumerate(nodes):
            angle = 2 * np.pi * i / n
            positions[node] = (np.cos(angle), np.sin(angle))
        for a, b in edges:
            x1, y1 = positions[a]
            x2, y2 = positions[b]
            ax5.plot([x1, x2], [y1, y2], color=BCS_COLORS["grid"], alpha=0.4, linewidth=0.6)
        for node, (x, y) in positions.items():
            ax5.scatter(x, y, s=60, color=BCS_COLORS["primary"], zorder=5, edgecolors="white")
    ax5.set_aspect("equal")
    ax5.axis("off")
    ax5.set_title("Network Topology")

    # Panel 6: Metrics bar chart
    ax6 = fig.add_subplot(gs[3, :])
    metric_names = ["Throughput\n(tx/s)", "Avg Latency\n(ms)", "Sync Success\n(%)", "Conflict\nRate (%)", "Offline TX\nSuccess (%)"]
    metric_values = [
        sim_metrics.throughput_tps,
        sim_metrics.avg_latency_ms,
        sim_metrics.sync_success_rate,
        sim_metrics.conflict_rate,
        sim_metrics.offline_tx_success_rate,
    ]
    colors = [BCS_COLORS["primary"], BCS_COLORS["secondary"], BCS_COLORS["accent"],
              BCS_COLORS["success"], BCS_COLORS["primary"]]
    bars = ax6.bar(metric_names, metric_values, color=colors, edgecolor="white", alpha=0.85)
    for bar, val in zip(bars, metric_values):
        ax6.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                 f"{val:.1f}", ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax6.set_ylabel("Value")
    ax6.set_title("Key Performance Metrics")
    ax6.grid(True, alpha=0.3, axis="y")
    ax6.set_facecolor(BCS_COLORS["background"])

    fig.patch.set_facecolor("white")
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    return output_path


def _format_summary(metrics: SimulationMetrics) -> str:
    """Format metrics as a text summary."""
    lines = [
        "=" * 50,
        "  BCS MiroFish Simulation Summary",
        "=" * 50,
        f"  Elapsed Time:        {metrics.elapsed_seconds:.1f} s",
        f"  Total Transactions:  {metrics.total_transactions}",
        f"  Confirmed TXs:       {metrics.confirmed_transactions}",
        f"  Throughput:          {metrics.throughput_tps:.2f} tx/s",
        f"  Avg Latency:         {metrics.avg_latency_ms:.1f} ms",
        f"  Confirmation Time:   {metrics.confirmation_time_ms:.1f} ms",
        f"  Blocks Created:      {metrics.blocks_created}",
        f"  N Circulating:       {metrics.n_circulating / 1e9:.2f} N",
        f"  N Gini Coefficient:  {metrics.n_concentration_gini:.4f}",
        f"  Sync Success Rate:   {metrics.sync_success_rate:.1f}%",
        f"  Conflict Rate:       {metrics.conflict_rate:.2f}%",
        f"  Offline TX Success:  {metrics.offline_tx_success_rate:.1f}%",
        "-" * 50,
        f"  Agents:  {metrics.agents_online} online / {metrics.agents_offline} offline",
        f"  Nodes:   {metrics.nodes_online} online / {metrics.nodes_offline} offline",
        f"  Partitions: {metrics.partition_events}  |  Failures: {metrics.failure_events}",
        "=" * 50,
    ]
    return "\n".join(lines)
