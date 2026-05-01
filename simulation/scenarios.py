"""
Predefined Simulation Scenarios
=================================
Ready-to-run MiroFish simulation scenarios covering various scales
and stress conditions.
"""

from __future__ import annotations

import json
import time
from typing import Dict, Any, Tuple, Optional
from pathlib import Path

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from mirofish import MiroFishSimulator
from metrics import SimulationMetrics
from visualization import (
    plot_throughput_over_time,
    plot_latency_distribution,
    plot_n_distribution,
    plot_network_topology,
    plot_sync_events,
    generate_report,
)


def _run_and_save(
    sim: MiroFishSimulator,
    scenario_name: str,
    duration_seconds: int,
    tx_rate: float,
    output_dir: str = "/mnt/agents/output/bcs_chain/simulation/output",
) -> Tuple[SimulationMetrics, str, str]:
    """
    Helper: run simulation, save JSON report and PNG chart.
    Returns (metrics, json_path, png_path).
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"Running scenario: {scenario_name}")
    print(f"  Nodes: {sim.num_nodes}, Users: {sim.num_users}, Target TXs: {sim.num_transactions_target}")
    print(f"{'='*60}")

    # Setup
    sim.setup_network_topology(topology_type="small-world")
    sim.create_agents()

    # Run
    start = time.monotonic()
    metrics = sim.run_simulation(duration_seconds=duration_seconds, tx_rate=tx_rate)
    elapsed = time.monotonic() - start

    print(f"Simulation completed in {elapsed:.1f}s")
    print(f"  Generated: {metrics.total_transactions} txs")
    print(f"  Confirmed: {metrics.confirmed_transactions} txs")
    print(f"  Throughput: {metrics.throughput_tps:.2f} tx/s")

    # Save JSON
    json_path = f"{output_dir}/{scenario_name}_report.json"
    with open(json_path, "w") as f:
        json.dump(metrics.to_dict(), f, indent=2)
    print(f"  JSON report: {json_path}")

    # Save PNG
    png_path = f"{output_dir}/{scenario_name}_report.png"
    agents_summary = sim.get_agent_summary()
    nodes = list(sim.nodes.keys())
    edges = sim.network_edges

    generate_report(
        metrics=sim.metrics,
        sim_metrics=metrics,
        nodes=nodes,
        edges=edges,
        agents_summary=agents_summary,
        output_path=png_path,
    )
    print(f"  PNG report: {png_path}")

    # Optional: individual plots
    plot_throughput_over_time(sim.metrics, f"{output_dir}/{scenario_name}_throughput.png")
    plot_latency_distribution(sim.metrics, f"{output_dir}/{scenario_name}_latency.png")
    plot_n_distribution(agents_summary, f"{output_dir}/{scenario_name}_n_distribution.png")
    plot_network_topology(nodes, edges, f"{output_dir}/{scenario_name}_topology.png")
    plot_sync_events(sim.metrics, f"{output_dir}/{scenario_name}_sync_events.png")

    return metrics, json_path, png_path


# ---------------------------------------------------------------------------
# Scenario 1: Small Scale Test
# ---------------------------------------------------------------------------

def run_small_scale_test(output_dir: str = "/mnt/agents/output/bcs_chain/simulation/output") -> Tuple[SimulationMetrics, str, str]:
    """
    Small-scale baseline test.
    10 nodes, 50 users, 1,000 transactions.
    """
    sim = MiroFishSimulator(
        num_nodes=10,
        num_users=50,
        num_transactions=1_000,
        random_seed=42,
    )
    return _run_and_save(
        sim=sim,
        scenario_name="small_scale",
        duration_seconds=30,
        tx_rate=15.0,
        output_dir=output_dir,
    )


# ---------------------------------------------------------------------------
# Scenario 2: Medium Scale Test
# ---------------------------------------------------------------------------

def run_medium_scale_test(output_dir: str = "/mnt/agents/output/bcs_chain/simulation/output") -> Tuple[SimulationMetrics, str, str]:
    """
    Medium-scale test.
    50 nodes, 500 users, 10,000 transactions.
    """
    sim = MiroFishSimulator(
        num_nodes=50,
        num_users=500,
        num_transactions=10_000,
        random_seed=123,
    )
    return _run_and_save(
        sim=sim,
        scenario_name="medium_scale",
        duration_seconds=60,
        tx_rate=20.0,
        output_dir=output_dir,
    )


# ---------------------------------------------------------------------------
# Scenario 3: Large Scale Test
# ---------------------------------------------------------------------------

def run_large_scale_test(output_dir: str = "/mnt/agents/output/bcs_chain/simulation/output") -> Tuple[SimulationMetrics, str, str]:
    """
    Large-scale stress test.
    200 nodes, 5,000 users, 100,000 transactions.
    """
    sim = MiroFishSimulator(
        num_nodes=200,
        num_users=5_000,
        num_transactions=100_000,
        random_seed=999,
    )
    return _run_and_save(
        sim=sim,
        scenario_name="large_scale",
        duration_seconds=120,
        tx_rate=50.0,
        output_dir=output_dir,
    )


# ---------------------------------------------------------------------------
# Scenario 4: Offline Stress Test
# ---------------------------------------------------------------------------

def run_offline_stress_test(output_dir: str = "/mnt/agents/output/bcs_chain/simulation/output") -> Tuple[SimulationMetrics, str, str]:
    """
    Offline stress test: 50% of nodes offline, high conflict rate expected.
    100 nodes, 1,000 users, 20,000 transactions.
    """
    sim = MiroFishSimulator(
        num_nodes=100,
        num_users=1_000,
        num_transactions=20_000,
        random_seed=777,
    )
    sim.setup_network_topology(topology_type="random")
    sim.create_agents()

    # Force 50% of nodes offline
    offline_nodes = list(sim.nodes.keys())[:50]
    for nid in offline_nodes:
        sim.nodes[nid].is_online = False

    print(f"\n{'='*60}")
    print("Running scenario: offline_stress")
    print(f"  Forced {len(offline_nodes)} nodes offline (50%)")
    print(f"{'='*60}")

    metrics = sim.run_simulation(duration_seconds=60, tx_rate=25.0)

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    json_path = f"{output_dir}/offline_stress_report.json"
    with open(json_path, "w") as f:
        json.dump(metrics.to_dict(), f, indent=2)

    png_path = f"{output_dir}/offline_stress_report.png"
    generate_report(
        metrics=sim.metrics,
        sim_metrics=metrics,
        nodes=list(sim.nodes.keys()),
        edges=sim.network_edges,
        agents_summary=sim.get_agent_summary(),
        output_path=png_path,
    )
    return metrics, json_path, png_path


# ---------------------------------------------------------------------------
# Scenario 5: Partition Recovery Test
# ---------------------------------------------------------------------------

def run_partition_recovery_test(output_dir: str = "/mnt/agents/output/bcs_chain/simulation/output") -> Tuple[SimulationMetrics, str, str]:
    """
    Network partition recovery test.
    Simulates a partition, then heals it and measures recovery time.
    50 nodes, 500 users, 15,000 transactions.
    """
    sim = MiroFishSimulator(
        num_nodes=50,
        num_users=500,
        num_transactions=15_000,
        random_seed=555,
    )
    sim.setup_network_topology(topology_type="small-world")
    sim.create_agents()

    print(f"\n{'='*60}")
    print("Running scenario: partition_recovery")
    print(f"{'='*60}")

    # Phase 1: Normal operation for 15s
    normal_metrics = sim.run_simulation(duration_seconds=15, tx_rate=20.0)

    # Phase 2: Introduce partition at ~20s mark
    partition_nodes = list(sim.nodes.keys())[:20]
    for nid in partition_nodes:
        sim.nodes[nid].is_online = False
    sim.partition_events.append({
        "tick": sim.tick,
        "partitioned_nodes": partition_nodes,
        "event": "manual_partition",
    })
    print(f"  Introduced partition: {len(partition_nodes)} nodes isolated")

    # Phase 3: Continue with partition for 15s
    partitioned_metrics = sim.run_simulation(duration_seconds=15, tx_rate=20.0)

    # Phase 4: Heal partition
    for nid in partition_nodes:
        sim.nodes[nid].is_online = True
    sim.metrics.record_sync_event({"event": "heal", "nodes_affected": len(partition_nodes), "tick": sim.tick})
    print(f"  Healed partition: {len(partition_nodes)} nodes rejoined")

    # Phase 5: Recovery period for 15s
    recovery_metrics = sim.run_simulation(duration_seconds=15, tx_rate=20.0)

    # Final metrics
    final_metrics = sim.collect_metrics()

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    json_path = f"{output_dir}/partition_recovery_report.json"
    with open(json_path, "w") as f:
        json.dump(final_metrics.to_dict(), f, indent=2)

    png_path = f"{output_dir}/partition_recovery_report.png"
    generate_report(
        metrics=sim.metrics,
        sim_metrics=final_metrics,
        nodes=list(sim.nodes.keys()),
        edges=sim.network_edges,
        agents_summary=sim.get_agent_summary(),
        output_path=png_path,
    )
    return final_metrics, json_path, png_path


# ---------------------------------------------------------------------------
# Scenario 6: Automation Shock Test
# ---------------------------------------------------------------------------

def run_automation_shock_test(output_dir: str = "/mnt/agents/output/bcs_chain/simulation/output") -> Tuple[SimulationMetrics, str, str]:
    """
    Automation shock test: simulate a sudden change in system parameters (e.g., phi change).
    80 nodes, 800 users, 30,000 transactions.
    """
    sim = MiroFishSimulator(
        num_nodes=80,
        num_users=800,
        num_transactions=30_000,
        random_seed=888,
    )
    sim.setup_network_topology(topology_type="random")
    sim.create_agents()

    print(f"\n{'='*60}")
    print("Running scenario: automation_shock")
    print(f"{'='*60}")

    # Phase 1: Baseline (phi = 3%)
    print("  Phase 1: Baseline (phi=3%)")
    sim.run_simulation(duration_seconds=20, tx_rate=25.0)

    # Phase 2: Shock - phi drops to 1% (more aggressive rebate)
    print("  Phase 2: Shock - phi drops to 1%")
    # Adjust agent configs
    for agent in sim.agents.values():
        agent.config.tx_probability_per_tick *= 1.5  # More activity

    sim.metrics.record_sync_event({"event": "automation_shock", "parameter": "phi", "old_value": 0.03, "new_value": 0.01, "tick": sim.tick})
    sim.run_simulation(duration_seconds=20, tx_rate=35.0)

    # Phase 3: Stabilization
    print("  Phase 3: Stabilization")
    for agent in sim.agents.values():
        agent.config.tx_probability_per_tick *= 0.8  # Slight cooldown
    sim.run_simulation(duration_seconds=20, tx_rate=30.0)

    final_metrics = sim.collect_metrics()

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    json_path = f"{output_dir}/automation_shock_report.json"
    with open(json_path, "w") as f:
        json.dump(final_metrics.to_dict(), f, indent=2)

    png_path = f"{output_dir}/automation_shock_report.png"
    generate_report(
        metrics=sim.metrics,
        sim_metrics=final_metrics,
        nodes=list(sim.nodes.keys()),
        edges=sim.network_edges,
        agents_summary=sim.get_agent_summary(),
        output_path=png_path,
    )
    return final_metrics, json_path, png_path


# ---------------------------------------------------------------------------
# All scenarios runner
# ---------------------------------------------------------------------------

def run_all_scenarios(output_dir: str = "/mnt/agents/output/bcs_chain/simulation/output") -> Dict[str, Tuple[SimulationMetrics, str, str]]:
    """Run all predefined scenarios and return results."""
    results = {}
    results["small_scale"] = run_small_scale_test(output_dir)
    results["medium_scale"] = run_medium_scale_test(output_dir)
    results["large_scale"] = run_large_scale_test(output_dir)
    results["offline_stress"] = run_offline_stress_test(output_dir)
    results["partition_recovery"] = run_partition_recovery_test(output_dir)
    results["automation_shock"] = run_automation_shock_test(output_dir)
    return results
