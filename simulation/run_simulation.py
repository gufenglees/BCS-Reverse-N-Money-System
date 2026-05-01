"""
MiroFish Simulation Entry Point
================================
Command-line interface for running BCS MiroFish simulations.

Usage:
    python run_simulation.py --scenario small_scale
    python run_simulation.py --nodes 50 --users 500 --txs 10000 --output ./results
    python run_simulation.py --all
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from scenarios import (
    run_small_scale_test,
    run_medium_scale_test,
    run_large_scale_test,
    run_offline_stress_test,
    run_partition_recovery_test,
    run_automation_shock_test,
    run_all_scenarios,
)


SCENARIO_MAP = {
    "small_scale": run_small_scale_test,
    "medium_scale": run_medium_scale_test,
    "large_scale": run_large_scale_test,
    "offline_stress": run_offline_stress_test,
    "partition_recovery": run_partition_recovery_test,
    "automation_shock": run_automation_shock_test,
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BCS MiroFish Simulation Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scenarios:
  small_scale        - 10 nodes, 50 users, 1,000 txs
  medium_scale       - 50 nodes, 500 users, 10,000 txs
  large_scale        - 200 nodes, 5,000 users, 100,000 txs
  offline_stress     - 50%% nodes offline, high conflict rate
  partition_recovery - Network partition and recovery
  automation_shock   - Parameter shock test
  all                - Run all scenarios
        """,
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="small_scale",
        help="Scenario to run (see list above)",
    )
    parser.add_argument(
        "--nodes",
        type=int,
        default=None,
        help="Override number of nodes",
    )
    parser.add_argument(
        "--users",
        type=int,
        default=None,
        help="Override number of users",
    )
    parser.add_argument(
        "--txs",
        type=int,
        default=None,
        help="Override target transaction count",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="/mnt/agents/output/bcs_chain/simulation/output",
        help="Output directory for reports",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Override simulation duration in seconds",
    )
    parser.add_argument(
        "--tx-rate",
        type=float,
        default=None,
        help="Override target tx/s rate",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all predefined scenarios",
    )

    args = parser.parse_args()
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("   BCS MiroFish Simulation Runner")
    print("   Bidirectional Currency System - Large-Scale Simulation")
    print("=" * 70)

    start_time = time.monotonic()

    if args.all:
        print("\nRunning ALL predefined scenarios...")
        results = run_all_scenarios(str(output_dir))
        print(f"\n{'='*70}")
        print("All scenarios completed!")
        for name, (metrics, json_path, png_path) in results.items():
            print(f"\n  {name}:")
            print(f"    Throughput: {metrics.throughput_tps:.2f} tx/s")
            print(f"    Latency:    {metrics.avg_latency_ms:.1f} ms")
            print(f"    JSON:       {json_path}")
            print(f"    PNG:        {png_path}")
    else:
        scenario_name = args.scenario
        if scenario_name not in SCENARIO_MAP and scenario_name != "custom":
            print(f"Error: Unknown scenario '{scenario_name}'")
            print(f"Available: {', '.join(SCENARIO_MAP.keys())}")
            return 1

        if scenario_name == "custom" or (args.nodes and args.users and args.txs):
            # Custom run
            from mirofish import MiroFishSimulator
            from visualization import generate_report

            nodes = args.nodes or 10
            users = args.users or 50
            txs = args.txs or 1_000
            duration = args.duration or 30
            tx_rate = args.tx_rate or 15.0

            print(f"\nRunning custom simulation:")
            print(f"  Nodes:     {nodes}")
            print(f"  Users:     {users}")
            print(f"  Target TXs:{txs}")
            print(f"  Duration:  {duration}s")
            print(f"  TX Rate:   {tx_rate} tx/s")
            print(f"  Seed:      {args.seed}")

            sim = MiroFishSimulator(
                num_nodes=nodes,
                num_users=users,
                num_transactions=txs,
                random_seed=args.seed,
            )
            sim.setup_network_topology(topology_type="small-world")
            sim.create_agents()
            metrics = sim.run_simulation(duration_seconds=duration, tx_rate=tx_rate)

            json_path = f"{output_dir}/custom_report.json"
            import json
            with open(json_path, "w") as f:
                json.dump(metrics.to_dict(), f, indent=2)

            png_path = f"{output_dir}/custom_report.png"
            generate_report(
                metrics=sim.metrics,
                sim_metrics=metrics,
                nodes=list(sim.nodes.keys()),
                edges=sim.network_edges,
                agents_summary=sim.get_agent_summary(),
                output_path=png_path,
            )
            print(f"\n  JSON: {json_path}")
            print(f"  PNG:  {png_path}")
        else:
            # Predefined scenario
            runner = SCENARIO_MAP[scenario_name]
            metrics, json_path, png_path = runner(str(output_dir))

            print(f"\n{'='*70}")
            print(f"Scenario '{scenario_name}' completed!")
            print(f"  Throughput:     {metrics.throughput_tps:.2f} tx/s")
            print(f"  Avg Latency:    {metrics.avg_latency_ms:.1f} ms")
            print(f"  Confirmation:   {metrics.confirmation_time_ms:.1f} ms")
            print(f"  N Circulating:  {metrics.n_circulating/1e9:.2f} N")
            print(f"  N Gini:         {metrics.n_concentration_gini:.4f}")
            print(f"  Sync Success:   {metrics.sync_success_rate:.1f}%")
            print(f"  Conflict Rate:  {metrics.conflict_rate:.2f}%")
            print(f"  JSON Report:    {json_path}")
            print(f"  PNG Report:     {png_path}")

    elapsed = time.monotonic() - start_time
    print(f"\n{'='*70}")
    print(f"Total execution time: {elapsed:.1f} seconds")
    print(f"{'='*70}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
