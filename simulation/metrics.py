"""
Simulation Metrics Collector
=============================
Collects and aggregates metrics during MiroFish simulations.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from collections import defaultdict


@dataclass
class SimulationMetrics:
    """Complete simulation metrics snapshot."""
    throughput_tps: float = 0.0
    avg_latency_ms: float = 0.0
    confirmation_time_ms: float = 0.0
    sync_success_rate: float = 100.0
    conflict_rate: float = 0.0
    n_concentration_gini: float = 0.0
    n_circulating: int = 0
    offline_tx_success_rate: float = 100.0
    total_transactions: int = 0
    confirmed_transactions: int = 0
    blocks_created: int = 0
    agents_online: int = 0
    agents_offline: int = 0
    nodes_online: int = 0
    nodes_offline: int = 0
    partition_events: int = 0
    failure_events: int = 0
    elapsed_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "throughput_tps": round(self.throughput_tps, 2),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "confirmation_time_ms": round(self.confirmation_time_ms, 2),
            "sync_success_rate": round(self.sync_success_rate, 2),
            "conflict_rate": round(self.conflict_rate, 2),
            "n_concentration_gini": round(self.n_concentration_gini, 4),
            "n_circulating": self.n_circulating,
            "offline_tx_success_rate": round(self.offline_tx_success_rate, 2),
            "total_transactions": self.total_transactions,
            "confirmed_transactions": self.confirmed_transactions,
            "blocks_created": self.blocks_created,
            "agents_online": self.agents_online,
            "agents_offline": self.agents_offline,
            "nodes_online": self.nodes_online,
            "nodes_offline": self.nodes_offline,
            "partition_events": self.partition_events,
            "failure_events": self.failure_events,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
        }


class MetricsCollector:
    """
    Records events during simulation and produces aggregated metrics.
    """

    def __init__(self):
        self.tx_latencies_ms: List[float] = []
        self.tx_timestamps: List[float] = []
        self.blocks: List[Dict[str, Any]] = []
        self.sync_events: List[Dict[str, Any]] = []
        self.offline_events: List[Dict[str, Any]] = []
        self._tx_count_per_tick: Dict[int, int] = defaultdict(int)
        self._block_times: List[float] = []
        self._start_time: float = time.monotonic()

    # ------------------------------------------------------------------
    # Recording methods
    # ------------------------------------------------------------------

    def record_transaction(self, tx: Any, latency_ms: float) -> None:
        """Record a transaction with its latency."""
        self.tx_latencies_ms.append(latency_ms)
        self.tx_timestamps.append(time.monotonic())

    def record_block(self, block: Any) -> None:
        """Record block creation event."""
        ts = time.monotonic()
        self.blocks.append({
            "height": getattr(block.header, "height", 0),
            "tx_count": len(getattr(block.body, "transactions", [])),
            "timestamp": ts,
            "merkle_root": getattr(block.header, "merkle_root_tx", ""),
        })
        self._block_times.append(ts)

    def record_sync_event(self, event: Dict[str, Any]) -> None:
        """Record a network sync event."""
        self.sync_events.append({
            **event,
            "timestamp": time.monotonic(),
        })

    def record_offline_event(self, event: Dict[str, Any]) -> None:
        """Record an offline/online transition event."""
        self.offline_events.append({
            **event,
            "timestamp": time.monotonic(),
        })

    # ------------------------------------------------------------------
    # Computed metrics
    # ------------------------------------------------------------------

    def get_latency_percentiles(self) -> Dict[str, float]:
        """Return latency percentiles (p50, p95, p99)."""
        if not self.tx_latencies_ms:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0}
        sorted_lat = sorted(self.tx_latencies_ms)
        n = len(sorted_lat)
        return {
            "p50": sorted_lat[int(n * 0.5)],
            "p95": sorted_lat[int(n * 0.95)] if n >= 20 else sorted_lat[-1],
            "p99": sorted_lat[int(n * 0.99)] if n >= 100 else sorted_lat[-1],
        }

    def get_throughput_over_time(self, bucket_seconds: float = 1.0) -> List[Tuple[float, float]]:
        """Return throughput (tx/s) over time buckets."""
        if not self.tx_timestamps:
            return []
        start = self._start_time
        buckets: Dict[int, int] = defaultdict(int)
        for ts in self.tx_timestamps:
            bucket = int((ts - start) / bucket_seconds)
            buckets[bucket] += 1
        return [(b * bucket_seconds, count / bucket_seconds) for b, count in sorted(buckets.items())]

    def get_block_interval_stats(self) -> Dict[str, float]:
        """Return block interval statistics."""
        if len(self._block_times) < 2:
            return {"avg": 0.0, "min": 0.0, "max": 0.0}
        intervals = [
            self._block_times[i] - self._block_times[i - 1]
            for i in range(1, len(self._block_times))
        ]
        return {
            "avg": sum(intervals) / len(intervals),
            "min": min(intervals),
            "max": max(intervals),
        }

    def get_summary(self) -> Dict[str, Any]:
        """Return a human-readable summary."""
        lat = self.get_latency_percentiles()
        tp = self.get_throughput_over_time()
        bi = self.get_block_interval_stats()
        return {
            "transactions_recorded": len(self.tx_latencies_ms),
            "blocks_recorded": len(self.blocks),
            "sync_events": len(self.sync_events),
            "offline_events": len(self.offline_events),
            "latency_ms": lat,
            "throughput_samples": len(tp),
            "block_interval_s": bi,
        }
