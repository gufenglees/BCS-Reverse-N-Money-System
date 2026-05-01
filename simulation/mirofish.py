"""
MiroFish Simulation Engine
==========================
A large-scale simulation framework for the BCS (Bidirectional Currency System).
Simulates network topology, agents, transactions, offline partitions, and node failures
in memory for rapid experimentation.
"""

from __future__ import annotations

import random
import time
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional, Any, Callable
from collections import defaultdict
from decimal import Decimal

# Add parent to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "currency"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "wallet"))

try:
    from transaction import Transaction, TxInput, TxOutput, TxType
    from block import Block, BlockHeader, BlockBody
    from utxo import UTXO, UTXOSet
    from state import AccountState, IdentityStatus, StateManager
    from wallet import Wallet
except ImportError:
    # Fallback: use direct file imports if package imports fail
    import importlib.util
    def _load_module(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
    
    _base = os.path.join(os.path.dirname(__file__), "..")
    _trans = _load_module("transaction", os.path.join(_base, "core", "transaction.py"))
    _block = _load_module("block", os.path.join(_base, "core", "block.py"))
    _utxo = _load_module("utxo", os.path.join(_base, "core", "utxo.py"))
    _state = _load_module("state", os.path.join(_base, "core", "state.py"))
    _wallet = _load_module("wallet_mod", os.path.join(_base, "wallet", "wallet.py"))
    
    Transaction = _trans.Transaction
    TxInput = _trans.TxInput
    TxOutput = _trans.TxOutput
    TxType = _trans.TxType
    Block = _block.Block
    BlockHeader = _block.BlockHeader
    BlockBody = _block.BlockBody
    UTXO = _utxo.UTXO
    UTXOSet = _utxo.UTXOSet
    AccountState = _state.AccountState
    IdentityStatus = _state.IdentityStatus
    StateManager = _state.StateManager
    Wallet = _wallet.Wallet

from metrics import MetricsCollector, SimulationMetrics


# =============================================================================
# Agent Base Class
# =============================================================================

@dataclass
class AgentConfig:
    """Configuration for an agent."""
    offline_probability: float = 0.1
    tx_probability_per_tick: float = 0.3
    avg_tx_amount: int = 1_000_000_000  # 1 N in nanoN


class Agent(ABC):
    """
    Base class for BCS simulation agents.

    Each agent has a wallet, behavior patterns, and an offline probability.
    """

    def __init__(
        self,
        agent_id: str,
        wallet: Wallet,
        password: str,
        address: str,
        config: AgentConfig,
    ):
        self.agent_id = agent_id
        self.wallet = wallet
        self.password = password
        self.address = address
        self.config = config
        self.balance: int = 0  # nanoN
        self.total_received: int = 0
        self.total_spent: int = 0
        self.tx_count: int = 0
        self.is_offline: bool = False
        self.offline_since: float = 0.0
        self.online_since: float = time.monotonic()
        self.offline_duration_total: float = 0.0
        self.pending_offline_txs: List[Transaction] = []
        self.lock_script: bytes = self._make_lock_script(address)
        self.history: List[Dict[str, Any]] = []

    def _make_lock_script(self, address: str) -> bytes:
        """Build a simple lock script from the address."""
        addr_bytes = address.encode()[:20].ljust(20, b"\x00")
        return b"\x76\xa9\x14" + addr_bytes + b"\x88\xac"

    @abstractmethod
    def act(self, tick: int, all_agents: List["Agent"], utxo_set: UTXOSet) -> Optional[Transaction]:
        """Perform an action for this tick; return a Transaction if one is created."""
        ...

    def go_offline(self) -> None:
        """Transition agent to offline state."""
        if not self.is_offline:
            self.is_offline = True
            self.offline_since = time.monotonic()

    def come_online(self) -> None:
        """Transition agent to online state."""
        if self.is_offline:
            self.is_offline = False
            self.offline_duration_total += time.monotonic() - self.offline_since
            self.online_since = time.monotonic()

    def record_history(self, event: str, data: Dict[str, Any]) -> None:
        """Record an event in the agent's history."""
        self.history.append({
            "tick": data.get("tick", -1),
            "event": event,
            "timestamp": time.monotonic(),
            "data": data,
        })

    def receive_n(self, amount: int) -> None:
        """Receive N currency."""
        self.balance += amount
        self.total_received += amount

    def spend_n(self, amount: int) -> bool:
        """Spend N currency if sufficient balance."""
        if self.balance >= amount:
            self.balance -= amount
            self.total_spent += amount
            return True
        return False


# =============================================================================
# Merchant Agent
# =============================================================================

class MerchantAgent(Agent):
    """
    Merchant agent: sells goods for D, requires N rebate from buyer.
    """

    def __init__(self, agent_id: str, wallet: Wallet, password: str, address: str, config: AgentConfig):
        super().__init__(agent_id, wallet, password, address, config)
        self.sale_count: int = 0
        self.total_sales_d: int = 0
        self.total_n_rebate: int = 0

    def act(self, tick: int, all_agents: List[Agent], utxo_set: UTXOSet) -> Optional[Transaction]:
        if self.is_offline:
            return None
        if random.random() > self.config.tx_probability_per_tick:
            return None

        # Find a consumer to sell to
        consumers = [a for a in all_agents if isinstance(a, ConsumerAgent) and not a.is_offline]
        if not consumers:
            return None

        buyer = random.choice(consumers)
        sale_d = random.randint(1000, 100_000)
        phi = Decimal(3) / Decimal(100)
        n_rebate = int(Decimal(sale_d) * phi)

        if buyer.balance < sale_d:
            return None

        # Create sale transaction: D from buyer to merchant, N rebate to buyer
        tx = Transaction(
            version=1,
            tx_type=TxType.TRANSFER_SALE,
            inputs=[],
            outputs=[
                TxOutput(amount=sale_d, lock_script=self.lock_script),          # D to merchant
                TxOutput(amount=n_rebate, lock_script=buyer.lock_script),       # N rebate to buyer
            ],
        )

        buyer.spend_n(sale_d)
        self.total_sales_d += sale_d
        self.total_n_rebate += n_rebate
        self.sale_count += 1
        self.tx_count += 1
        buyer.tx_count += 1
        self.record_history("sale", {"tick": tick, "amount_d": sale_d, "n_rebate": n_rebate, "buyer": buyer.agent_id})
        return tx


# =============================================================================
# Employer Agent
# =============================================================================

class EmployerAgent(Agent):
    """
    Employer agent: pays wages in D, receives N from workers.
    """

    def __init__(self, agent_id: str, wallet: Wallet, password: str, address: str, config: AgentConfig):
        super().__init__(agent_id, wallet, password, address, config)
        self.wage_count: int = 0
        self.total_wages_d: int = 0
        self.total_n_received: int = 0

    def act(self, tick: int, all_agents: List[Agent], utxo_set: UTXOSet) -> Optional[Transaction]:
        if self.is_offline:
            return None
        if random.random() > self.config.tx_probability_per_tick:
            return None

        workers = [a for a in all_agents if isinstance(a, WorkerAgent) and not a.is_offline]
        if not workers:
            return None

        worker = random.choice(workers)
        wage_d = random.randint(1000, 50_000)
        psi = Decimal(2) / Decimal(100)
        n_transfer = int(Decimal(wage_d) * psi)

        if worker.balance < n_transfer:
            return None

        tx = Transaction(
            version=1,
            tx_type=TxType.TRANSFER_WAGE,
            inputs=[],
            outputs=[
                TxOutput(amount=wage_d, lock_script=worker.lock_script),      # D wage to worker
                TxOutput(amount=n_transfer, lock_script=self.lock_script),   # N to employer
            ],
        )

        worker.receive_n(wage_d)
        worker.spend_n(n_transfer)
        self.total_wages_d += wage_d
        self.total_n_received += n_transfer
        self.wage_count += 1
        self.tx_count += 1
        worker.tx_count += 1
        self.record_history("wage", {"tick": tick, "amount_d": wage_d, "n_transfer": n_transfer, "worker": worker.agent_id})
        return tx


# =============================================================================
# Worker Agent
# =============================================================================

class WorkerAgent(Agent):
    """
    Worker agent: receives wages, pays N for transactions.
    """

    def __init__(self, agent_id: str, wallet: Wallet, password: str, address: str, config: AgentConfig):
        super().__init__(agent_id, wallet, password, address, config)
        self.wage_received_count: int = 0
        self.total_wages_received: int = 0

    def act(self, tick: int, all_agents: List[Agent], utxo_set: UTXOSet) -> Optional[Transaction]:
        if self.is_offline:
            return None
        if random.random() > self.config.tx_probability_per_tick:
            return None

        # Simple transfer to random agent
        targets = [a for a in all_agents if a.agent_id != self.agent_id and not a.is_offline]
        if not targets:
            return None

        target = random.choice(targets)
        amount = random.randint(100, min(self.balance // 2, 1_000_000_000))
        if amount <= 0:
            return None

        tx = Transaction(
            version=1,
            tx_type=TxType.TRANSFER,
            inputs=[],
            outputs=[
                TxOutput(amount=amount, lock_script=target.lock_script),
            ],
        )

        self.spend_n(amount)
        target.receive_n(amount)
        self.tx_count += 1
        target.tx_count += 1
        self.record_history("transfer", {"tick": tick, "amount": amount, "to": target.agent_id})
        return tx


# =============================================================================
# Consumer Agent
# =============================================================================

class ConsumerAgent(Agent):
    """
    Consumer agent: buys goods, receives N rebate from purchases.
    """

    def __init__(self, agent_id: str, wallet: Wallet, password: str, address: str, config: AgentConfig):
        super().__init__(agent_id, wallet, password, address, config)
        self.purchase_count: int = 0
        self.total_purchases_d: int = 0
        self.total_n_rebate_received: int = 0

    def act(self, tick: int, all_agents: List[Agent], utxo_set: UTXOSet) -> Optional[Transaction]:
        if self.is_offline:
            return None
        if random.random() > self.config.tx_probability_per_tick:
            return None

        # Find a merchant to buy from
        merchants = [a for a in all_agents if isinstance(a, MerchantAgent) and not a.is_offline]
        if not merchants:
            return None

        merchant = random.choice(merchants)
        purchase_d = random.randint(100, 10_000)
        phi = Decimal(3) / Decimal(100)
        n_rebate = int(Decimal(purchase_d) * phi)

        if self.balance < purchase_d:
            return None

        tx = Transaction(
            version=1,
            tx_type=TxType.TRANSFER_SALE,
            inputs=[],
            outputs=[
                TxOutput(amount=purchase_d, lock_script=merchant.lock_script),  # D to merchant
                TxOutput(amount=n_rebate, lock_script=self.lock_script),        # N rebate to self
            ],
        )

        self.spend_n(purchase_d)
        self.receive_n(n_rebate)
        self.total_purchases_d += purchase_d
        self.total_n_rebate_received += n_rebate
        self.purchase_count += 1
        self.tx_count += 1
        merchant.tx_count += 1
        self.record_history("purchase", {"tick": tick, "amount_d": purchase_d, "n_rebate": n_rebate, "merchant": merchant.agent_id})
        return tx


# =============================================================================
# Simulated Node
# =============================================================================

class SimulatedNode:
    """Lightweight in-memory blockchain node for simulation."""

    def __init__(self, node_id: str):
        self.node_id = node_id
        self.chain: List[Block] = []
        self.utxo_set = UTXOSet()
        self.mempool: List[Transaction] = []
        self.state_manager = StateManager()
        self.peers: Set[str] = set()
        self.is_online: bool = True
        self.block_height: int = 0
        self.blocks_created: int = 0
        self.txs_confirmed: int = 0
        self._init_genesis()

    def _init_genesis(self) -> None:
        header = BlockHeader(
            version=1,
            prev_block_hash="0" * 64,
            merkle_root_tx="0" * 64,
            merkle_root_utxo="0" * 64,
            merkle_root_identity="0" * 64,
            timestamp=1609459200000,
            height=0,
            tx_count=0,
            validator_pubkey="",
            signature="",
        )
        genesis = Block(header=header, body=BlockBody(transactions=[]))
        self.chain.append(genesis)
        self.block_height = 0

    def add_tx_to_mempool(self, tx: Transaction) -> bool:
        """Add transaction to mempool if node is online."""
        if not self.is_online:
            return False
        self.mempool.append(tx)
        return True

    def create_block(self, max_txs: int = 100) -> Optional[Block]:
        """Create a new block from mempool transactions."""
        if not self.is_online:
            return None
        txs_to_include = self.mempool[:max_txs]
        if not txs_to_include:
            # Empty block
            txs_to_include = []

        prev = self.chain[-1]
        tx_hashes = [tx.hash() for tx in txs_to_include]
        merkle_tx = self._compute_merkle(tx_hashes) if tx_hashes else "0" * 64

        # Apply txs to UTXO set
        for tx in txs_to_include:
            self.utxo_set.apply_transaction(tx)

        header = BlockHeader(
            version=1,
            prev_block_hash=prev.hash,
            merkle_root_tx=merkle_tx,
            merkle_root_utxo=self.utxo_set.merkle_root,
            merkle_root_identity="0" * 64,
            timestamp=prev.header.timestamp + 5000,
            height=prev.header.height + 1,
            tx_count=len(txs_to_include),
            validator_pubkey="",
            signature="",
        )
        block = Block(header=header, body=BlockBody(transactions=txs_to_include))
        self.chain.append(block)
        self.block_height = block.header.height
        self.blocks_created += 1
        self.txs_confirmed += len(txs_to_include)
        self.mempool = self.mempool[max_txs:]
        return block

    def _compute_merkle(self, hashes: List[str]) -> str:
        if not hashes:
            return "0" * 64
        if len(hashes) == 1:
            return hashlib.sha3_256(hashes[0].encode()).hexdigest()
        current = [hashlib.sha3_256(h.encode()).digest() for h in hashes]
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left
                next_level.append(hashlib.sha3_256(left + right).digest())
            current = next_level
        return current[0].hex()

    def get_balance(self, lock_script: bytes) -> int:
        utxos = self.utxo_set.get_all()
        return sum(u.amount for u in utxos if u.lock_script == lock_script)

    def fail(self) -> None:
        """Simulate node failure."""
        self.is_online = False

    def recover(self) -> None:
        """Recover from failure."""
        self.is_online = True


# =============================================================================
# MiroFish Simulator
# =============================================================================

class MiroFishSimulator:
    """
    Large-scale BCS simulation engine.

    Simulates a network of nodes, multiple agent types, transaction generation,
    offline partitions, and node failures.
    """

    def __init__(
        self,
        num_nodes: int,
        num_users: int,
        num_transactions: int,
        random_seed: int = 42,
    ):
        self.num_nodes = num_nodes
        self.num_users = num_users
        self.num_transactions_target = num_transactions
        self.random_seed = random_seed
        random.seed(random_seed)

        self.nodes: Dict[str, SimulatedNode] = {}
        self.agents: Dict[str, Agent] = {}
        self.network_edges: List[Tuple[str, str]] = []
        self.metrics = MetricsCollector()

        self.tick: int = 0
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.tx_generated: int = 0
        self.tx_confirmed: int = 0
        self.block_count: int = 0
        self.partition_events: List[Dict[str, Any]] = []
        self.failure_events: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def setup_network_topology(self, topology_type: str = "random") -> None:
        """
        Set up network topology: random, small-world, or star.
        """
        node_ids = [f"node_{i}" for i in range(self.num_nodes)]
        for nid in node_ids:
            self.nodes[nid] = SimulatedNode(nid)

        edges: Set[Tuple[str, str]] = set()

        if topology_type == "random":
            # Erdos-Renyi-like random graph with p=0.15
            p = 0.15
            for i, a in enumerate(node_ids):
                for b in node_ids[i + 1:]:
                    if random.random() < p:
                        edges.add((a, b))

        elif topology_type == "small-world":
            # Ring lattice with rewiring
            k = 4  # Each node connects to 2 nearest neighbors on each side
            for i, a in enumerate(node_ids):
                for j in range(1, k // 2 + 1):
                    b = node_ids[(i + j) % len(node_ids)]
                    edges.add((a, b))
            # Rewire with probability 0.3
            rewired = set()
            for a, b in list(edges):
                if random.random() < 0.3:
                    new_b = random.choice(node_ids)
                    if new_b != a:
                        rewired.add((a, new_b))
                else:
                    rewired.add((a, b))
            edges = rewired

        elif topology_type == "star":
            center = node_ids[0]
            for nid in node_ids[1:]:
                edges.add((center, nid))

        # Ensure connectivity: add random edges if too sparse
        for nid in node_ids:
            connected = any(a == nid or b == nid for a, b in edges)
            if not connected:
                other = random.choice([n for n in node_ids if n != nid])
                edges.add((nid, other))

        self.network_edges = list(edges)
        # Register peers
        for a, b in edges:
            self.nodes[a].peers.add(b)
            self.nodes[b].peers.add(a)

    def create_agents(self) -> None:
        """
        Create simulation agents: merchants, employers, workers, consumers.
        Distribution: 20% merchants, 20% employers, 30% workers, 30% consumers.
        """
        import tempfile

        counts = {
            "merchant": max(1, int(self.num_users * 0.2)),
            "employer": max(1, int(self.num_users * 0.2)),
            "worker": max(1, int(self.num_users * 0.3)),
            "consumer": self.num_users - max(1, int(self.num_users * 0.2)) - max(1, int(self.num_users * 0.2)) - max(1, int(self.num_users * 0.3)),
        }

        password = "sim_password"
        idx = 0

        for role, count in counts.items():
            for i in range(count):
                agent_id = f"{role}_{i}"
                db_path = os.path.join(tempfile.gettempdir(), f"sim_wallet_{agent_id}.db")
                wallet = Wallet(db_path)
                wallet.init_database()
                address = wallet.create_new(label=agent_id, password=password)

                config = AgentConfig(
                    offline_probability=random.uniform(0.05, 0.2),
                    tx_probability_per_tick=random.uniform(0.2, 0.5),
                    avg_tx_amount=random.randint(500_000_000, 2_000_000_000),
                )

                if role == "merchant":
                    agent = MerchantAgent(agent_id, wallet, password, address, config)
                elif role == "employer":
                    agent = EmployerAgent(agent_id, wallet, password, address, config)
                elif role == "worker":
                    agent = WorkerAgent(agent_id, wallet, password, address, config)
                else:
                    agent = ConsumerAgent(agent_id, wallet, password, address, config)

                # Initial balance
                initial_n = random.randint(1_000_000_000, 10_000_000_000)
                agent.balance = initial_n
                agent.total_received = initial_n

                self.agents[agent_id] = agent
                idx += 1

    # ------------------------------------------------------------------
    # Simulation run
    # ------------------------------------------------------------------

    def run_simulation(self, duration_seconds: int = 60, tx_rate: float = 10.0) -> SimulationMetrics:
        """
        Run the simulation for a given duration.

        Args:
            duration_seconds: Wall-clock simulation duration.
            tx_rate: Target transactions per second.
        """
        self.start_time = time.monotonic()
        target_end = self.start_time + duration_seconds
        txs_per_tick = max(1, int(tx_rate * 0.1))  # 100ms ticks
        tick_duration = 0.1  # 100ms per tick

        while time.monotonic() < target_end and self.tx_generated < self.num_transactions_target:
            self.tick += 1
            tick_start = time.monotonic()

            # 1. Simulate agent actions
            self._process_agent_actions()

            # 2. Nodes create blocks periodically (every 10 ticks = 1s)
            if self.tick % 10 == 0:
                self._process_block_creation()

            # 3. Simulate network propagation (simplified: all online nodes see all txs)
            self._propagate_transactions()

            # 4. Random offline/online transitions
            self._simulate_offline_transitions()

            # Tick timing
            elapsed = time.monotonic() - tick_start
            sleep_time = max(0, tick_duration - elapsed)
            if sleep_time > 0:
                time.sleep(sleep_time)

        self.end_time = time.monotonic()
        return self.collect_metrics()

    def _process_agent_actions(self) -> None:
        """Let each agent act and collect generated transactions."""
        agents = list(self.agents.values())
        utxo_set = list(self.nodes.values())[0].utxo_set if self.nodes else UTXOSet()

        for agent in agents:
            tx = agent.act(self.tick, agents, utxo_set)
            if tx:
                self.tx_generated += 1
                latency_start = time.monotonic()
                # Add to a random online node's mempool
                online_nodes = [n for n in self.nodes.values() if n.is_online]
                if online_nodes:
                    node = random.choice(online_nodes)
                    if node.add_tx_to_mempool(tx):
                        latency = time.monotonic() - latency_start
                        self.metrics.record_transaction(tx, latency_ms=latency * 1000)

    def _process_block_creation(self) -> None:
        """Have online validator nodes create blocks."""
        online_nodes = [n for n in self.nodes.values() if n.is_online]
        if not online_nodes:
            return
        # Round-robin among online nodes
        node = online_nodes[self.block_count % len(online_nodes)]
        block = node.create_block(max_txs=50)
        if block:
            self.block_count += 1
            self.tx_confirmed += len(block.body.transactions)
            self.metrics.record_block(block)

    def _propagate_transactions(self) -> None:
        """Simplified propagation: all online nodes share mempool contents."""
        if len(self.nodes) <= 1:
            return
        # Gather all unique txs from all mempools
        all_txs: Dict[str, Transaction] = {}
        for node in self.nodes.values():
            if node.is_online:
                for tx in node.mempool:
                    all_txs[tx.hash()] = tx
        # Broadcast to all online nodes
        for node in self.nodes.values():
            if node.is_online:
                existing = {tx.hash() for tx in node.mempool}
                for tx_hash, tx in all_txs.items():
                    if tx_hash not in existing:
                        node.mempool.append(tx)

    def _simulate_offline_transitions(self) -> None:
        """Randomly toggle agent and node offline/online states."""
        for agent in self.agents.values():
            if agent.is_offline:
                # 10% chance to come back online per tick
                if random.random() < 0.1:
                    agent.come_online()
                    self.metrics.record_offline_event({
                        "event": "come_online",
                        "agent": agent.agent_id,
                        "tick": self.tick,
                    })
            else:
                if random.random() < agent.config.offline_probability * 0.01:
                    agent.go_offline()
                    self.metrics.record_offline_event({
                        "event": "go_offline",
                        "agent": agent.agent_id,
                        "tick": self.tick,
                    })

    # ------------------------------------------------------------------
    # Failure & partition simulation
    # ------------------------------------------------------------------

    def simulate_offline_partitions(self, partition_probability: float = 0.1) -> None:
        """
        Simulate network partitions: randomly isolate subsets of nodes.
        """
        node_ids = list(self.nodes.keys())
        if len(node_ids) < 4:
            return

        if random.random() < partition_probability:
            # Partition: isolate a random subset
            subset_size = random.randint(1, len(node_ids) // 3)
            partition = set(random.sample(node_ids, subset_size))
            for nid in partition:
                self.nodes[nid].is_online = False
            self.partition_events.append({
                "tick": self.tick,
                "partitioned_nodes": list(partition),
                "partition_size": len(partition),
            })
            self.metrics.record_sync_event({
                "event": "partition",
                "nodes_affected": len(partition),
                "tick": self.tick,
            })

    def simulate_node_failures(self, failure_rate: float = 0.05) -> None:
        """
        Simulate random node failures and recoveries.
        """
        for node in self.nodes.values():
            if node.is_online:
                if random.random() < failure_rate:
                    node.fail()
                    self.failure_events.append({
                        "tick": self.tick,
                        "node": node.node_id,
                        "event": "failure",
                    })
            else:
                # Recovery probability
                if random.random() < 0.05:
                    node.recover()
                    self.failure_events.append({
                        "tick": self.tick,
                        "node": node.node_id,
                        "event": "recovery",
                    })

    # ------------------------------------------------------------------
    # Metrics collection
    # ------------------------------------------------------------------

    def collect_metrics(self) -> SimulationMetrics:
        """Collect and return comprehensive simulation metrics."""
        total_elapsed = self.end_time - self.start_time if self.end_time > self.start_time else 0.001
        throughput_tps = self.tx_confirmed / total_elapsed if total_elapsed > 0 else 0

        # N concentration (Gini coefficient)
        balances = [a.balance for a in self.agents.values()]
        gini = self._gini_coefficient(balances)

        # N circulating
        n_circulating = sum(a.balance for a in self.agents.values())

        # Offline events
        offline_events = self.metrics.offline_events
        offline_tx_count = sum(1 for e in offline_events if e.get("event") == "go_offline")
        online_tx_count = sum(1 for e in offline_events if e.get("event") == "come_online")
        offline_tx_success_rate = (online_tx_count / max(offline_tx_count, 1)) * 100

        # Latency stats
        latencies = self.metrics.tx_latencies_ms
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        confirmation_time = avg_latency * 1.5  # Simplified estimate

        # Sync success rate
        sync_events = self.metrics.sync_events
        partition_count = sum(1 for e in sync_events if e.get("event") == "partition")
        sync_success_rate = max(0, 100 - partition_count * 2)

        # Conflict rate
        conflict_count = len(self.partition_events)
        conflict_rate = (conflict_count / max(self.block_count, 1)) * 100

        return SimulationMetrics(
            throughput_tps=throughput_tps,
            avg_latency_ms=avg_latency,
            confirmation_time_ms=confirmation_time,
            sync_success_rate=sync_success_rate,
            conflict_rate=conflict_rate,
            n_concentration_gini=gini,
            n_circulating=n_circulating,
            offline_tx_success_rate=offline_tx_success_rate,
            total_transactions=self.tx_generated,
            confirmed_transactions=self.tx_confirmed,
            blocks_created=self.block_count,
            agents_online=sum(1 for a in self.agents.values() if not a.is_offline),
            agents_offline=sum(1 for a in self.agents.values() if a.is_offline),
            nodes_online=sum(1 for n in self.nodes.values() if n.is_online),
            nodes_offline=sum(1 for n in self.nodes.values() if not n.is_online),
            partition_events=len(self.partition_events),
            failure_events=len(self.failure_events),
            elapsed_seconds=total_elapsed,
        )

    @staticmethod
    def _gini_coefficient(values: List[int]) -> float:
        """Calculate Gini coefficient for inequality measurement."""
        if not values or sum(values) == 0:
            return 0.0
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        cumsum = 0
        for i, v in enumerate(sorted_vals, 1):
            cumsum += (2 * i - n - 1) * v
        denominator = n * sum(sorted_vals)
        return abs(cumsum) / denominator if denominator > 0 else 0.0

    def get_agent_summary(self) -> Dict[str, Any]:
        """Return summary statistics for all agents."""
        summary = {
            "merchants": [],
            "employers": [],
            "workers": [],
            "consumers": [],
        }
        for agent in self.agents.values():
            info = {
                "id": agent.agent_id,
                "balance": agent.balance,
                "tx_count": agent.tx_count,
                "total_received": agent.total_received,
                "total_spent": agent.total_spent,
                "offline_ratio": agent.offline_duration_total / max(self.end_time - self.start_time, 0.001),
            }
            if isinstance(agent, MerchantAgent):
                info["sales"] = agent.sale_count
                info["total_sales_d"] = agent.total_sales_d
                info["total_n_rebate"] = agent.total_n_rebate
                summary["merchants"].append(info)
            elif isinstance(agent, EmployerAgent):
                info["wages"] = agent.wage_count
                info["total_wages_d"] = agent.total_wages_d
                info["total_n_received"] = agent.total_n_received
                summary["employers"].append(info)
            elif isinstance(agent, WorkerAgent):
                info["wages_received"] = agent.total_wages_received
                summary["workers"].append(info)
            else:
                info["purchases"] = agent.purchase_count
                info["total_purchases_d"] = agent.total_purchases_d
                info["total_n_rebate_received"] = agent.total_n_rebate_received
                summary["consumers"].append(info)
        return summary
