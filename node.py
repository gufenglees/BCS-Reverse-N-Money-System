"""
BCS Node — Main Node Entry Point
=================================
Integrates all BCS modules into a single runnable node process.

Architecture Overview:
    ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
    │  REST API   │   │   gRPC API  │   │    CLI      │
    └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
           │                  │                 │
           └──────────────────┼─────────────────┘
                              ▼
                    ┌─────────────────┐
                    │   BCSNode       │
                    │  (this module)  │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
   ┌─────────┐        ┌──────────┐        ┌─────────────┐
   │  Core   │        │ Currency │        │  Identity   │
   │(chain)  │        │(rules)   │        │(registry)   │
   └────┬────┘        └────┬─────┘        └──────┬──────┘
        │                  │                     │
        ▼                  ▼                     ▼
   ┌─────────┐        ┌──────────┐        ┌─────────────┐
   │  Mempool│        │Governance│        │  Trust      │
   │ Storage │        │  Params  │        │  Anchor     │
   └─────────┘        └──────────┘        └─────────────┘
        │
        ▼
   ┌─────────┐   ┌─────────────┐
   │  P2P    │   │   Offline   │
   │ Network │   │   Sync      │
   └─────────┘   └─────────────┘

Usage:
    node = BCSNode("/etc/bcs/node.toml")
    await node.start()
    ...
    await node.stop()
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
#  Ensure sibling imports work for all subpackages (existing modules use
#  implicit relative style, e.g. `from transaction import Transaction`).
#  When running as a module (`python -m bcs_chain.node`) this is not needed,
#  but when invoked as a script we patch sys.path accordingly.
# --------------------------------------------------------------------------- #
_PACKAGE_ROOT = Path(__file__).parent.resolve()
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))
for _subdir in ("core", "currency", "identity", "offline", "zk", "api", "network", "wallet", "cli"):
    _sp = _PACKAGE_ROOT / _subdir
    if str(_sp) not in sys.path:
        sys.path.insert(0, str(_sp))

# Core imports
from core.block import Block, BlockBody, BlockHeader
from core.transaction import Transaction, TxInput, TxOutput, TxType, ZKProof
from core.utxo import UTXOSet, UTXO
from core.state import StateManager, IdentityStatus
from core.validator import TxValidator, BlockValidator, SystemParams, ValidationResult
from core.mempool import Mempool
from core.storage import BlockStore, IndexStore
from core.consensus import PoABFTConsensus, ValidatorSet, ValidatorInfo

# Currency imports
from currency.params import SystemParameters, GovernanceParams
from currency.rules_engine import CurrencyRulesEngine
from currency.feasibility import NFeasibilityEngine
from currency.n_lifecycle import NLifecycleManager

# Identity imports
from identity.registry import IdentityRegistry, IdentityRecord, IdentityStatus as RegIdentityStatus
from identity.did import DIDDocument
from identity.trust_anchor import TrustAnchorRegistry

# Offline imports
from offline.sync import SyncEngine, SyncResult
from offline.cache import TxCache
from offline.utxo_view import UTXOSyncView
from offline.conflict_resolver import ConflictResolver

# Network imports
from network.p2p import P2PNode, Peer
from network.messages import Message, MessageType

# API imports
from api.rest_server import create_app, NodeAppState
from api.grpc_server import create_grpc_server, NodeServiceServicer
from api.schemas import SystemParametersSchema

# Wallet imports (for node key management)
from wallet.wallet import Wallet

# ZK imports
from zk.verifier import ZKVerifier

# TOML config parsing
try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # type: ignore


# --------------------------------------------------------------------------- #
#  Node Configuration
# --------------------------------------------------------------------------- #

@dataclass
class NodeConfig:
    """Runtime configuration for BCSNode."""

    # Network
    listen_host: str = "0.0.0.0"
    p2p_port: int = 10001
    rest_port: int = 8080
    grpc_port: int = 50051
    bootstrap_peers: List[str] = field(default_factory=list)
    network_id: str = "bcs-testnet"

    # Consensus
    block_interval_ms: int = 5_000
    validator_id: int = 0
    validator_pubkey_hex: str = ""
    validator_privkey_hex: str = ""  # hex-encoded raw secp256k1 private key
    validator_name: str = ""

    # Storage
    data_dir: str = "./bcs_data"
    db_name: str = "bcs_chain.db"

    # Governance
    phi_numerator: int = 3
    phi_denominator: int = 100
    psi_numerator: int = 5
    psi_denominator: int = 100
    required_gov_signatures: int = 2
    n_lower_bound: int = 0
    n_upper_bound: int = 10_000_000_000_000  # 10,000 N in nanoN

    # API
    enable_rest: bool = True
    enable_grpc: bool = True
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    rate_limit_rps: int = 100

    # Identity bootstrap
    trust_anchors: List[Dict[str, str]] = field(default_factory=list)

    @classmethod
    def from_toml(cls, path: str) -> "NodeConfig":
        """Load configuration from a TOML file."""
        with open(path, "rb") as f:
            data = tomllib.load(f)

        net = data.get("network", {})
        consensus = data.get("consensus", {})
        storage = data.get("storage", {})
        governance = data.get("governance", {})
        api = data.get("api", {})
        identity = data.get("identity", {})

        return cls(
            listen_host=net.get("listen_host", "0.0.0.0"),
            p2p_port=net.get("p2p_port", 10001),
            rest_port=net.get("rest_port", 8080),
            grpc_port=net.get("grpc_port", 50051),
            bootstrap_peers=net.get("bootstrap_peers", []),
            network_id=net.get("network_id", "bcs-testnet"),
            block_interval_ms=consensus.get("block_interval_ms", 5_000),
            validator_id=consensus.get("validator_id", 0),
            validator_pubkey_hex=consensus.get("validator_pubkey_hex", ""),
            validator_privkey_hex=consensus.get("validator_privkey_hex", ""),
            validator_name=consensus.get("validator_name", ""),
            data_dir=storage.get("data_dir", "./bcs_data"),
            db_name=storage.get("db_name", "bcs_chain.db"),
            phi_numerator=governance.get("phi_numerator", 3),
            phi_denominator=governance.get("phi_denominator", 100),
            psi_numerator=governance.get("psi_numerator", 5),
            psi_denominator=governance.get("psi_denominator", 100),
            required_gov_signatures=governance.get("required_gov_signatures", 2),
            n_lower_bound=governance.get("n_lower_bound", 0),
            n_upper_bound=governance.get("n_upper_bound", 10_000_000_000_000),
            enable_rest=api.get("enable_rest", True),
            enable_grpc=api.get("enable_grpc", True),
            cors_origins=api.get("cors_origins", ["*"]),
            rate_limit_rps=api.get("rate_limit_rps", 100),
            trust_anchors=identity.get("trust_anchors", []),
        )

    @classmethod
    def from_file(cls, path: str) -> "NodeConfig":
        """Alias for from_toml with fallback to defaults."""
        if not os.path.exists(path):
            print(f"[WARN] Config file not found: {path}, using defaults")
            return cls()
        return cls.from_toml(path)


# --------------------------------------------------------------------------- #
#  BCSNode
# --------------------------------------------------------------------------- #

class BCSNode:
    """
    Main BCS blockchain node.

    Integrates: core blockchain, currency rules, identity registry,
    offline sync, P2P network, REST/gRPC APIs, and consensus.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        """
        Initialize the node and all subsystems.

        Args:
            config_path: Path to a TOML configuration file.
                         If None, uses default configuration.
        """
        self.config: NodeConfig = (
            NodeConfig.from_file(config_path) if config_path else NodeConfig()
        )

        # --- Data directory setup ---
        self._data_dir = Path(self.config.data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = self._data_dir / self.config.db_name

        # --- Core subsystems ---
        self.block_store = BlockStore(str(self._db_path))
        self.index_store = IndexStore(str(self._db_path))
        self.utxo_set = UTXOSet()
        self.state_manager = StateManager()
        self.mempool = Mempool()

        # --- Currency / governance ---
        self.governance = GovernanceParams(
            genesis_params=SystemParameters(
                phi_numerator=self.config.phi_numerator,
                phi_denominator=self.config.phi_denominator,
                psi_numerator=self.config.psi_numerator,
                psi_denominator=self.config.psi_denominator,
                block_interval_ms=self.config.block_interval_ms,
                required_gov_signatures=self.config.required_gov_signatures,
            )
        )
        self.currency_engine = CurrencyRulesEngine(
            governance=self.governance,
            get_balance=self._get_balance,
        )
        self.feasibility_engine = NFeasibilityEngine()
        self.n_lifecycle = NLifecycleManager(current_height=0)

        # --- Identity ---
        self.identity_registry = IdentityRegistry(str(self._data_dir / "identity.db"))
        self.trust_anchor_registry = TrustAnchorRegistry(
            governance_threshold=self.config.required_gov_signatures
        )
        self._load_bootstrap_trust_anchors()

        # --- Offline ---
        self.tx_cache = TxCache(str(self._data_dir / "tx_cache.db"))
        self.utxo_sync_view = UTXOSyncView(initial_chain_utxos=self.utxo_set)
        self.conflict_resolver = ConflictResolver()
        self.sync_engine = SyncEngine(
            cache=self.tx_cache,
            utxo_view=self.utxo_sync_view,
        )

        # --- Consensus ---
        self.validator_set: Optional[ValidatorSet] = None
        self.consensus: Optional[PoABFTConsensus] = None
        self._validator_privkey: Optional[bytes] = None
        self._init_consensus()

        # --- P2P ---
        self.p2p = P2PNode(
            node_id=self.config.validator_name or f"node-{self.config.validator_id}",
            listen_host=self.config.listen_host,
            listen_port=self.config.p2p_port,
            network_id=self.config.network_id,
        )
        self.p2p.on_tx_received = self._on_p2p_tx
        self.p2p.on_block_received = self._on_p2p_block

        # --- API ---
        self._rest_app: Optional[Any] = None
        self._rest_server: Optional[Any] = None
        self._grpc_server: Optional[Any] = None

        # --- Lifecycle ---
        self._running = False
        self._shutdown_event = asyncio.Event()
        self._tasks: set[asyncio.Task] = set()
        self._start_time: float = 0.0
        self._block_proposal_task: Optional[asyncio.Task] = None

        # Wire app state for REST server
        self._app_state = NodeAppState()
        self._wire_app_state()

    # ------------------------------------------------------------------ #
    #  Internal initializers
    # ------------------------------------------------------------------ #

    def _init_consensus(self) -> None:
        """Initialize consensus with validator set from config."""
        # In a real network, validators would be loaded from genesis or
        # governance state. Here we create a single-validator set if
        # configured, or a default set for testing.
        if self.config.validator_pubkey_hex:
            validators = [
                ValidatorInfo(
                    validator_id=self.config.validator_id,
                    pubkey_hex=self.config.validator_pubkey_hex,
                    name=self.config.validator_name or f"val{self.config.validator_id}",
                    weight=1,
                )
            ]
            self.validator_set = ValidatorSet(validators)
            self.consensus = PoABFTConsensus(
                validator_set=self.validator_set,
                mempool=self.mempool,
                utxo_set=self.utxo_set,
                state_manager=self.state_manager,
                params=SystemParams(
                    block_interval_ms=self.config.block_interval_ms,
                    max_tx_per_block=2_000,
                    max_block_size=1_048_576,
                ),
                block_store=self.block_store,
            )
            if self.config.validator_privkey_hex:
                self._validator_privkey = bytes.fromhex(self.config.validator_privkey_hex)
        else:
            # No validator configured — observer mode
            self.validator_set = None
            self.consensus = None

    def _wire_app_state(self) -> None:
        """Connect the REST app state to node subsystems."""
        self._app_state.mempool = self.mempool
        self._app_state.blockchain = self.block_store
        self._app_state.utxo_manager = self.utxo_set
        self._app_state.identity_registry = self.identity_registry
        self._app_state.trust_anchor_registry = self.trust_anchor_registry
        self._app_state.params = self.governance.latest()
        self._app_state.offline_sync_engine = self.sync_engine
        self._app_state.zk_verifier = ZKVerifier()

    def _load_bootstrap_trust_anchors(self) -> None:
        """
        Load genesis/configured Trust Anchors into the local registry.

        In production, Trust Anchor changes should be driven by on-chain
        governance.  These config entries are bootstrap trust roots for a new
        network or local development environment.
        """
        for anchor in self.config.trust_anchors:
            try:
                self.trust_anchor_registry.add_anchor(
                    anchor_id=anchor["id"],
                    name=anchor.get("name", anchor["id"]),
                    public_key=anchor["public_key"],
                    url=anchor.get("url", ""),
                    gov_signatures=["bootstrap"] * max(1, self.config.required_gov_signatures),
                )
            except Exception as exc:
                print(f"[WARN] Failed to load trust anchor {anchor.get('id', '<unknown>')}: {exc}")

    def _get_balance(self, address: str) -> int:
        """Callable for CurrencyRulesEngine to query balances."""
        utxos = self.index_store.get_utxos_by_address(address, unspent_only=True)
        return sum(u.amount for u in utxos)

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        """
        Start the node: API servers, P2P network, and consensus loop.
        """
        if self._running:
            return
        self._running = True
        self._start_time = time.monotonic()
        print(f"[NODE] BCSNode starting (network={self.config.network_id})")

        # 1. Load chain tip from storage
        latest = self.block_store.get_latest_block()
        if latest:
            if self.consensus:
                self.consensus.chain_tip = latest
            print(f"[NODE] Loaded chain tip: height={latest.header.height}")
        else:
            print("[NODE] No existing chain found — awaiting genesis")

        # 2. Start P2P
        await self.p2p.start(bootstrap_peers=self.config.bootstrap_peers)

        # 3. Start REST API
        if self.config.enable_rest:
            await self._start_rest()

        # 4. Start gRPC
        if self.config.enable_grpc:
            await self._start_grpc()

        # 5. Start consensus block proposal loop (if validator)
        if self.consensus and self._validator_privkey:
            self._block_proposal_task = asyncio.create_task(self._consensus_loop())
            self._tasks.add(self._block_proposal_task)
            self._block_proposal_task.add_done_callback(self._tasks.discard)

        # 6. Setup signal handlers for graceful shutdown
        self._setup_signals()

        print(f"[NODE] BCSNode started. REST={self.config.rest_port}, P2P={self.config.p2p_port}, gRPC={self.config.grpc_port}")

    async def stop(self) -> None:
        """Gracefully shut down all subsystems."""
        if not self._running:
            return
        self._running = False
        self._shutdown_event.set()
        print("[NODE] Shutting down...")

        # Cancel consensus loop
        if self._block_proposal_task:
            self._block_proposal_task.cancel()
            try:
                await self._block_proposal_task
            except asyncio.CancelledError:
                pass

        # Cancel all tracked tasks
        for task in list(self._tasks):
            task.cancel()

        # Stop APIs
        if self._rest_server:
            self._rest_server.close()
            await self._rest_server.wait_closed()

        if self._grpc_server:
            self._grpc_server.stop(grace_period=5.0)
            # Wait for shutdown
            self._grpc_server.wait_for_termination(timeout=10)

        # Stop P2P
        await self.p2p.stop()

        # Close stores
        self.block_store.close()
        self.index_store.close()
        self.identity_registry.close()
        self.tx_cache.close()

        print("[NODE] BCSNode stopped")

    def _setup_signals(self) -> None:
        """Register OS signal handlers for graceful shutdown."""
        loop = asyncio.get_running_loop()

        def _signal_handler(sig: int) -> None:
            print(f"\n[NODE] Received signal {sig}, initiating shutdown...")
            asyncio.create_task(self.stop())

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda s=sig: _signal_handler(s))
            except NotImplementedError:
                pass  # Windows does not support add_signal_handler

    # ------------------------------------------------------------------ #
    #  API Starters
    # ------------------------------------------------------------------ #

    async def _start_rest(self) -> None:
        """Start the uvicorn-based REST server."""
        import uvicorn

        app = create_app(app_state=self._app_state)
        config = uvicorn.Config(
            app,
            host=self.config.listen_host,
            port=self.config.rest_port,
            log_level="info",
        )
        self._rest_server = uvicorn.Server(config)
        task = asyncio.create_task(self._rest_server.serve())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _start_grpc(self) -> None:
        """Start the gRPC server."""
        servicer = NodeServiceServicer(
            mempool=self.mempool,
            blockchain=self.block_store,
            utxo_manager=self.utxo_set,
            identity_registry=self.identity_registry,
            params=self.governance.latest(),
        )
        server = create_grpc_server(
            servicer=servicer,
            bind_address=f"{self.config.listen_host}:{self.config.grpc_port}",
        )
        server.start()
        self._grpc_server = server
        print(f"[gRPC] Server started on {self.config.listen_host}:{self.config.grpc_port}")

    # ------------------------------------------------------------------ #
    #  Consensus Loop
    # ------------------------------------------------------------------ #

    async def _consensus_loop(self) -> None:
        """
        Periodic block proposer loop.
        When it's our turn, propose a block, broadcast it, and collect signatures.
        """
        assert self.consensus is not None
        assert self.validator_set is not None

        while self._running and not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.config.block_interval_ms / 1000.0,
                )
                break
            except asyncio.TimeoutError:
                pass

            if not self.consensus.chain_tip:
                continue

            next_height = self.consensus.chain_tip.header.height + 1
            expected = self.validator_set.proposer_for_height(next_height)

            if expected.validator_id == self.config.validator_id:
                try:
                    block = self.consensus.propose_block(
                        validator_id=self.config.validator_id,
                        height=next_height,
                        privkey=self._validator_privkey,
                    )
                    # Validate our own block
                    res = self.consensus.validate_block(block)
                    if not res.valid:
                        print(f"[CONSENSUS] Self-proposed block invalid: {res.reason}")
                        continue

                    # Commit (with our own signature counted)
                    committed = self.consensus.commit_block(block)
                    if committed:
                        # Index transactions
                        self._index_block(block)
                        # Broadcast to peers
                        await self.p2p.broadcast_block(block)
                        print(
                            f"[CONSENSUS] Block committed: height={block.header.height}, "
                            f"txs={len(block.body.transactions)}, hash={block.hash[:16]}..."
                        )
                    else:
                        print(f"[CONSENSUS] Block not finalized (needs more signatures)")
                except PermissionError:
                    pass  # Not our turn
                except Exception as exc:
                    print(f"[CONSENSUS] Block proposal error: {exc}")

    # ------------------------------------------------------------------ #
    #  P2P Handlers
    # ------------------------------------------------------------------ #

    async def _on_p2p_tx(self, msg: Message, peer: Peer) -> None:
        """Handle a new transaction received from a peer."""
        try:
            tx_dict = json.loads(msg.payload)
            tx = Transaction.from_dict(tx_dict)
            await self.submit_transaction(tx)
        except Exception as exc:
            print(f"[P2P] Failed to process received tx: {exc}")

    async def _on_p2p_block(self, msg: Message, peer: Peer) -> None:
        """Handle a new block received from a peer."""
        try:
            block_dict = json.loads(msg.payload)
            block = Block.from_dict(block_dict)
            await self.process_block(block)
        except Exception as exc:
            print(f"[P2P] Failed to process received block: {exc}")

    # ------------------------------------------------------------------ #
    #  Transaction & Block Processing
    # ------------------------------------------------------------------ #

    async def submit_transaction(self, tx: Transaction) -> ValidationResult:
        """
        Receive a transaction, validate it, and add it to the mempool.

        Validation pipeline:
            1. Structural checks (core.validator.TxValidator)
            2. Currency rules (φ/ψ enforcement via CurrencyRulesEngine)
            3. Feasibility check
            4. Mempool admission

        Args:
            tx: The transaction to submit.

        Returns:
            ValidationResult indicating acceptance or rejection reason.
        """
        # 1. Core validation
        tx_validator = TxValidator()
        params = SystemParams(
            block_interval_ms=self.config.block_interval_ms,
            max_tx_per_block=2_000,
            max_block_size=1_048_576,
        )
        core_res = tx_validator.validate(tx, self.utxo_set, self.state_manager, params)
        if not core_res.valid:
            return core_res

        # 2. Currency rules
        if tx.tx_type == TxType.TRANSFER_SALE:
            curr_res = self.currency_engine.validate_sale_transaction(
                tx, self.governance.latest()
            )
            if not curr_res.valid:
                return ValidationResult(False, f"Currency: {curr_res.reason}")

        elif tx.tx_type == TxType.TRANSFER_WAGE:
            curr_res = self.currency_engine.validate_wage_transaction(
                tx, self.governance.latest()
            )
            if not curr_res.valid:
                return ValidationResult(False, f"Currency: {curr_res.reason}")

        elif tx.tx_type == TxType.MINT:
            curr_res = self.currency_engine.validate_mint_transaction(tx)
            if not curr_res.valid:
                return ValidationResult(False, f"Currency: {curr_res.reason}")

        # 3. Feasibility
        if tx.tx_type in (TxType.TRANSFER_SALE, TxType.TRANSFER_WAGE):
            for inp in tx.inputs:
                owner = self._extract_owner_from_input(inp)
                if owner:
                    # The chain only settles N. For sale/wage feasibility we
                    # read the external payment amount from tx.extra. Payment
                    # references are optional metadata.
                    d_amount = self._extract_external_amount_from_extra(tx)
                    account_state = self.state_manager.get_state(owner)
                    result = self.feasibility_engine.check_sale_feasibility(
                        address=owner,
                        proposed_sale_amount_d=d_amount,
                        account_state=account_state,
                        params=self.governance.latest(),
                    )
                    if not result.feasible:
                        return ValidationResult(
                            False,
                            f"Feasibility: shortfall={result.shortfall} "
                            f"remaining_capacity={result.remaining_capacity}",
                        )

        # 4. Mempool
        try:
            self.mempool.add_tx(tx, fee=0)
            # Optionally broadcast to peers (if not already from P2P)
            # await self.p2p.broadcast_tx(tx)
            return ValidationResult(True, "Accepted into mempool")
        except Exception as exc:
            return ValidationResult(False, f"Mempool: {exc}")

    async def process_block(self, block: Block) -> ValidationResult:
        """
        Process a new block received from the network.

        Steps:
            1. Validate block against current chain tip.
            2. Apply to UTXO set and storage.
            3. Update indexes and mempool.
            4. Update N-lifecycle tracker.

        Args:
            block: The candidate block.

        Returns:
            ValidationResult indicating acceptance or rejection.
        """
        if self.consensus is None:
            return ValidationResult(False, "No consensus configured")

        prev = self.consensus.chain_tip
        res = self.consensus.validate_block(block, prev)
        if not res.valid:
            return res

        # Attempt to commit (requires sufficient signatures)
        committed = self.consensus.commit_block(block)
        if committed:
            self._index_block(block)
            print(
                f"[BLOCK] Processed block height={block.header.height}, "
                f"txs={len(block.body.transactions)}"
            )
            return ValidationResult(True, "Block committed")
        else:
            # Block is valid but not yet finalized — track signatures
            return ValidationResult(True, "Block valid, awaiting finality")

    def _index_block(self, block: Block) -> None:
        """Update all secondary indexes after a block is committed."""
        self.block_store.save_block(block)
        for idx, tx in enumerate(block.body.transactions):
            self.index_store.index_transaction(tx, block.header.height, idx)
            # Index outputs as UTXOs
            for out_idx, out in enumerate(tx.outputs):
                utxo = UTXO(
                    tx_hash=tx.hash(),
                    output_index=out_idx,
                    amount=out.amount,
                    lock_script=out.lock_script,
                )
                addr = self._extract_address_from_lock(out.lock_script)
                self.index_store.index_utxo(utxo, address=addr)
            # Mark spent inputs
            for inp in tx.inputs:
                self.index_store.spend_utxo(inp.tx_hash, inp.output_index, spent_by_tx=tx.hash())
        # Update N-lifecycle
        self.n_lifecycle.on_block(block)

    # ------------------------------------------------------------------ #
    #  Offline Batch Processing
    # ------------------------------------------------------------------ #

    async def sync_offline_batch(self, batch: List[Transaction]) -> Dict[str, Any]:
        """
        Process a batch of offline-created transactions.

        Steps:
            1. Detect conflicts with current UTXO set.
            2. Validate each transaction.
            3. Submit valid ones to mempool.
            4. Update offline cache statuses.

        Args:
            batch: List of transactions created while offline.

        Returns:
            Dict with keys: accepted, rejected, conflicts, new_tip_hash.
        """
        accepted: List[str] = []
        rejected: List[Dict[str, str]] = []
        conflicts: List[Dict[str, str]] = []

        for tx in batch:
            tx_hash = tx.hash()

            # Check for UTXO conflicts
            conflict_found = False
            for inp in tx.inputs:
                if not self.utxo_set.get(inp.tx_hash, inp.output_index):
                    conflicts.append({
                        "tx_hash": tx_hash,
                        "reason": f"Input {inp.tx_hash[:16]}...:{inp.output_index} already spent",
                    })
                    conflict_found = True
                    break

            if conflict_found:
                self.tx_cache.update_status(tx_hash, self._tx_status_rejected())
                continue

            # Validate and submit
            res = await self.submit_transaction(tx)
            if res.valid:
                accepted.append(tx_hash)
                self.tx_cache.update_status(tx_hash, self._tx_status_pending())
            else:
                rejected.append({"tx_hash": tx_hash, "reason": res.reason})
                self.tx_cache.update_status(tx_hash, self._tx_status_rejected())

        latest = self.block_store.get_latest_block()
        return {
            "accepted": accepted,
            "rejected": rejected,
            "conflicts": conflicts,
            "new_tip_hash": latest.hash if latest else "0" * 64,
            "synced_blocks": 0,
        }

    def _tx_status_pending(self) -> Any:
        from offline.cache import TxStatus
        return TxStatus.PENDING_NETWORK

    def _tx_status_rejected(self) -> Any:
        from offline.cache import TxStatus
        return TxStatus.REJECTED

    # ------------------------------------------------------------------ #
    #  Status
    # ------------------------------------------------------------------ #

    def get_status(self) -> Dict[str, Any]:
        """
        Return a comprehensive status dictionary for the node.

        Includes: height, peers, mempool size, uptime, validator info,
        governance parameters, identity counts.
        """
        latest = self.block_store.get_latest_block()
        height = latest.header.height if latest else -1
        tip_hash = latest.hash if latest else "0" * 64

        peer_count = len(self.p2p.peer_manager.all_peers())
        mempool_count = self.mempool.size()
        uptime = time.monotonic() - self._start_time if self._start_time else 0.0

        params = self.governance.latest()
        id_counts = self.identity_registry.count_by_status()

        return {
            "version": "0.1.0",
            "network_id": self.config.network_id,
            "running": self._running,
            "height": height,
            "tip_hash": tip_hash,
            "peers": peer_count,
            "mempool_count": mempool_count,
            "uptime_seconds": round(uptime, 3),
            "validator_id": self.config.validator_id,
            "validator_name": self.config.validator_name,
            "is_validator": self.consensus is not None,
            "governance": {
                "phi": f"{params.phi_numerator}/{params.phi_denominator}",
                "psi": f"{params.psi_numerator}/{params.psi_denominator}",
                "required_gov_signatures": params.required_gov_signatures,
                "n_lower_bound": self.config.n_lower_bound,
                "n_upper_bound": self.config.n_upper_bound,
            },
            "identity_counts": id_counts,
            "rest_port": self.config.rest_port if self.config.enable_rest else None,
            "grpc_port": self.config.grpc_port if self.config.enable_grpc else None,
            "p2p_port": self.config.p2p_port,
        }

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_owner_from_input(inp: TxInput) -> str:
        """Extract a pseudo-address from a TxInput for feasibility checks."""
        unlock = inp.unlock_script
        if len(unlock) >= 25 and unlock[:3] == b"\x76\xa9\x14" and unlock[-2:] == b"\x88\xac":
            return unlock[3:23].hex()
        return unlock.hex()[:40] if unlock else ""

    @staticmethod
    def _extract_address_from_lock(lock_script: bytes) -> str:
        """Extract address from a lock_script."""
        if len(lock_script) == 25 and lock_script[:3] == b"\x76\xa9\x14" and lock_script[-2:] == b"\x88\xac":
            return lock_script[3:23].hex()
        return lock_script.hex()[:40] if lock_script else ""

    @staticmethod
    def _extract_external_amount_from_extra(tx: Transaction) -> int:
        """
        Extract the external payment amount used to calculate N obligations.

        Preferred MVP metadata is JSON with `external_amount`; `d_amount` is
        retained as a backward-compatible alias.  The binary fallback matches
        the older simplified sale/wage extra encoding.
        """
        extra = getattr(tx, "extra", b"") or b""
        if not extra:
            return 0
        try:
            data = json.loads(extra.decode("utf-8"))
            if isinstance(data, dict):
                return int(data.get("external_amount", data.get("d_amount", 0)) or 0)
        except Exception:
            pass

        try:
            party_len = extra[0]
            return int.from_bytes(extra[1 + party_len : 1 + party_len + 8], "big")
        except Exception:
            return 0

    # ------------------------------------------------------------------ #
    #  Governance operations
    # ------------------------------------------------------------------ #

    def update_governance_params(
        self,
        new_params: SystemParameters,
        at_height: int,
        reason: str = "",
    ) -> None:
        """Record a governance parameter change."""
        self.governance.update(new_params, at_height=at_height, reason=reason)
        self._app_state.params = new_params

    def register_identity(
        self,
        did_document: Any,
        vc: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Register a new identity in the registry."""
        return self.identity_registry.register(did_document, vc, metadata)

    def verify_identity(
        self,
        did: str,
        gov_signature: str,
        auth_height: int = 0,
    ) -> Any:
        """Governance verification to activate a PENDING identity."""
        return self.identity_registry.verify_and_activate(did, gov_signature, auth_height)


# --------------------------------------------------------------------------- #
#  Standalone entry point
# --------------------------------------------------------------------------- #

async def main() -> None:
    """CLI entry point: ``python -m bcs_chain.node <config_path>``."""
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    node = BCSNode(config_path)
    await node.start()

    # Wait until shutdown signal
    try:
        while node._running:
            await asyncio.sleep(1.0)
    except asyncio.CancelledError:
        pass
    finally:
        await node.stop()


if __name__ == "__main__":
    asyncio.run(main())
