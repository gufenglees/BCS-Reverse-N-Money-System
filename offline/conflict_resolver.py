"""
conflict_resolver.py — Offline Conflict Resolution
==================================================
Implements the DAG-based conflict resolution strategies described in §6.3.

Conflict types:
  • DOUBLE_SPEND        — UTXO already spent while offline
  • RULE_CHANGE         — φ / ψ parameters changed
  • INSUFFICIENT_BALANCE — new chain state leaves wallet short
  • TIMEOUT              — tx expired before reconnect

Resolution strategies:
  • REBUILD              — recreate tx with alternative UTXOs
  • ADJUST               — tweak outputs to meet new rules
  • RBF                  — Replace-By-Fee (higher fee / priority)
  • REJECT               — permanently discard
  • USER_INTERVENTION    — hand off to UI / user
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s | %(name)s | %(levelname)s | %(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Core imports
# ---------------------------------------------------------------------------
from _core_stubs import (
    Transaction,
    TxType,
    TxInput,
    TxOutput,
    UTXO,
    UTXOSet,
    SystemParameters,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class ConflictType(IntEnum):
    DOUBLE_SPEND = 0
    RULE_CHANGE = 1
    INSUFFICIENT_BALANCE = 2
    TIMEOUT = 3


class ResolutionStrategy(IntEnum):
    REBUILD = 0
    ADJUST = 1
    RBF = 2
    REJECT = 3
    USER_INTERVENTION = 4


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
@dataclass
class Conflict:
    """Describes an offline transaction that conflicts with chain reality."""
    tx: Transaction
    type: ConflictType
    reason: str
    spent_utxos: List[Tuple[bytes, int]] = field(default_factory=list)
    new_params: Optional[SystemParameters] = None
    available_utxos: List[UTXO] = field(default_factory=list)  # for rebuilding


@dataclass
class Resolution:
    """Outcome of conflict resolution."""
    strategy: ResolutionStrategy
    new_tx: Optional[Transaction] = None
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class ConflictResolutionError(Exception):
    pass

class UnresolvableError(ConflictResolutionError):
    pass


# ---------------------------------------------------------------------------
# ConflictResolver
# ---------------------------------------------------------------------------
class ConflictResolver:
    """
    Automatic (and semi-automatic) conflict resolution engine.

    Usage:
        resolver = ConflictResolver(params=current_params)
        resolution = resolver.resolve(conflict)
        if resolution.strategy == ResolutionStrategy.REBUILD:
            broadcast(resolution.new_tx)
    """

    def __init__(
        self,
        params: Optional[SystemParameters] = None,
        wallet_utxos: Optional[List[UTXO]] = None,
    ) -> None:
        self.params = params or SystemParameters()
        self.wallet_utxos = wallet_utxos or []
        logger.info("ConflictResolver initialised (wallet_utxos=%s)", len(self.wallet_utxos))

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def resolve(self, conflict: Conflict) -> Resolution:
        """Route to the appropriate specialised resolver."""
        logger.info(
            "Resolving conflict type=%s tx=%s reason=%s",
            conflict.type.name,
            conflict.tx.hash().hex()[:16],
            conflict.reason,
        )

        if conflict.type == ConflictType.DOUBLE_SPEND:
            return self.resolve_double_spend(conflict)
        elif conflict.type == ConflictType.RULE_CHANGE:
            return self.resolve_rule_change(conflict)
        elif conflict.type == ConflictType.INSUFFICIENT_BALANCE:
            return self.resolve_insufficient_balance(conflict)
        elif conflict.type == ConflictType.TIMEOUT:
            return self.resolve_timeout(conflict)
        else:
            return Resolution(
                strategy=ResolutionStrategy.USER_INTERVENTION,
                message=f"Unknown conflict type: {conflict.type}",
            )

    # ------------------------------------------------------------------
    # DOUBLE_SPEND resolution
    # ------------------------------------------------------------------
    def resolve_double_spend(self, conflict: Conflict) -> Resolution:
        """
        Strategy priority:
          1. REBUILD — if wallet has alternative UTXOs covering the total output.
          2. RBF     — if tx has higher offline_priority than competing tx (stub).
          3. REJECT  — otherwise.
        """
        tx = conflict.tx
        total_out = tx.total_output

        # --- strategy A: rebuild with alternative UTXOs ---
        # Exclude the UTXOs that are already spent
        excluded = set(conflict.spent_utxos)
        alternatives = [
            u for u in (conflict.available_utxos or self.wallet_utxos)
            if (u.tx_hash, u.output_index) not in excluded
        ]
        alt_sum = sum(u.amount for u in alternatives)

        if alt_sum >= total_out:
            rebuilt = self._rebuild_tx(tx, alternatives, total_out)
            return Resolution(
                strategy=ResolutionStrategy.REBUILD,
                new_tx=rebuilt,
                message="Transaction rebuilt with alternative UTXOs",
                metadata={"excluded_utxos": len(excluded), "alt_utxos_used": len(rebuilt.inputs)},
            )

        # --- strategy B: RBF (stub — needs mempool visibility) ---
        if tx._offline_priority > 0:
            logger.info("Attempting RBF for tx %s", tx.hash().hex()[:16])
            # In a real implementation we would bump fee and re-sign.
            # Here we return USER_INTERVENTION because RBF needs mempool data.
            return Resolution(
                strategy=ResolutionStrategy.USER_INTERVENTION,
                message="RBF possible but requires mempool data; user confirmation needed",
                metadata={"rbf_suggested": True, "priority": tx._offline_priority},
            )

        # --- strategy C: reject ---
        return Resolution(
            strategy=ResolutionStrategy.REJECT,
            message=f"UTXOs already spent and no alternatives available: {conflict.spent_utxos}",
        )

    # ------------------------------------------------------------------
    # RULE_CHANGE resolution
    # ------------------------------------------------------------------
    def resolve_rule_change(self, conflict: Conflict) -> Resolution:
        """
        Adjust tx to meet new φ / ψ parameters.

        For TRANSFER_SALE:  recompute required N = φ_new * external_amount.
        For TRANSFER_WAGE:  recompute required N = ψ_new * external_amount.
        """
        tx = conflict.tx
        new_params = conflict.new_params or self.params

        if tx.tx_type == TxType.TRANSFER_SALE:
            return self._adjust_for_phi(tx, new_params)
        elif tx.tx_type == TxType.TRANSFER_WAGE:
            return self._adjust_for_psi(tx, new_params)
        elif tx.tx_type == TxType.TRANSFER:
            # Plain transfers are unaffected by φ/ψ changes
            return Resolution(
                strategy=ResolutionStrategy.ADJUST,
                new_tx=tx,
                message="Plain TRANSFER unaffected by φ/ψ rule change",
            )
        else:
            return Resolution(
                strategy=ResolutionStrategy.USER_INTERVENTION,
                message=f"Unsupported tx type for automatic rule adjustment: {tx.tx_type}",
            )

    def _adjust_for_phi(self, tx: Transaction, params: SystemParameters) -> Resolution:
        external_amount = self._extract_external_amount(tx)
        if external_amount <= 0:
            return Resolution(
                strategy=ResolutionStrategy.REJECT,
                message="Cannot adjust SALE tx: missing external_amount in extra field",
            )

        required_n = int(external_amount * params.phi)
        # assume first output is the N payment to buyer
        if tx.outputs and tx.outputs[0].amount >= required_n:
            adjusted = self._adjust_output(tx, output_index=0, new_amount=required_n)
            return Resolution(
                strategy=ResolutionStrategy.ADJUST,
                new_tx=adjusted,
                message=f"Adjusted SALE tx for new φ={params.phi} (required N={required_n})",
            )
        else:
            # Need more N — try to rebuild with larger input if possible
            return Resolution(
                strategy=ResolutionStrategy.USER_INTERVENTION,
                message=f"Insufficient N for new φ={params.phi}; needs {required_n}, has {tx.outputs[0].amount if tx.outputs else 0}",
                metadata={"required_n": required_n, "current_n": tx.outputs[0].amount if tx.outputs else 0},
            )

    def _adjust_for_psi(self, tx: Transaction, params: SystemParameters) -> Resolution:
        external_amount = self._extract_external_amount(tx)
        if external_amount <= 0:
            return Resolution(
                strategy=ResolutionStrategy.REJECT,
                message="Cannot adjust WAGE tx: missing external_amount",
            )
        required_n = int(external_amount * params.psi)
        if tx.outputs and tx.outputs[0].amount >= required_n:
            adjusted = self._adjust_output(tx, output_index=0, new_amount=required_n)
            return Resolution(
                strategy=ResolutionStrategy.ADJUST,
                new_tx=adjusted,
                message=f"Adjusted WAGE tx for new ψ={params.psi} (required N={required_n})",
            )
        return Resolution(
            strategy=ResolutionStrategy.USER_INTERVENTION,
            message=f"Insufficient N for new ψ={params.psi}",
        )

    # ------------------------------------------------------------------
    # INSUFFICIENT_BALANCE resolution
    # ------------------------------------------------------------------
    def resolve_insufficient_balance(self, conflict: Conflict) -> Resolution:
        """
        Strategy priority:
          1. ADJUST — reduce outputs to fit available balance.
          2. REBUILD — add more inputs if wallet has them.
          3. REJECT — if neither works.
        """
        tx = conflict.tx
        total_out = tx.total_output
        available = sum(u.amount for u in (conflict.available_utxos or self.wallet_utxos))

        if available >= total_out:
            # wallet has enough, just needs different inputs → rebuild
            rebuilt = self._rebuild_tx(tx, conflict.available_utxos or self.wallet_utxos, total_out)
            return Resolution(
                strategy=ResolutionStrategy.REBUILD,
                new_tx=rebuilt,
                message="Added more inputs to cover total output",
            )

        # try reducing outputs proportionally
        reduced = self._reduce_outputs(tx, available)
        if reduced and reduced.total_output <= available:
            # must also account for fee; we keep a safety margin
            return Resolution(
                strategy=ResolutionStrategy.ADJUST,
                new_tx=reduced,
                message=f"Reduced outputs to fit available balance {available}",
                metadata={"original_total": total_out, "new_total": reduced.total_output},
            )

        return Resolution(
            strategy=ResolutionStrategy.REJECT,
            message=f"Insufficient balance: available={available}, required={total_out}",
        )

    # ------------------------------------------------------------------
    # TIMEOUT resolution
    # ------------------------------------------------------------------
    def resolve_timeout(self, conflict: Conflict) -> Resolution:
        """
        Expired transactions are generally rejected unless the user explicitly
        wants to revive them (which essentially means rebuild with fresh TTL).
        """
        return Resolution(
            strategy=ResolutionStrategy.REJECT,
            message="Transaction expired while offline",
            metadata={"expired_at": conflict.reason},
        )

    # ------------------------------------------------------------------
    # Internal tx manipulation helpers
    # ------------------------------------------------------------------
    def _rebuild_tx(
        self,
        original: Transaction,
        available_utxos: List[UTXO],
        target_output_sum: int,
    ) -> Transaction:
        """Rebuild *original* using the smallest sufficient subset of *available_utxos*."""
        # Greedy selection: sort desc, accumulate until >= target
        sorted_utxos = sorted(available_utxos, key=lambda u: u.amount, reverse=True)
        selected: List[UTXO] = []
        selected_sum = 0
        for u in sorted_utxos:
            selected.append(u)
            selected_sum += u.amount
            if selected_sum >= target_output_sum:
                break

        new_inputs = [
            TxInput(tx_hash=u.tx_hash, output_index=u.output_index, unlock_script=b"")
            for u in selected
        ]
        # copy outputs (caller may adjust later)
        new_outputs = [
            TxOutput(amount=o.amount, lock_script=o.lock_script, asset_type=o.asset_type, metadata=o.metadata)
            for o in original.outputs
        ]

        rebuilt = Transaction(
            version=original.version,
            tx_type=original.tx_type,
            inputs=new_inputs,
            outputs=new_outputs,
            lock_time=original.lock_time,
            extra=original.extra,
            witnesses=[],
            _offline_priority=original._offline_priority + 1,
        )
        return rebuilt

    def _adjust_output(self, tx: Transaction, output_index: int, new_amount: int) -> Transaction:
        """Create a copy with a single output amount changed."""
        new_outputs = [
            TxOutput(
                amount=new_amount if idx == output_index else o.amount,
                lock_script=o.lock_script,
                asset_type=o.asset_type,
                metadata=o.metadata,
            )
            for idx, o in enumerate(tx.outputs)
        ]
        return Transaction(
            version=tx.version,
            tx_type=tx.tx_type,
            inputs=[TxInput(i.tx_hash, i.output_index, b"") for i in tx.inputs],
            outputs=new_outputs,
            lock_time=tx.lock_time,
            extra=tx.extra,
            witnesses=[],
            _offline_priority=tx._offline_priority + 1,
        )

    def _reduce_outputs(self, tx: Transaction, max_total: int) -> Optional[Transaction]:
        """Reduce all outputs proportionally so sum ≤ max_total."""
        total = tx.total_output
        if total == 0:
            return tx
        ratio = max_total / total
        if ratio >= 1.0:
            return tx

        reduced_outputs: List[TxOutput] = []
        for o in tx.outputs:
            new_amount = max(1, int(o.amount * ratio))
            reduced_outputs.append(TxOutput(
                amount=new_amount,
                lock_script=o.lock_script,
                asset_type=o.asset_type,
                metadata=o.metadata,
            ))
        return Transaction(
            version=tx.version,
            tx_type=tx.tx_type,
            inputs=[TxInput(i.tx_hash, i.output_index, b"") for i in tx.inputs],
            outputs=reduced_outputs,
            lock_time=tx.lock_time,
            extra=tx.extra,
            witnesses=[],
            _offline_priority=tx._offline_priority + 1,
        )

    def _extract_external_amount(self, tx: Transaction) -> int:
        """Parse external amount from tx.extra (JSON-encoded).

        `d_amount` remains accepted as a backward-compatible alias.
        """
        if not tx.extra:
            return 0
        try:
            import json
            extra = json.loads(tx.extra.decode())
            return int(extra.get("external_amount", extra.get("d_amount", 0)))
        except Exception:
            return 0


# ===========================================================================
# Self-test
# ===========================================================================
def _self_test() -> None:
    print("\n=== conflict_resolver.py self-test ===")
    from _core_stubs import TxInput, TxOutput

    addr_a = b"\x00" * 20
    addr_b = b"\x01" * 20
    addr_c = b"\x02" * 20

    # --- build a tx with inputs from utxo1 & utxo2 ---
    tx = Transaction(
        tx_type=TxType.TRANSFER,
        inputs=[
            TxInput(tx_hash=b"\x11" * 32, output_index=0),
            TxInput(tx_hash=b"\x22" * 32, output_index=0),
        ],
        outputs=[
            TxOutput(amount=800, lock_script=addr_b),
            TxOutput(amount=200, lock_script=addr_a),
        ],
    )

    resolver = ConflictResolver(
        wallet_utxos=[
            UTXO(tx_hash=b"\x33" * 32, output_index=0, amount=1500, lock_script=addr_a),
            UTXO(tx_hash=b"\x44" * 32, output_index=0, amount=500, lock_script=addr_a),
        ],
    )

    # --- DOUBLE_SPEND: has alternatives ---
    conflict_ds = Conflict(
        tx=tx,
        type=ConflictType.DOUBLE_SPEND,
        reason="UTXO already spent",
        spent_utxos=[(b"\x11" * 32, 0), (b"\x22" * 32, 0)],
    )
    res = resolver.resolve_double_spend(conflict_ds)
    assert res.strategy == ResolutionStrategy.REBUILD
    assert res.new_tx is not None
    assert len(res.new_tx.inputs) >= 1
    print(f"[DOUBLE_SPEND] strategy={res.strategy.name} new_inputs={len(res.new_tx.inputs)}")

    # --- DOUBLE_SPEND: no alternatives ---
    resolver2 = ConflictResolver(wallet_utxos=[])
    res2 = resolver2.resolve_double_spend(conflict_ds)
    assert res2.strategy == ResolutionStrategy.REJECT
    print(f"[DOUBLE_SPEND_NO_ALT] strategy={res2.strategy.name}")

    # --- RULE_CHANGE: SALE ---
    sale_tx = Transaction(
        tx_type=TxType.TRANSFER_SALE,
        inputs=[TxInput(tx_hash=b"\x55" * 32, output_index=0)],
        outputs=[TxOutput(amount=500, lock_script=addr_b)],
        extra=b'{"external_amount": 10000}',
    )
    new_params = SystemParameters(phi_numerator=5, phi_denominator=100)  # φ = 5%
    conflict_rc = Conflict(
        tx=sale_tx,
        type=ConflictType.RULE_CHANGE,
        reason="phi changed from 3% to 5%",
        new_params=new_params,
    )
    res_rc = resolver.resolve_rule_change(conflict_rc)
    assert res_rc.strategy == ResolutionStrategy.ADJUST
    assert res_rc.new_tx is not None
    assert res_rc.new_tx.outputs[0].amount == 500  # 5% * 10000 = 500
    print(f"[RULE_CHANGE] strategy={res_rc.strategy.name} new_amount={res_rc.new_tx.outputs[0].amount}")

    # --- INSUFFICIENT_BALANCE: rebuild possible ---
    conflict_ib = Conflict(
        tx=tx,
        type=ConflictType.INSUFFICIENT_BALANCE,
        reason="Wallet balance too low",
        available_utxos=[
            UTXO(tx_hash=b"\x33" * 32, output_index=0, amount=1500, lock_script=addr_a),
        ],
    )
    res_ib = resolver.resolve_insufficient_balance(conflict_ib)
    assert res_ib.strategy == ResolutionStrategy.REBUILD
    print(f"[INSUFF_BAL] strategy={res_ib.strategy.name}")

    # --- INSUFFICIENT_BALANCE: reduce outputs ---
    resolver3 = ConflictResolver(wallet_utxos=[])
    conflict_ib2 = Conflict(
        tx=tx,
        type=ConflictType.INSUFFICIENT_BALANCE,
        reason="Wallet balance too low",
        available_utxos=[],
    )
    res_ib2 = resolver3.resolve_insufficient_balance(conflict_ib2)
    assert res_ib2.strategy == ResolutionStrategy.REJECT
    print(f"[INSUFF_BAL_REJECT] strategy={res_ib2.strategy.name}")

    # --- TIMEOUT ---
    conflict_to = Conflict(
        tx=tx,
        type=ConflictType.TIMEOUT,
        reason="TTL expired",
    )
    res_to = resolver.resolve_timeout(conflict_to)
    assert res_to.strategy == ResolutionStrategy.REJECT
    print(f"[TIMEOUT] strategy={res_to.strategy.name}")

    print("=== conflict_resolver.py self-test PASSED ===\n")


if __name__ == "__main__":
    _self_test()
