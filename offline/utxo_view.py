"""
utxo_view.py — Local Optimistic UTXO View
==========================================
Maintains an optimistic, in-memory replica of the spendable UTXO set.

Key features:
  • apply_local_tx()   — optimistically spend inputs / create outputs
  • revert_on_conflict() — roll back a specific local tx
  • sync_with_chain()  — reconcile with canonical chain UTXO set
  • get_spendable_utxos() / get_balance() — wallet-facing queries
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

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
from _core_stubs import Transaction, TxInput, TxOutput, UTXO, UTXOSet

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class UTXOViewError(Exception):
    pass

class UTXONotFoundError(UTXOViewError):
    pass

class DoubleSpendError(UTXOViewError):
    pass


# ---------------------------------------------------------------------------
# UTXOSyncView
# ---------------------------------------------------------------------------
class UTXOSyncView:
    """
    Optimistic local UTXO view.

    Internally stores three layers:
      1. _chain_utxos   — last known canonical UTXO set (from chain sync)
      2. _local_spent   — UTXOs spent by local (offline) transactions
      3. _local_created — UTXOs created by local transactions

    The effective view = (_chain_utxos ∪ _local_created) \\ _local_spent.
    """

    def __init__(self, initial_chain_utxos: Optional[UTXOSet] = None) -> None:
        self._chain_utxos: UTXOSet = initial_chain_utxos or UTXOSet()
        # local_spent keys map to the tx_hash that spent them (for revert)
        self._local_spent: Dict[Tuple[bytes, int], bytes] = {}
        self._local_created: Dict[Tuple[bytes, int], UTXO] = {}
        self._applied_local_txs: Dict[bytes, Transaction] = {}
        logger.info("UTXOSyncView initialised with %s chain UTXOs", len(self._chain_utxos.all()))

    # ------------------------------------------------------------------
    # Optimistic local application
    # ------------------------------------------------------------------
    def apply_local_tx(self, tx: Transaction) -> None:
        """
        Optimistically apply *tx* to the local view.

        Marks all inputs as locally spent and registers newly created outputs
        in the optimistic layer.

        Raises:
            DoubleSpendError:  if any input is already spent (locally or on chain).
            UTXONotFoundError: if an input references a UTXO we don't know about.
        """
        tx_hash = tx.hash()

        # --- validation ---
        for inp in tx.inputs:
            key = (inp.tx_hash, inp.output_index)
            if key in self._local_spent:
                other_tx = self._local_spent[key].hex()[:16]
                raise DoubleSpendError(
                    f"Input {key} already locally spent by tx {other_tx}"
                )
            if not self._utxo_exists(key):
                raise UTXONotFoundError(
                    f"Input {key} not found in local or chain view"
                )

        # --- apply ---
        for inp in tx.inputs:
            key = (inp.tx_hash, inp.output_index)
            self._local_spent[key] = tx_hash

        for idx, out in enumerate(tx.outputs):
            utxo = UTXO(
                tx_hash=tx_hash,
                output_index=idx,
                amount=out.amount,
                lock_script=out.lock_script,
                confirmations=0,
            )
            self._local_created[(tx_hash, idx)] = utxo

        self._applied_local_txs[tx_hash] = tx
        logger.info(
            "Applied local tx %s (spent=%d created=%d)",
            tx_hash.hex()[:16],
            len(tx.inputs),
            len(tx.outputs),
        )

    # ------------------------------------------------------------------
    # Revert a specific local tx
    # ------------------------------------------------------------------
    def revert_on_conflict(self, tx_hash: bytes) -> bool:
        """
        Roll back a previously applied local transaction.

        Restores its inputs to the spendable set and removes its outputs.

        Returns:
            True if the tx was found and reverted.
        """
        tx = self._applied_local_txs.get(tx_hash)
        if tx is None:
            logger.warning("revert_on_conflict: tx %s not in local set", tx_hash.hex()[:16])
            return False

        # un-spend inputs
        for inp in tx.inputs:
            key = (inp.tx_hash, inp.output_index)
            self._local_spent.pop(key, None)

        # remove created outputs
        for idx in range(len(tx.outputs)):
            self._local_created.pop((tx_hash, idx), None)

        del self._applied_local_txs[tx_hash]
        logger.info("Reverted local tx %s", tx_hash.hex()[:16])
        return True

    # ------------------------------------------------------------------
    # Sync with chain
    # ------------------------------------------------------------------
    def sync_with_chain(self, chain_utxo_set: UTXOSet) -> Dict[str, any]:
        """
        Replace the chain layer with the latest canonical UTXO set.

        After replacement we re-apply every local tx on top; any tx whose
        inputs are now missing in the new chain set is automatically
        reverted and reported as a conflict.

        Returns:
            dict with keys:
                "reverted_txs"    : list[bytes]  — hashes of auto-reverted txs
                "still_valid"     : list[bytes]  — hashes that remain valid
                "chain_utxo_count" : int
        """
        self._chain_utxos = chain_utxo_set.copy()
        reverted: List[bytes] = []
        still_valid: List[bytes] = []

        # snapshot current local txs (values only; we'll re-apply sequentially)
        local_txs = list(self._applied_local_txs.values())

        # clear optimistic layers
        self._local_spent.clear()
        self._local_created.clear()
        self._applied_local_txs.clear()

        # re-apply
        for tx in local_txs:
            tx_hash = tx.hash()
            try:
                self.apply_local_tx(tx)
                still_valid.append(tx_hash)
            except (DoubleSpendError, UTXONotFoundError) as exc:
                logger.warning(
                    "Auto-reverted tx %s after chain sync: %s",
                    tx_hash.hex()[:16],
                    exc,
                )
                reverted.append(tx_hash)

        logger.info(
            "Chain sync complete: chain_utxos=%s reverted=%s still_valid=%s",
            len(self._chain_utxos.all()),
            len(reverted),
            len(still_valid),
        )
        return {
            "reverted_txs": reverted,
            "still_valid": still_valid,
            "chain_utxo_count": len(self._chain_utxos.all()),
        }

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def get_spendable_utxos(self, address: bytes) -> List[UTXO]:
        """
        Return all UTXOs spendable by *address* in the current (optimistic) view.

        A UTXO is spendable iff:
          1. It exists in chain OR local_created layer.
          2. It has NOT been locally spent.
          3. Its lock_script contains *address*.
        """
        results: List[UTXO] = []
        seen: Set[Tuple[bytes, int]] = set()

        def _add_if_spendable(utxo: UTXO) -> None:
            key = (utxo.tx_hash, utxo.output_index)
            if key in seen:
                return
            if key in self._local_spent:
                return
            if address not in utxo.lock_script:
                return
            seen.add(key)
            results.append(utxo)

        # chain layer
        for utxo in self._chain_utxos.all():
            _add_if_spendable(utxo)

        # local created layer
        for utxo in self._local_created.values():
            _add_if_spendable(utxo)

        return sorted(results, key=lambda u: (u.tx_hash, u.output_index))

    def get_balance(self, address: bytes) -> int:
        """Total spendable balance (nanoN) for *address*."""
        return sum(u.amount for u in self.get_spendable_utxos(address))

    def get_all_spendable(self) -> List[UTXO]:
        """All spendable UTXOs regardless of address (diagnostic)."""
        results: List[UTXO] = []
        seen: Set[Tuple[bytes, int]] = set()
        for utxo in self._chain_utxos.all():
            key = (utxo.tx_hash, utxo.output_index)
            if key not in self._local_spent and key not in seen:
                seen.add(key)
                results.append(utxo)
        for utxo in self._local_created.values():
            key = (utxo.tx_hash, utxo.output_index)
            if key not in self._local_spent and key not in seen:
                seen.add(key)
                results.append(utxo)
        return results

    # ------------------------------------------------------------------
    # State snapshot / diff
    # ------------------------------------------------------------------
    def get_local_diff(self) -> Dict[str, List[UTXO]]:
        """
        Return the delta introduced by local (offline) transactions.
        """
        return {
            "spent": [
                self._resolve_utxo(key)
                for key in self._local_spent
                if self._resolve_utxo(key) is not None
            ],
            "created": list(self._local_created.values()),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _utxo_exists(self, key: Tuple[bytes, int]) -> bool:
        if key in self._local_created:
            return True
        return self._chain_utxos.exists(key[0], key[1])

    def _resolve_utxo(self, key: Tuple[bytes, int]) -> Optional[UTXO]:
        if key in self._local_created:
            return self._local_created[key]
        return self._chain_utxos.get(key[0], key[1])

    def __repr__(self) -> str:
        return (
            f"<UTXOSyncView chain={len(self._chain_utxos.all())} "
            f"local_spent={len(self._local_spent)} "
            f"local_created={len(self._local_created)}>"
        )


# ===========================================================================
# Self-test
# ===========================================================================
def _self_test() -> None:
    print("\n=== utxo_view.py self-test ===")
    from _core_stubs import TxType, TxInput, TxOutput

    addr_a = b"\x00" * 20
    addr_b = b"\x01" * 20

    # --- build a chain UTXO set ---
    chain = UTXOSet()
    utxo1 = UTXO(tx_hash=b"\xaa" * 32, output_index=0, amount=1000, lock_script=addr_a)
    utxo2 = UTXO(tx_hash=b"\xbb" * 32, output_index=0, amount=2000, lock_script=addr_a)
    chain.add(utxo1)
    chain.add(utxo2)

    view = UTXOSyncView(initial_chain_utxos=chain)
    assert view.get_balance(addr_a) == 3000
    print(f"[INIT] balance={view.get_balance(addr_a)}")

    # --- apply local tx: spend utxo1 → send 800 to addr_b, change 100 to addr_a ---
    tx1 = Transaction(
        version=1,
        tx_type=TxType.TRANSFER,
        inputs=[TxInput(tx_hash=utxo1.tx_hash, output_index=utxo1.output_index)],
        outputs=[
            TxOutput(amount=800, lock_script=addr_b),
            TxOutput(amount=100, lock_script=addr_a),
        ],
    )
    view.apply_local_tx(tx1)
    assert view.get_balance(addr_a) == 2100  # 2000 + 100
    assert view.get_balance(addr_b) == 800
    print(f"[APPLY] a={view.get_balance(addr_a)} b={view.get_balance(addr_b)}")

    # --- double spend should fail ---
    tx_double = Transaction(
        version=1,
        tx_type=TxType.TRANSFER,
        inputs=[TxInput(tx_hash=utxo1.tx_hash, output_index=utxo1.output_index)],
        outputs=[TxOutput(amount=500, lock_script=addr_b)],
    )
    try:
        view.apply_local_tx(tx_double)
        assert False, "should raise DoubleSpendError"
    except DoubleSpendError:
        print("[DOUBLE-SPEND] correctly rejected")

    # --- revert tx1 ---
    ok = view.revert_on_conflict(tx1.hash())
    assert ok
    assert view.get_balance(addr_a) == 3000
    assert view.get_balance(addr_b) == 0
    print(f"[REVERT] a={view.get_balance(addr_a)} b={view.get_balance(addr_b)}")

    # --- double spend now succeeds after revert ---
    view.apply_local_tx(tx_double)
    assert view.get_balance(addr_a) == 2000  # utxo2 only
    assert view.get_balance(addr_b) == 500
    print(f"[RETRY] a={view.get_balance(addr_a)} b={view.get_balance(addr_b)}")

    # --- sync with chain: replace chain set (simulate external spend of utxo1) ---
    new_chain = UTXOSet()
    new_chain.add(UTXO(tx_hash=b"\xcc" * 32, output_index=0, amount=5000, lock_script=addr_a))
    # utxo1 & utxo2 are gone (spent by someone else)
    result = view.sync_with_chain(new_chain)
    assert tx_double.hash() in result["reverted_txs"]
    assert view.get_balance(addr_a) == 5000
    print(f"[SYNC] reverted={len(result['reverted_txs'])} still_valid={len(result['still_valid'])}")

    # --- diff ---
    diff = view.get_local_diff()
    assert len(diff["spent"]) == 0  # all reverted
    assert len(diff["created"]) == 0
    print("[DIFF] empty after full revert")

    print("=== utxo_view.py self-test PASSED ===\n")


if __name__ == "__main__":
    _self_test()
