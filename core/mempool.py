"""
BCS Blockchain Core — Transaction Mempool
=========================================
In-memory transaction pool for pending (unconfirmed) transactions.

Features:
  • Fee-priority + FIFO ordering for block selection
  • O(1) lookup by tx hash
  • Duplicate detection
  • Size-bounded selection for block building

All amounts use int (nanoN units).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from transaction import Transaction


# ---------------------------------------------------------------------------
# Mempool entry
# ---------------------------------------------------------------------------

@dataclass(order=True)
class MempoolEntry:
    """
    Wrapper around a Transaction with metadata for ordering.

    Sort key is ``(priority_score, arrival_time)`` where higher priority
    scores sort first.  We negate priority_score for heap-like behavior
    with dataclass ordering.
    """
    # sort_index is used for ordering: higher = better
    sort_index: float = 0.0
    # Non-ordering fields (all need defaults for ordered dataclass)
    tx: Transaction = field(default=None, compare=False)
    arrival_time: float = field(default_factory=time.time, compare=False)
    fee: int = field(default=0, compare=False)
    size_bytes: int = field(default=0, compare=False)


# ---------------------------------------------------------------------------
# Mempool
# ---------------------------------------------------------------------------

class Mempool:
    """
    Memory pool for pending transactions.

    Transactions are indexed by hash for fast lookup and stored in a
    list ordered by fee-priority (higher fee = earlier).

    Usage::

        pool = Mempool()
        pool.add_tx(tx, fee=1000)
        selected = pool.select_transactions(max_count=100)
        pool.remove_tx(tx_hash)
    """

    def __init__(self, max_size: int = 10_000) -> None:
        self._max_size = max_size
        # tx_hash -> MempoolEntry
        self._entries: dict[str, MempoolEntry] = {}
        # Ordered list (highest priority first)
        self._ordered: list[MempoolEntry] = []

    # ------------------------------------------------------------------
    # Add
    # ------------------------------------------------------------------

    def add_tx(
        self,
        tx: Transaction,
        fee: int = 0,
        size_bytes: int = 0,
    ) -> bool:
        """
        Add a transaction to the mempool.

        Args:
            tx: The transaction to add.
            fee: Explicit fee in nanoN (if known).
            size_bytes: Serialized size of the transaction.

        Returns:
            True if added, False if already present or pool full.
        """
        tx_hash = tx.hash()
        if tx_hash in self._entries:
            return False

        if size_bytes == 0:
            # Rough estimate: 200 bytes base + 150 per input + 80 per output
            size_bytes = 200 + len(tx.inputs) * 150 + len(tx.outputs) * 80

        # Priority score: fee per byte, higher is better
        priority = fee / max(size_bytes, 1)
        entry = MempoolEntry(
            sort_index=-priority,  # negate for ascending sort
            tx=tx,
            arrival_time=time.time(),
            fee=fee,
            size_bytes=size_bytes,
        )

        self._entries[tx_hash] = entry
        self._insert_ordered(entry)

        # Evict lowest-priority if over capacity
        if len(self._entries) > self._max_size:
            self._evict_lowest()

        return True

    # ------------------------------------------------------------------
    # Remove
    # ------------------------------------------------------------------

    def remove_tx(self, tx_hash: str) -> Optional[Transaction]:
        """Remove a transaction by its hash and return it (or None)."""
        entry = self._entries.pop(tx_hash, None)
        if entry is None:
            return None
        self._ordered.remove(entry)
        return entry.tx

    def remove_confirmed(self, transactions: list[Transaction]) -> int:
        """Bulk-remove transactions that have been confirmed in a block."""
        removed = 0
        for tx in transactions:
            if self.remove_tx(tx.hash()) is not None:
                removed += 1
        return removed

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_by_hash(self, tx_hash: str) -> Optional[Transaction]:
        """Lookup a transaction by its hash."""
        entry = self._entries.get(tx_hash)
        return entry.tx if entry else None

    def get_pending(self) -> list[Transaction]:
        """Return all pending transactions in priority order."""
        return [e.tx for e in self._ordered]

    def contains(self, tx_hash: str) -> bool:
        return tx_hash in self._entries

    def size(self) -> int:
        return len(self._entries)

    def total_size_bytes(self) -> int:
        return sum(e.size_bytes for e in self._entries.values())

    def get_entry(self, tx_hash: str) -> Optional[MempoolEntry]:
        return self._entries.get(tx_hash)

    # ------------------------------------------------------------------
    # Select for block building
    # ------------------------------------------------------------------

    def select_transactions(
        self,
        max_count: int = 1_000,
        max_size_bytes: int = 1_000_000,
    ) -> list[Transaction]:
        """
        Select transactions for a new block, respecting limits.

        Priority order: highest fee/byte first, then earliest arrival.
        """
        selected: list[Transaction] = []
        total_size = 0
        for entry in self._ordered:
            if len(selected) >= max_count:
                break
            if total_size + entry.size_bytes > max_size_bytes:
                continue
            selected.append(entry.tx)
            total_size += entry.size_bytes
        return selected

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _insert_ordered(self, entry: MempoolEntry) -> None:
        # Insertion sort into ordered list (maintains priority)
        # bisect could be used, but linear is fine for small pools
        inserted = False
        for i, existing in enumerate(self._ordered):
            if entry < existing:
                self._ordered.insert(i, entry)
                inserted = True
                break
        if not inserted:
            self._ordered.append(entry)

    def _evict_lowest(self) -> None:
        """Remove the lowest-priority transaction (last in ordered list)."""
        if not self._ordered:
            return
        lowest = self._ordered.pop()
        self._entries.pop(lowest.tx.hash(), None)

    def clear(self) -> None:
        """Empty the mempool."""
        self._entries.clear()
        self._ordered.clear()

    # ------------------------------------------------------------------
    # Snapshot / stats
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, int | float]:
        """Return mempool statistics."""
        if not self._entries:
            return {
                "count": 0,
                "total_size_bytes": 0,
                "avg_fee": 0,
                "max_fee": 0,
                "min_fee": 0,
            }
        fees = [e.fee for e in self._entries.values()]
        return {
            "count": len(self._entries),
            "total_size_bytes": self.total_size_bytes(),
            "avg_fee": sum(fees) / len(fees),
            "max_fee": max(fees),
            "min_fee": min(fees),
        }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from transaction import TxType, TxInput, TxOutput

    pool = Mempool(max_size=5)

    # 1. Add transactions
    for i in range(5):
        tx = Transaction(
            version=1,
            tx_type=TxType.TRANSFER,
            inputs=[TxInput(tx_hash=f"{'ab'[i%2]}" * 64, output_index=i)],
            outputs=[TxOutput(amount=(i + 1) * 100_000_000)],
        )
        fee = (5 - i) * 1_000_000  # descending fee
        ok = pool.add_tx(tx, fee=fee)
        assert ok
    assert pool.size() == 5
    print("Added 5 txs, pool size:", pool.size())

    # 2. Order by fee (highest first)
    pending = pool.get_pending()
    fees = [pool.get_entry(tx.hash()).fee for tx in pending]
    assert fees == sorted(fees, reverse=True)
    print("Priority order OK:", fees)

    # 3. Lookup
    first_hash = pending[0].hash()
    assert pool.contains(first_hash)
    assert pool.get_by_hash(first_hash) is not None
    print("Lookup OK")

    # 4. Select for block
    selected = pool.select_transactions(max_count=3, max_size_bytes=999_999)
    assert len(selected) == 3
    selected_fees = [pool.get_entry(tx.hash()).fee for tx in selected]
    assert selected_fees == sorted(selected_fees, reverse=True)
    print("Block selection OK:", selected_fees)

    # 5. Eviction on overflow
    tx6 = Transaction(
        inputs=[TxInput(tx_hash="c" * 64, output_index=0)],
        outputs=[TxOutput(amount=100)],
    )
    ok6 = pool.add_tx(tx6, fee=10_000_000)
    assert ok6
    assert pool.size() == 5  # max_size enforced
    # The new tx has very high fee, so the lowest-fee tx was evicted
    print("Eviction OK, size still:", pool.size())

    # 6. Remove confirmed
    removed = pool.remove_confirmed(selected[:2])
    assert removed == 2
    assert pool.size() == 3
    print("Bulk remove OK, size:", pool.size())

    # 7. Stats
    stats = pool.stats()
    assert stats["count"] == 3
    print("Stats:", stats)

    print("mempool.py self-test PASSED")
