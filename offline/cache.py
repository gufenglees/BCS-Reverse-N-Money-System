"""
cache.py — Offline Transaction Cache (SQLite-backed)
=====================================================
Persistent cache for transactions created while offline.

Features:
  • TTL-based expiry (default 24 h)
  • Status machine: DRAFT → SIGNED_LOCAL → CACHED → PENDING_NETWORK → CONFIRMED
  • Sequence numbers for deterministic replay ordering
  • Automatic cleanup of expired records
"""
from __future__ import annotations

import logging
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
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
# Core imports (stubs)
# ---------------------------------------------------------------------------
from _core_stubs import Transaction

# ---------------------------------------------------------------------------
# Status enumeration
# ---------------------------------------------------------------------------
class TxStatus(IntEnum):
    """Offline transaction lifecycle states."""
    DRAFT = 0
    SIGNED_LOCAL = 1
    CACHED = 2
    PENDING_NETWORK = 3
    CONFIRMED = 4
    REJECTED = 5
    CONFLICTED = 6


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class CacheError(Exception):
    """Base cache exception."""
    pass

class TxNotFoundError(CacheError):
    pass


# ---------------------------------------------------------------------------
# CachedTx dataclass (lightweight view)
# ---------------------------------------------------------------------------
@dataclass
class CachedTx:
    tx_hash: bytes
    tx: Transaction
    status: TxStatus
    created_at: int          # unix timestamp (seconds)
    expiry_at: int           # unix timestamp (seconds)
    sequence_number: int


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
SCHEMA_SQL: str = """
CREATE TABLE IF NOT EXISTS offline_txs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_hash         BLOB    NOT NULL UNIQUE,
    tx_data         BLOB    NOT NULL,
    status          INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expiry_at       INTEGER NOT NULL DEFAULT (strftime('%s', 'now') + 86400),
    sequence_number INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_status    ON offline_txs(status);
CREATE INDEX IF NOT EXISTS idx_expiry    ON offline_txs(expiry_at);
CREATE INDEX IF NOT EXISTS idx_sequence  ON offline_txs(sequence_number);
"""

# ---------------------------------------------------------------------------
# TxCache
# ---------------------------------------------------------------------------
class TxCache:
    """
    SQLite-backed cache for offline transactions.

    Thread-safety:  sqlite3 is safe for single-process multi-thread when
    using the same connection (Python 3.7+).  We use a per-thread connection
    model via :py:meth:`_connect` for maximum safety.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        default_ttl_seconds: int = 86400,
    ) -> None:
        """
        Args:
            db_path: SQLite file path.  None → in-memory.
            default_ttl_seconds: default TTL for newly cached txs.
        """
        self.db_path = db_path or ":memory:"
        self.default_ttl = default_ttl_seconds
        self._seq_counter: int = int(time.time())

        # For :memory: databases we must keep a persistent connection
        # because each new connection to ":memory:" creates a fresh empty DB.
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.executescript(SCHEMA_SQL)
            self._mem_conn.commit()

        # initialise schema for file-backed DBs
        if self.db_path != ":memory:":
            self._migrate()
        logger.info("TxCache initialised at %s (default_ttl=%s)", self.db_path, default_ttl_seconds)

    # ------------------------------------------------------------------
    # Connection helper
    # ------------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _migrate(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.commit()

    # ------------------------------------------------------------------
    # Core CRUD
    # ------------------------------------------------------------------
    def cache_tx(
        self,
        tx: Transaction,
        status: TxStatus = TxStatus.CACHED,
        expiry_seconds: Optional[int] = None,
    ) -> int:
        """
        Insert or replace a transaction in the cache.

        Returns:
            The assigned sequence_number.
        """
        expiry_seconds = expiry_seconds or self.default_ttl
        now = int(time.time())
        expiry = now + expiry_seconds
        seq = self._next_sequence()
        tx_hash = tx.hash()
        tx_data = tx.serialize()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO offline_txs
                    (tx_hash, tx_data, status, created_at, expiry_at, sequence_number)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(tx_hash) DO UPDATE SET
                    tx_data=excluded.tx_data,
                    status=excluded.status,
                    expiry_at=excluded.expiry_at,
                    sequence_number=excluded.sequence_number
                """,
                (tx_hash, tx_data, int(status), now, expiry, seq),
            )
            conn.commit()

        logger.info(
            "Cached tx %s status=%s seq=%s expiry=%s",
            tx_hash.hex()[:16],
            status.name,
            seq,
            expiry,
        )
        return seq

    def get_pending(self) -> List[CachedTx]:
        """
        Return all transactions whose status is *not* CONFIRMED or REJECTED,
        ordered by sequence_number ascending.
        """
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT tx_hash, tx_data, status, created_at, expiry_at, sequence_number
                FROM offline_txs
                WHERE status NOT IN (?, ?)
                ORDER BY sequence_number ASC
                """,
                (TxStatus.CONFIRMED, TxStatus.REJECTED),
            )
            rows = cur.fetchall()

        return [_row_to_cached(row) for row in rows]

    def get_by_hash(self, tx_hash: bytes) -> Optional[CachedTx]:
        """Lookup a single transaction by its hash."""
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT tx_hash, tx_data, status, created_at, expiry_at, sequence_number
                FROM offline_txs WHERE tx_hash = ?
                """,
                (tx_hash,),
            )
            row = cur.fetchone()
        return _row_to_cached(row) if row else None

    def remove(self, tx_hash: bytes) -> bool:
        """Delete a transaction from the cache.  Returns True if a row was deleted."""
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM offline_txs WHERE tx_hash = ?", (tx_hash,)
            )
            conn.commit()
            deleted = cur.rowcount > 0
        if deleted:
            logger.info("Removed tx %s from cache", tx_hash.hex()[:16])
        return deleted

    def update_status(self, tx_hash: bytes, status: TxStatus) -> bool:
        """Update the status of a cached transaction."""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE offline_txs SET status = ? WHERE tx_hash = ?",
                (int(status), tx_hash),
            )
            conn.commit()
            updated = cur.rowcount > 0
        if updated:
            logger.info("Updated tx %s → %s", tx_hash.hex()[:16], status.name)
        else:
            logger.warning("update_status: tx %s not found", tx_hash.hex()[:16])
        return updated

    def get_expired(self) -> List[CachedTx]:
        """Return all transactions whose expiry_at is in the past."""
        now = int(time.time())
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT tx_hash, tx_data, status, created_at, expiry_at, sequence_number
                FROM offline_txs
                WHERE expiry_at < ?
                ORDER BY sequence_number ASC
                """,
                (now,),
            )
            rows = cur.fetchall()
        return [_row_to_cached(row) for row in rows]

    def purge_expired(self) -> int:
        """Physically delete expired rows.  Returns number of rows removed."""
        now = int(time.time())
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM offline_txs WHERE expiry_at < ?", (now,)
            )
            conn.commit()
            count = cur.rowcount
        if count:
            logger.info("Purged %s expired transactions", count)
        return count

    def get_all_status_counts(self) -> Dict[TxStatus, int]:
        """Aggregate count per status (useful for diagnostics)."""
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT status, COUNT(*) FROM offline_txs GROUP BY status"
            )
            rows = cur.fetchall()
        return {TxStatus(row["status"]): row[1] for row in rows}

    # ------------------------------------------------------------------
    # Sequence helpers
    # ------------------------------------------------------------------
    def _next_sequence(self) -> int:
        self._seq_counter += 1
        return self._seq_counter

    def max_sequence(self) -> int:
        """Highest sequence_number in the cache (0 if empty)."""
        with self._connect() as conn:
            cur = conn.execute("SELECT COALESCE(MAX(sequence_number), 0) FROM offline_txs")
            row = cur.fetchone()
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Batch helpers
    # ------------------------------------------------------------------
    def cache_many(
        self,
        txs: List[Transaction],
        status: TxStatus = TxStatus.CACHED,
        expiry_seconds: Optional[int] = None,
    ) -> List[int]:
        """Batch insert.  Returns list of sequence numbers."""
        return [self.cache_tx(tx, status, expiry_seconds) for tx in txs]

    def remove_many(self, tx_hashes: List[bytes]) -> int:
        """Batch delete.  Returns total rows removed."""
        with self._connect() as conn:
            placeholders = ",".join("?" * len(tx_hashes))
            cur = conn.execute(
                f"DELETE FROM offline_txs WHERE tx_hash IN ({placeholders})",
                tx_hashes,
            )
            conn.commit()
            return cur.rowcount


# ---------------------------------------------------------------------------
# Row helper
# ---------------------------------------------------------------------------
def _row_to_cached(row: sqlite3.Row) -> CachedTx:
    return CachedTx(
        tx_hash=row["tx_hash"],
        tx=Transaction.deserialize(row["tx_data"]),
        status=TxStatus(row["status"]),
        created_at=row["created_at"],
        expiry_at=row["expiry_at"],
        sequence_number=row["sequence_number"],
    )


# ===========================================================================
# Self-test
# ===========================================================================
def _self_test() -> None:
    print("\n=== cache.py self-test ===")
    from _core_stubs import TxInput, TxOutput, TxType

    cache = TxCache(db_path=":memory:", default_ttl_seconds=3600)

    # --- helper to build a dummy tx ---
    def make_tx(val: int) -> Transaction:
        return Transaction(
            version=1,
            tx_type=TxType.TRANSFER,
            inputs=[TxInput(tx_hash=bytes([val] * 32), output_index=0)],
            outputs=[TxOutput(amount=val * 100, lock_script=b"\x00" * 20)],
        )

    tx1 = make_tx(1)
    tx2 = make_tx(2)
    tx3 = make_tx(3)

    # --- cache ---
    seq1 = cache.cache_tx(tx1, status=TxStatus.DRAFT)
    seq2 = cache.cache_tx(tx2, status=TxStatus.SIGNED_LOCAL)
    seq3 = cache.cache_tx(tx3, status=TxStatus.CACHED, expiry_seconds=-1)  # immediate expiry
    print(f"[CACHE] seq1={seq1} seq2={seq2} seq3={seq3}")
    assert seq1 < seq2 < seq3

    # --- get_pending ---
    pending = cache.get_pending()
    assert len(pending) == 3
    print(f"[PENDING] count={len(pending)}")

    # --- get_by_hash ---
    found = cache.get_by_hash(tx2.hash())
    assert found is not None
    assert found.status == TxStatus.SIGNED_LOCAL
    print(f"[GET] found tx2 status={found.status.name}")

    # --- update_status ---
    ok = cache.update_status(tx2.hash(), TxStatus.PENDING_NETWORK)
    assert ok
    updated = cache.get_by_hash(tx2.hash())
    assert updated is not None and updated.status == TxStatus.PENDING_NETWORK
    print(f"[UPDATE] tx2 → {updated.status.name}")

    # --- expiry ---
    expired = cache.get_expired()
    assert len(expired) == 1
    assert expired[0].tx_hash == tx3.hash()
    print(f"[EXPIRED] count={len(expired)} (tx3)")

    # --- purge ---
    purged = cache.purge_expired()
    assert purged == 1
    assert cache.get_by_hash(tx3.hash()) is None
    print(f"[PURGE] removed={purged}")

    # --- remove ---
    removed = cache.remove(tx1.hash())
    assert removed
    assert cache.get_by_hash(tx1.hash()) is None
    print(f"[REMOVE] tx1 removed={removed}")

    # --- status counts ---
    counts = cache.get_all_status_counts()
    print(f"[COUNTS] {counts}")
    assert counts.get(TxStatus.PENDING_NETWORK, 0) == 1

    print("=== cache.py self-test PASSED ===\n")


if __name__ == "__main__":
    _self_test()
