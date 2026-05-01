"""
BCS Balance Tracker — Query Balances, UTXOs & Transaction History
==================================================================
Lightweight balance tracker that synchronizes with a BCS node client,
maintains a local cache of UTXOs, and computes derived account metrics
including N feasibility (max sale capacity).

Architecture reference: architecture_design.md §2.7, §3.4
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from core.utxo import UTXO
from core.state import AccountState, IdentityStatus


# --------------------------------------------------------------------------- #
# Node client interface (abstract — implemented by SDK or REST wrapper)
# --------------------------------------------------------------------------- #

class NodeClientStub:
    """
    Stub interface for a BCS node client.
    Production code would use bcs_sdk.client or REST API.
    """

    def get_utxos(self, address: str) -> list[UTXO]:
        """Return UTXOs for an address."""
        return []

    def get_account_state(self, address: str) -> AccountState:
        """Return derived account state."""
        return AccountState(address=address)

    def get_transaction_history(self, address: str) -> list[dict[str, Any]]:
        """Return confirmed transaction history."""
        return []

    def get_mempool_for_address(self, address: str) -> list[dict[str, Any]]:
        """Return pending mempool transactions affecting this address."""
        return []


# --------------------------------------------------------------------------- #
# BalanceTracker
# --------------------------------------------------------------------------- #

class BalanceTracker:
    """
    Tracks balances, UTXOs, and transaction history for BCS addresses.

    Maintains a local SQLite cache of synced data, and can refresh from
    a remote node client on demand.

    Usage::

        tracker = BalanceTracker("/path/to/balance_cache.db")
        tracker.update_from_node(node_client)

        bal = tracker.get_balance("addr...")
        utxos = tracker.get_utxos("addr...")
    """

    def __init__(self, cache_path: str) -> None:
        """
        Args:
            cache_path: Path to the SQLite cache database.
        """
        self.cache_path = Path(cache_path)
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ------------------------------------------------------------------ #
    # Database
    # ------------------------------------------------------------------ #

    def _ensure_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.cache_path))
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self) -> None:
        conn = self._ensure_connection()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS utxo_cache (
                outpoint TEXT PRIMARY KEY,
                address TEXT NOT NULL,
                tx_hash TEXT NOT NULL,
                output_index INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                lock_script BLOB,
                asset_type INTEGER DEFAULT 0,
                metadata BLOB,
                confirmations INTEGER DEFAULT 0,
                synced_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS balance_cache (
                address TEXT PRIMARY KEY,
                n_balance INTEGER DEFAULT 0,
                n_available INTEGER DEFAULT 0,
                n_locked INTEGER DEFAULT 0,
                n_pending INTEGER DEFAULT 0,
                max_sale_capacity INTEGER DEFAULT 0,
                current_sale_volume INTEGER DEFAULT 0,
                identity_status INTEGER DEFAULT 0,
                last_synced_at INTEGER DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tx_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL,
                tx_hash TEXT NOT NULL,
                tx_type INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                direction TEXT NOT NULL,  -- 'in' | 'out' | 'self'
                fee INTEGER DEFAULT 0,
                block_height INTEGER DEFAULT 0,
                timestamp INTEGER DEFAULT 0,
                extra TEXT,
                UNIQUE(address, tx_hash)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_utxo_addr ON utxo_cache(address)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tx_addr ON tx_history(address)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tx_hash ON tx_history(tx_hash)"
        )
        conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------ #
    # Sync from node
    # ------------------------------------------------------------------ #

    def update_from_node(self, node_client: NodeClientStub, address: Optional[str] = None) -> None:
        """
        Pull latest UTXOs, account state, and history from a node client.

        Args:
            node_client: Connected node client instance.
            address: If given, sync only this address; otherwise sync all
                     addresses present in the local cache.
        """
        addresses = [address] if address else self._all_cached_addresses()
        conn = self._ensure_connection()

        for addr in addresses:
            if not addr:
                continue

            # 1. UTXOs
            utxos = node_client.get_utxos(addr)
            self._replace_utxos(addr, utxos)

            # 2. Account state
            state = node_client.get_account_state(addr)
            self._update_balance_cache(addr, state)

            # 3. Transaction history
            history = node_client.get_transaction_history(addr)
            self._replace_history(addr, history)

            # 4. Mempool (pending)
            pending = node_client.get_mempool_for_address(addr)
            pending_n = sum(
                p.get("amount", 0) for p in pending if p.get("direction") == "out"
            )
            conn.execute(
                """
                UPDATE balance_cache
                SET n_pending = ?, last_synced_at = ?
                WHERE address = ?
                """,
                (pending_n, int(time.time()), addr),
            )

        conn.commit()

    # ------------------------------------------------------------------ #
    # Queries
    # ------------------------------------------------------------------ #

    def get_balance(self, address: str) -> dict[str, int]:
        """
        Return balance summary for an address.

        Returns:
            dict with n_balance, n_available, n_locked, n_pending.
        """
        conn = self._ensure_connection()
        row = conn.execute(
            "SELECT n_balance, n_available, n_locked, n_pending FROM balance_cache WHERE address = ?",
            (address,),
        ).fetchone()
        if row is None:
            return {"n_balance": 0, "n_available": 0, "n_locked": 0, "n_pending": 0}
        return {
            "n_balance": row["n_balance"],
            "n_available": row["n_available"],
            "n_locked": row["n_locked"],
            "n_pending": row["n_pending"],
        }

    def get_utxos(self, address: str) -> list[UTXO]:
        """Return cached UTXOs for an address."""
        conn = self._ensure_connection()
        rows = conn.execute(
            """
            SELECT tx_hash, output_index, amount, lock_script, asset_type,
                   metadata, confirmations
            FROM utxo_cache WHERE address = ? ORDER BY amount ASC
            """,
            (address,),
        ).fetchall()
        return [
            UTXO(
                tx_hash=r["tx_hash"],
                output_index=r["output_index"],
                amount=r["amount"],
                lock_script=r["lock_script"] or b"",
                asset_type=r["asset_type"],
                metadata=r["metadata"] or b"",
                confirmations=r["confirmations"],
            )
            for r in rows
        ]

    def get_max_sale_capacity(self, address: str) -> int:
        """
        Return the maximum D-denominated sale capacity for an address.

        Formula: n_available / φ (as stored by the node in AccountState).
        """
        conn = self._ensure_connection()
        row = conn.execute(
            "SELECT max_sale_capacity FROM balance_cache WHERE address = ?",
            (address,),
        ).fetchone()
        return row["max_sale_capacity"] if row else 0

    def get_transaction_history(
        self, address: str, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        """
        Return paginated transaction history for an address.

        Each record contains: tx_hash, tx_type, amount, direction,
        fee, block_height, timestamp, extra.
        """
        conn = self._ensure_connection()
        rows = conn.execute(
            """
            SELECT tx_hash, tx_type, amount, direction, fee,
                   block_height, timestamp, extra
            FROM tx_history
            WHERE address = ?
            ORDER BY timestamp DESC, block_height DESC
            LIMIT ? OFFSET ?
            """,
            (address, limit, offset),
        ).fetchall()
        return [
            {
                "tx_hash": r["tx_hash"],
                "tx_type": r["tx_type"],
                "amount": r["amount"],
                "direction": r["direction"],
                "fee": r["fee"],
                "block_height": r["block_height"],
                "timestamp": r["timestamp"],
                "extra": json.loads(r["extra"]) if r["extra"] else None,
            }
            for r in rows
        ]

    # ------------------------------------------------------------------ #
    # Local cache updates (usable without a node client)
    # ------------------------------------------------------------------ #

    def add_utxo(self, address: str, utxo: UTXO) -> None:
        """Manually add a UTXO to the local cache (e.g. from offline tx creation)."""
        conn = self._ensure_connection()
        conn.execute(
            """
            INSERT OR REPLACE INTO utxo_cache
            (outpoint, address, tx_hash, output_index, amount, lock_script,
             asset_type, metadata, confirmations, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utxo.outpoint,
                address,
                utxo.tx_hash,
                utxo.output_index,
                utxo.amount,
                utxo.lock_script,
                utxo.asset_type,
                utxo.metadata,
                utxo.confirmations,
                int(time.time()),
            ),
        )
        conn.commit()
        self._recalc_balance(address)

    def remove_utxo(self, outpoint: str) -> None:
        """Remove a spent UTXO from cache."""
        conn = self._ensure_connection()
        row = conn.execute(
            "SELECT address FROM utxo_cache WHERE outpoint = ?", (outpoint,)
        ).fetchone()
        conn.execute("DELETE FROM utxo_cache WHERE outpoint = ?", (outpoint,))
        conn.commit()
        if row:
            self._recalc_balance(row["address"])

    def add_history_entry(self, address: str, entry: dict[str, Any]) -> None:
        """Add a transaction history entry to the cache."""
        conn = self._ensure_connection()
        conn.execute(
            """
            INSERT OR REPLACE INTO tx_history
            (address, tx_hash, tx_type, amount, direction, fee,
             block_height, timestamp, extra)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                address,
                entry["tx_hash"],
                entry.get("tx_type", 0),
                entry.get("amount", 0),
                entry.get("direction", "in"),
                entry.get("fee", 0),
                entry.get("block_height", 0),
                entry.get("timestamp", 0),
                json.dumps(entry.get("extra")) if "extra" in entry else None,
            ),
        )
        conn.commit()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _all_cached_addresses(self) -> list[str]:
        conn = self._ensure_connection()
        rows = conn.execute(
            "SELECT DISTINCT address FROM balance_cache"
        ).fetchall()
        return [r["address"] for r in rows]

    def _replace_utxos(self, address: str, utxos: list[UTXO]) -> None:
        conn = self._ensure_connection()
        conn.execute("DELETE FROM utxo_cache WHERE address = ?", (address,))
        for u in utxos:
            conn.execute(
                """
                INSERT INTO utxo_cache
                (outpoint, address, tx_hash, output_index, amount, lock_script,
                 asset_type, metadata, confirmations, synced_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    u.outpoint,
                    address,
                    u.tx_hash,
                    u.output_index,
                    u.amount,
                    u.lock_script,
                    u.asset_type,
                    u.metadata,
                    u.confirmations,
                    int(time.time()),
                ),
            )

    def _update_balance_cache(self, address: str, state: AccountState) -> None:
        conn = self._ensure_connection()
        conn.execute(
            """
            INSERT INTO balance_cache
            (address, n_balance, n_available, n_locked, max_sale_capacity,
               current_sale_volume, identity_status, last_synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(address) DO UPDATE SET
                n_balance = excluded.n_balance,
                n_available = excluded.n_available,
                n_locked = excluded.n_locked,
                max_sale_capacity = excluded.max_sale_capacity,
                current_sale_volume = excluded.current_sale_volume,
                identity_status = excluded.identity_status,
                last_synced_at = excluded.last_synced_at
            """,
            (
                address,
                state.n_balance,
                state.n_available,
                state.n_locked,
                state.max_sale_capacity,
                state.current_sale_volume,
                int(state.identity_status),
                int(time.time()),
            ),
        )

    def _replace_history(self, address: str, history: list[dict[str, Any]]) -> None:
        conn = self._ensure_connection()
        conn.execute(
            "DELETE FROM tx_history WHERE address = ?", (address,)
        )
        for entry in history:
            conn.execute(
                """
                INSERT INTO tx_history
                (address, tx_hash, tx_type, amount, direction, fee,
                 block_height, timestamp, extra)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    address,
                    entry["tx_hash"],
                    entry.get("tx_type", 0),
                    entry.get("amount", 0),
                    entry.get("direction", "in"),
                    entry.get("fee", 0),
                    entry.get("block_height", 0),
                    entry.get("timestamp", 0),
                    json.dumps(entry.get("extra")) if entry.get("extra") else None,
                ),
            )

    def _recalc_balance(self, address: str) -> None:
        """Recompute balance from cached UTXOs (local-only update)."""
        conn = self._ensure_connection()
        rows = conn.execute(
            "SELECT amount, lock_script, metadata FROM utxo_cache WHERE address = ?",
            (address,),
        ).fetchall()
        total = 0
        locked = 0
        for r in rows:
            total += r["amount"]
            # Simple timelock detection: if metadata starts with non-zero, consider locked
            if r["metadata"] and r["metadata"][0:1] != b"\x00":
                locked += r["amount"]
        available = max(0, total - locked)
        conn.execute(
            """
            INSERT INTO balance_cache
            (address, n_balance, n_available, n_locked, last_synced_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(address) DO UPDATE SET
                n_balance = excluded.n_balance,
                n_available = excluded.n_available,
                n_locked = excluded.n_locked,
                last_synced_at = excluded.last_synced_at
            """,
            (address, total, available, locked, int(time.time())),
        )
        conn.commit()

    # ------------------------------------------------------------------ #
    # Context manager
    # ------------------------------------------------------------------ #

    def __enter__(self) -> "BalanceTracker":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

def _self_test() -> None:
    import os
    import tempfile

    print("=" * 60)
    print("BCS BalanceTracker Self-Test")
    print("=" * 60)

    tmpdir = tempfile.mkdtemp(prefix="bcs_balance_test_")
    cache_path = os.path.join(tmpdir, "balance_cache.db")

    # 1. Init
    tracker = BalanceTracker(cache_path)
    print("[1] BalanceTracker initialized")

    # 2. Simulate node sync
    class MockNode(NodeClientStub):
        def get_utxos(self, address: str) -> list[UTXO]:
            if address == "addrA":
                return [
                    UTXO(tx_hash="a" * 64, output_index=0, amount=1_000_000_000, lock_script=b""),
                    UTXO(tx_hash="b" * 64, output_index=1, amount=500_000_000, lock_script=b""),
                ]
            return []

        def get_account_state(self, address: str) -> AccountState:
            if address == "addrA":
                return AccountState(
                    address=address,
                    n_balance=1_500_000_000,
                    n_available=1_500_000_000,
                    max_sale_capacity=50_000_000_000,
                    identity_status=IdentityStatus.AUTHENTICATED,
                )
            return AccountState(address=address)

        def get_transaction_history(self, address: str) -> list[dict[str, Any]]:
            if address == "addrA":
                return [
                    {
                        "tx_hash": "a" * 64,
                        "tx_type": 0,
                        "amount": 1_000_000_000,
                        "direction": "in",
                        "fee": 0,
                        "block_height": 100,
                        "timestamp": 1_700_000_000,
                    },
                    {
                        "tx_hash": "b" * 64,
                        "tx_type": 0,
                        "amount": 500_000_000,
                        "direction": "in",
                        "fee": 0,
                        "block_height": 200,
                        "timestamp": 1_700_010_000,
                    },
                ]
            return []

    node = MockNode()
    tracker.update_from_node(node, address="addrA")

    # 3. Balance query
    bal = tracker.get_balance("addrA")
    assert bal["n_balance"] == 1_500_000_000
    assert bal["n_available"] == 1_500_000_000
    print(f"[2] Balance synced: {bal}")

    # 4. UTXO query
    utxos = tracker.get_utxos("addrA")
    assert len(utxos) == 2
    assert utxos[0].amount == 500_000_000  # sorted ASC
    print(f"[3] UTXOs: {len(utxos)} entries")

    # 5. Max sale capacity
    cap = tracker.get_max_sale_capacity("addrA")
    assert cap == 50_000_000_000
    print(f"[4] Max sale capacity: {cap}")

    # 6. Transaction history
    hist = tracker.get_transaction_history("addrA")
    assert len(hist) == 2
    assert hist[0]["tx_hash"] == "b" * 64  # most recent first
    print(f"[5] History: {len(hist)} entries")

    # 7. Add UTXO manually
    new_utxo = UTXO(tx_hash="c" * 64, output_index=0, amount=300_000_000, lock_script=b"")
    tracker.add_utxo("addrA", new_utxo)
    utxos2 = tracker.get_utxos("addrA")
    assert len(utxos2) == 3
    print(f"[6] Added UTXO manually, now {len(utxos2)} entries")

    # 8. Remove UTXO
    tracker.remove_utxo(new_utxo.outpoint)
    utxos3 = tracker.get_utxos("addrA")
    assert len(utxos3) == 2
    print(f"[7] Removed UTXO, back to {len(utxos3)} entries")

    # 9. Add history manually
    tracker.add_history_entry(
        "addrA",
        {
            "tx_hash": "d" * 64,
            "tx_type": 1,
            "amount": 200_000_000,
            "direction": "out",
            "fee": 1_000_000,
            "block_height": 300,
            "timestamp": 1_700_020_000,
        },
    )
    hist2 = tracker.get_transaction_history("addrA")
    assert len(hist2) == 3
    print(f"[8] Added history entry, now {len(hist2)} entries")

    tracker.close()
    os.remove(cache_path)
    os.rmdir(tmpdir)

    print("\n" + "=" * 60)
    print("All balance.py self-tests PASSED")
    print("=" * 60)


if __name__ == "__main__":
    _self_test()
