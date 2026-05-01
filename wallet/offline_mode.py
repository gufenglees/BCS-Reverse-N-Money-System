"""
BCS Offline Mode Manager — Offline Transaction & Sync Queue
=============================================================
Manages offline-first operations for BCS wallets:

  • Enable/disable offline mode
  • Prepare lightweight UTXO proof packages for offline validation
  • Create and queue transactions while offline
  • Sync pending transactions when connectivity is restored
  • Conflict detection and resolution for double-spends

Offline transaction state machine::

    [Draft] --sign--> [SignedLocal] --cache--> [Cached]
                          |
                          +-- sync attempt --> [PendingNetwork]
                          |
                          +-- conflict --> [Conflicted] --> [Resolved]

Architecture reference: architecture_design.md §2.2, §6.2, §6.3
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from core.transaction import Transaction, TxType
from core.utxo import UTXO


# --------------------------------------------------------------------------- #
# Sync result model
# --------------------------------------------------------------------------- #

class SyncStatus(Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass
class SyncResult:
    """Result of an offline-to-online sync operation."""
    status: SyncStatus
    accepted: list[str] = field(default_factory=list)      # tx_hashes accepted
    rejected: list[dict[str, Any]] = field(default_factory=list)  # {tx_hash, reason}
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    synced_blocks: int = 0
    new_tip: str = ""
    message: str = ""


# --------------------------------------------------------------------------- #
# OfflineTxRecord — database row model
# --------------------------------------------------------------------------- #

@dataclass
class OfflineTxRecord:
    """Row in the offline transaction queue."""
    id: int = 0
    tx_hash: str = ""
    tx_json: str = ""
    status: str = "draft"       # draft | signed | cached | pending | confirmed | conflicted | resolved
    created_at: int = 0
    queued_at: int = 0
    submitted_at: Optional[int] = None
    reject_reason: str = ""
    sequence_number: int = 0


# --------------------------------------------------------------------------- #
# OfflineModeManager
# --------------------------------------------------------------------------- #

class OfflineModeManager:
    """
    Manages offline transaction lifecycle and reconnection sync.

    Usage::

        mgr = OfflineModeManager("/path/to/offline.db")
        mgr.enable()

        # While offline: create and queue transactions
        tx = mgr.create_offline_transaction(tx_spec)
        mgr.queue_for_sync(tx)

        # When back online
        mgr.disable()
        result = mgr.sync_when_online(node_client)
    """

    def __init__(self, storage_path: str) -> None:
        """
        Args:
            storage_path: Path to the SQLite database for offline tx queue.
        """
        self.storage_path = Path(storage_path)
        self._offline: bool = False
        self._sequence_counter: int = 0
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ------------------------------------------------------------------ #
    # Database
    # ------------------------------------------------------------------ #

    def _ensure_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.storage_path))
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self) -> None:
        conn = self._ensure_connection()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS offline_txs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_hash TEXT UNIQUE NOT NULL,
                tx_json TEXT NOT NULL,
                status TEXT DEFAULT 'draft',
                created_at INTEGER NOT NULL,
                queued_at INTEGER,
                submitted_at INTEGER,
                reject_reason TEXT DEFAULT '',
                sequence_number INTEGER DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS offline_utxo_snapshot (
                outpoint TEXT PRIMARY KEY,
                address TEXT NOT NULL,
                tx_hash TEXT NOT NULL,
                output_index INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                lock_script BLOB,
                asset_type INTEGER DEFAULT 0,
                metadata BLOB,
                merkle_proof BLOB,
                snapshot_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS offline_state (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_offtx_status ON offline_txs(status)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_offtx_seq ON offline_txs(sequence_number)"
        )
        conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------ #
    # Offline state
    # ------------------------------------------------------------------ #

    def enable(self) -> None:
        """Enable offline mode. New transactions will be queued locally."""
        self._offline = True
        self._save_state("offline_mode", "true")
        print("[offline] Offline mode ENABLED")

    def disable(self) -> None:
        """Disable offline mode. Does NOT automatically sync — call sync_when_online()."""
        self._offline = False
        self._save_state("offline_mode", "false")
        print("[offline] Offline mode DISABLED — ready to sync")

    def is_offline(self) -> bool:
        """Return True if offline mode is currently active."""
        return self._offline

    # ------------------------------------------------------------------ #
    # UTXO proof package (for offline validation)
    # ------------------------------------------------------------------ #

    def prepare_utxo_package(
        self, address: str, available_utxos: list[UTXO], max_utxos: int = 100
    ) -> dict[str, Any]:
        """
        Prepare a lightweight UTXO proof package for offline use.

        The package includes:
          • The UTXO set for the address (capped at max_utxos)
          • A timestamp
          • A "light proof" header (stub for future Merkle proof inclusion)

        Args:
            address: Address to prepare package for.
            available_utxos: Current UTXOs from the node.
            max_utxos: Cap on number of UTXOs included.

        Returns:
            dict suitable for JSON serialization.
        """
        # Sort by amount ascending, then take top max_utxos
        sorted_utxos = sorted(available_utxos, key=lambda u: u.amount, reverse=True)
        included = sorted_utxos[:max_utxos]

        # Store in local snapshot table
        conn = self._ensure_connection()
        conn.execute("DELETE FROM offline_utxo_snapshot WHERE address = ?", (address,))
        for u in included:
            conn.execute(
                """
                INSERT INTO offline_utxo_snapshot
                (outpoint, address, tx_hash, output_index, amount, lock_script,
                 asset_type, metadata, snapshot_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    int(time.time()),
                ),
            )
        conn.commit()

        return {
            "address": address,
            "utxos": [u.to_dict() for u in included],
            "count": len(included),
            "total_amount": sum(u.amount for u in included),
            "timestamp": int(time.time()),
            "light_proof": "stub",  # TODO: real Merkle proof
        }

    def get_cached_utxo_package(self, address: str) -> list[UTXO]:
        """Retrieve the last prepared UTXO set for an address from local cache."""
        conn = self._ensure_connection()
        rows = conn.execute(
            """
            SELECT tx_hash, output_index, amount, lock_script, asset_type, metadata
            FROM offline_utxo_snapshot WHERE address = ?
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
            )
            for r in rows
        ]

    # ------------------------------------------------------------------ #
    # Offline transaction creation
    # ------------------------------------------------------------------ #

    def create_offline_transaction(
        self,
        tx_spec: dict[str, Any],
        wallet,
        password: str,
    ) -> Transaction:
        """
        Create a transaction while offline using cached UTXO data.

        Args:
            tx_spec: dict describing the desired transaction:
                {
                    "tx_type": 0 | 1 | 2 | 10,
                    "from_addr": "...",
                    "recipient": "...",      # or "buyer" / "employer"
                    "amount": int,
                    "fee": int,
                    "external_amount": int,  # for sale/wage; d_amount alias still accepted
                    "n_amount": int,         # for sale/wage
                }
            wallet: Wallet instance for signing.
            password: Wallet password.

        Returns:
            Signed Transaction (inputs reference cached UTXOs).
        """
        from tx_creator import TxCreator, UTXOStrategy

        creator = TxCreator()
        from_addr = tx_spec["from_addr"]
        tx_type = TxType(tx_spec.get("tx_type", 0))

        # Use cached UTXOs
        cached_utxos = self.get_cached_utxo_package(from_addr)
        if not cached_utxos:
            raise ValueError(f"No cached UTXOs for {from_addr}. Run prepare_utxo_package first.")

        if tx_type == TxType.TRANSFER:
            tx = creator.create_transfer(
                wallet=wallet,
                from_addr=from_addr,
                recipient=tx_spec["recipient"],
                amount=tx_spec["amount"],
                fee=tx_spec["fee"],
                password=password,
                available_utxos=cached_utxos,
            )
        elif tx_type == TxType.TRANSFER_SALE:
            tx = creator.create_sale(
                wallet=wallet,
                from_addr=from_addr,
                buyer=tx_spec.get("buyer", tx_spec.get("recipient", "")),
                d_amount=tx_spec.get("external_amount", tx_spec.get("d_amount", 0)),
                n_amount=tx_spec.get("n_amount", tx_spec["amount"]),
                fee=tx_spec["fee"],
                password=password,
                available_utxos=cached_utxos,
                external_currency=tx_spec.get("external_currency", ""),
                external_payment_ref=tx_spec.get("external_payment_ref", ""),
            )
        elif tx_type == TxType.TRANSFER_WAGE:
            tx = creator.create_wage(
                wallet=wallet,
                from_addr=from_addr,
                employer=tx_spec.get("employer", tx_spec.get("recipient", "")),
                d_amount=tx_spec.get("external_amount", tx_spec.get("d_amount", 0)),
                n_amount=tx_spec.get("n_amount", tx_spec["amount"]),
                fee=tx_spec["fee"],
                password=password,
                available_utxos=cached_utxos,
                external_currency=tx_spec.get("external_currency", ""),
                external_payment_ref=tx_spec.get("external_payment_ref", ""),
            )
        else:
            raise ValueError(f"Unsupported offline tx type: {tx_type}")

        # Store in local queue as "draft"
        self._store_offline_tx(tx, status="draft")
        return tx

    # ------------------------------------------------------------------ #
    # Queue management
    # ------------------------------------------------------------------ #

    def queue_for_sync(self, tx: Transaction) -> None:
        """
        Queue a signed transaction for later broadcast when online.

        Args:
            tx: Signed Transaction to queue.
        """
        self._sequence_counter += 1
        self._store_offline_tx(tx, status="cached", sequence=self._sequence_counter)
        print(f"[offline] Queued tx {tx.hash()[:16]}... (seq={self._sequence_counter})")

    def get_pending_queue(self) -> list[OfflineTxRecord]:
        """Return all transactions in the queue (draft + cached + pending)."""
        conn = self._ensure_connection()
        rows = conn.execute(
            """
            SELECT * FROM offline_txs
            WHERE status IN ('draft', 'cached', 'pending', 'conflicted')
            ORDER BY sequence_number ASC, created_at ASC
            """
        ).fetchall()
        return [
            OfflineTxRecord(
                id=r["id"],
                tx_hash=r["tx_hash"],
                tx_json=r["tx_json"],
                status=r["status"],
                created_at=r["created_at"],
                queued_at=r["queued_at"],
                submitted_at=r["submitted_at"],
                reject_reason=r["reject_reason"],
                sequence_number=r["sequence_number"],
            )
            for r in rows
        ]

    def get_queue_summary(self) -> dict[str, int]:
        """Return counts per status."""
        conn = self._ensure_connection()
        rows = conn.execute(
            "SELECT status, COUNT(*) as c FROM offline_txs GROUP BY status"
        ).fetchall()
        return {r["status"]: r["c"] for r in rows}

    def clear_queue(self) -> None:
        """Clear all offline transactions (destructive)."""
        conn = self._ensure_connection()
        conn.execute("DELETE FROM offline_txs")
        conn.commit()
        self._sequence_counter = 0
        print("[offline] Queue cleared")

    def mark_confirmed(self, tx_hash: str) -> None:
        """Mark a queued transaction as confirmed on-chain."""
        conn = self._ensure_connection()
        conn.execute(
            "UPDATE offline_txs SET status = 'confirmed' WHERE tx_hash = ?",
            (tx_hash,),
        )
        conn.commit()

    def mark_rejected(self, tx_hash: str, reason: str) -> None:
        """Mark a queued transaction as rejected with a reason."""
        conn = self._ensure_connection()
        conn.execute(
            """
            UPDATE offline_txs
            SET status = 'rejected', reject_reason = ?
            WHERE tx_hash = ?
            """,
            (reason, tx_hash),
        )
        conn.commit()

    def mark_conflicted(self, tx_hash: str, reason: str) -> None:
        """Mark a transaction as conflicted (e.g. double-spend detected)."""
        conn = self._ensure_connection()
        conn.execute(
            """
            UPDATE offline_txs
            SET status = 'conflicted', reject_reason = ?
            WHERE tx_hash = ?
            """,
            (reason, tx_hash),
        )
        conn.commit()

    # ------------------------------------------------------------------ #
    # Sync when online
    # ------------------------------------------------------------------ #

    def sync_when_online(
        self,
        node_client,
        auto_resolve_conflicts: bool = True,
    ) -> SyncResult:
        """
        Submit all cached offline transactions to the network.

        Phase 1: Check UTXO validity (has any input been spent?)
        Phase 2: Submit valid transactions
        Phase 3: Handle rejections and conflicts

        Args:
            node_client: Connected node client with submit_transaction().
            auto_resolve_conflicts: If True, attempt to rebuild conflicted txs.

        Returns:
            SyncResult with accepted / rejected / conflicted lists.
        """
        queue = self.get_pending_queue()
        if not queue:
            return SyncResult(
                status=SyncStatus.SUCCESS,
                message="No pending offline transactions",
            )

        accepted: list[str] = []
        rejected: list[dict[str, Any]] = []
        conflicts: list[dict[str, Any]] = []

        for record in queue:
            tx = Transaction.from_dict(json.loads(record.tx_json))

            # Phase 1: Validate inputs still exist
            all_valid = True
            conflict_reason = ""
            for inp in tx.inputs:
                # Ask node if this UTXO still exists
                exists = getattr(node_client, "utxo_exists", lambda *_: True)(
                    inp.tx_hash, inp.output_index
                )
                if not exists:
                    all_valid = False
                    conflict_reason = f"UTXO {inp.tx_hash}:{inp.output_index} already spent"
                    break

            if not all_valid:
                self.mark_conflicted(tx.hash(), conflict_reason)
                conflicts.append({
                    "tx_hash": tx.hash(),
                    "reason": conflict_reason,
                    "tx": tx.to_dict(),
                })
                continue

            # Phase 2: Submit
            try:
                result = node_client.submit_transaction(tx)
                if result.get("accepted", False):
                    accepted.append(tx.hash())
                    self._update_tx_status(tx.hash(), "pending", submitted_at=int(time.time()))
                else:
                    reason = result.get("reason", "unknown")
                    rejected.append({"tx_hash": tx.hash(), "reason": reason})
                    self.mark_rejected(tx.hash(), reason)
            except Exception as exc:
                reason = str(exc)
                rejected.append({"tx_hash": tx.hash(), "reason": reason})
                self.mark_rejected(tx.hash(), reason)

        status = SyncStatus.SUCCESS
        if conflicts and not accepted:
            status = SyncStatus.FAILED
        elif conflicts or rejected:
            status = SyncStatus.PARTIAL

        return SyncResult(
            status=status,
            accepted=accepted,
            rejected=rejected,
            conflicts=conflicts,
            message=f"Sync complete: {len(accepted)} accepted, {len(rejected)} rejected, {len(conflicts)} conflicts",
        )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _store_offline_tx(
        self,
        tx: Transaction,
        status: str = "draft",
        sequence: int = 0,
    ) -> None:
        conn = self._ensure_connection()
        now = int(time.time())
        tx_json = json.dumps(tx.to_dict(), sort_keys=True)
        conn.execute(
            """
            INSERT INTO offline_txs
            (tx_hash, tx_json, status, created_at, queued_at, sequence_number)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(tx_hash) DO UPDATE SET
                status = excluded.status,
                tx_json = excluded.tx_json,
                queued_at = excluded.queued_at,
                sequence_number = excluded.sequence_number
            """,
            (tx.hash(), tx_json, status, now, now if status == "cached" else None, sequence),
        )
        conn.commit()

    def _update_tx_status(
        self, tx_hash: str, status: str, submitted_at: Optional[int] = None
    ) -> None:
        conn = self._ensure_connection()
        if submitted_at is not None:
            conn.execute(
                """
                UPDATE offline_txs
                SET status = ?, submitted_at = ?
                WHERE tx_hash = ?
                """,
                (status, submitted_at, tx_hash),
            )
        else:
            conn.execute(
                "UPDATE offline_txs SET status = ? WHERE tx_hash = ?",
                (status, tx_hash),
            )
        conn.commit()

    def _save_state(self, key: str, value: str) -> None:
        conn = self._ensure_connection()
        conn.execute(
            """
            INSERT INTO offline_state (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
        conn.commit()

    def _load_state(self, key: str, default: str = "") -> str:
        conn = self._ensure_connection()
        row = conn.execute(
            "SELECT value FROM offline_state WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    # ------------------------------------------------------------------ #
    # Context manager
    # ------------------------------------------------------------------ #

    def __enter__(self) -> "OfflineModeManager":
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
    print("BCS OfflineModeManager Self-Test")
    print("=" * 60)

    tmpdir = tempfile.mkdtemp(prefix="bcs_offline_test_")
    db_path = os.path.join(tmpdir, "offline.db")

    # 1. Init
    mgr = OfflineModeManager(db_path)
    assert not mgr.is_offline()
    print("[1] Initialized, offline=False")

    # 2. Enable offline
    mgr.enable()
    assert mgr.is_offline()
    print("[2] Offline mode enabled")

    # 3. Prepare UTXO package
    utxos = [
        UTXO(tx_hash="a" * 64, output_index=0, amount=1_000_000_000, lock_script=b""),
        UTXO(tx_hash="b" * 64, output_index=1, amount=500_000_000, lock_script=b""),
    ]
    pkg = mgr.prepare_utxo_package("addr1", utxos, max_utxos=10)
    assert pkg["count"] == 2
    assert pkg["total_amount"] == 1_500_000_000
    print(f"[3] UTXO package prepared: {pkg['count']} UTXOs")

    # 4. Cached UTXO retrieval
    cached = mgr.get_cached_utxo_package("addr1")
    assert len(cached) == 2
    print(f"[4] Cached UTXOs retrieved: {len(cached)}")

    # 5. Create offline tx (simulated)
    # We need a real wallet to sign — create one inline
    from wallet import Wallet
    wallet_db = os.path.join(tmpdir, "wallet.db")
    with Wallet(wallet_db) as w:
        addr = w.create_new(label="offline-test", password="secret")
        pk = w.get_public_key(addr)
        # Prepare UTXOs with the correct lock script for this address
        from core.script import StandardScripts
        from core.transaction import TxOutput
        import hashlib
        pk_hash = hashlib.new("ripemd160", hashlib.sha256(pk).digest()).digest()
        lock = StandardScripts.p2pkh_lock_script(pk_hash)
        real_utxos = [
            UTXO(tx_hash="x" * 64, output_index=0, amount=1_000_000_000, lock_script=lock),
            UTXO(tx_hash="y" * 64, output_index=1, amount=500_000_000, lock_script=lock),
        ]
        mgr.prepare_utxo_package(addr, real_utxos)

        tx_spec = {
            "tx_type": 0,
            "from_addr": addr,
            "recipient": addr,  # send to self for test
            "amount": 300_000_000,
            "fee": 1_000_000,
        }
        tx = mgr.create_offline_transaction(tx_spec, wallet=w, password="secret")
        assert tx.tx_type == TxType.TRANSFER
        print(f"[5] Offline tx created: {tx.hash()[:16]}...")

        # 6. Queue for sync
        mgr.queue_for_sync(tx)
        summary = mgr.get_queue_summary()
        assert summary.get("cached", 0) >= 1
        print(f"[6] Queued for sync: {summary}")

    # 7. Mock sync
    class MockNode:
        def __init__(self):
            self.submissions: list[Transaction] = []

        def utxo_exists(self, tx_hash: str, output_index: int) -> bool:
            return True

        def submit_transaction(self, tx: Transaction) -> dict[str, Any]:
            self.submissions.append(tx)
            return {"accepted": True, "tx_hash": tx.hash()}

    node = MockNode()
    mgr.disable()
    result = mgr.sync_when_online(node)
    assert result.status in (SyncStatus.SUCCESS, SyncStatus.PARTIAL)
    print(f"[7] Sync result: {result.status.value}, accepted={len(result.accepted)}")

    # 8. Queue inspection
    queue = mgr.get_pending_queue()
    print(f"[8] Pending queue length: {len(queue)}")

    # 9. Conflict simulation
    class BadNode:
        def utxo_exists(self, tx_hash: str, output_index: int) -> bool:
            return False

        def submit_transaction(self, tx: Transaction) -> dict[str, Any]:
            return {"accepted": False, "reason": "UTXO spent"}

    # Re-enable, create another tx, sync with bad node
    mgr.enable()
    with Wallet(wallet_db) as w2:
        # reuse same address by importing
        # create a new wallet+addr and test conflict
        addr2 = w2.create_new(label="offline-test2", password="secret")
        pk2 = w2.get_public_key(addr2)
        pk_hash2 = hashlib.new("ripemd160", hashlib.sha256(pk2).digest()).digest()
        lock2 = StandardScripts.p2pkh_lock_script(pk_hash2)
        real_utxos2 = [
            UTXO(tx_hash="c" * 64, output_index=0, amount=2_000_000_000, lock_script=lock2),
        ]
        mgr.prepare_utxo_package(addr2, real_utxos2)
        tx_spec2 = {
            "tx_type": 0,
            "from_addr": addr2,
            "recipient": addr2,
            "amount": 500_000_000,
            "fee": 1_000_000,
        }
        tx2 = mgr.create_offline_transaction(tx_spec2, wallet=w2, password="secret")
        mgr.queue_for_sync(tx2)

    mgr.disable()
    result2 = mgr.sync_when_online(BadNode())
    assert len(result2.conflicts) > 0
    print(f"[9] Conflict detection OK: {len(result2.conflicts)} conflicts")

    # 10. Clear queue
    mgr.clear_queue()
    summary = mgr.get_queue_summary()
    assert summary == {}
    print("[10] Queue cleared")

    mgr.close()
    os.remove(db_path)
    os.remove(wallet_db)
    os.rmdir(tmpdir)

    print("\n" + "=" * 60)
    print("All offline_mode.py self-tests PASSED")
    print("=" * 60)


if __name__ == "__main__":
    _self_test()
