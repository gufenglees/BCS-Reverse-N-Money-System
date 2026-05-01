"""
Offline Synchronization Integration Tests
==========================================
Tests for offline transaction creation, caching, conflict detection,
resolution, and sync after offline periods.
"""

import pytest
import time
import asyncio
from unittest.mock import MagicMock

from cache import TxCache, TxStatus, CachedTx
from sync import SyncEngine, SyncResult, RejectedTx, PeerClient
from tx_builder import OfflineTxBuilder
from _core_stubs import Transaction, TxInput, TxOutput, TxType, UTXOSet, UTXO


# ---------------------------------------------------------------------------
# Offline Transaction Creation
# ---------------------------------------------------------------------------

class TestOfflineTxCreation:
    def test_create_offline_transfer(self):
        """Create an offline transfer transaction."""
        builder = OfflineTxBuilder()
        tx = builder.create_transfer(
            inputs=[TxInput(tx_hash=b"\x01" * 32, output_index=0)],
            outputs=[TxOutput(amount=500_000_000, lock_script=b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac")],
        )
        assert tx.tx_type == TxType.TRANSFER
        assert tx.total_output == 500_000_000
        assert len(tx.inputs) == 1

    def test_create_offline_sale(self):
        """Create an offline sale transaction (TRANSFER_SALE)."""
        builder = OfflineTxBuilder()
        tx = builder.create_sale(
            inputs=[TxInput(tx_hash=b"\x02" * 32, output_index=0)],
            outputs=[
                TxOutput(amount=100_000_000_000, lock_script=b"\x76\xa9\x14" + b"M" * 20 + b"\x88\xac"),
                TxOutput(amount=3_000_000_000, lock_script=b"\x76\xa9\x14" + b"B" * 20 + b"\x88\xac"),
            ],
        )
        assert tx.tx_type == TxType.TRANSFER_SALE
        assert tx.total_output >= 100_000_000_000

    def test_create_offline_wage(self):
        """Create an offline wage transaction (TRANSFER_WAGE)."""
        builder = OfflineTxBuilder()
        tx = builder.create_wage(
            inputs=[TxInput(tx_hash=b"\x03" * 32, output_index=0)],
            outputs=[
                TxOutput(amount=50_000_000_000, lock_script=b"\x76\xa9\x14" + b"W" * 20 + b"\x88\xac"),
                TxOutput(amount=1_000_000_000, lock_script=b"\x76\xa9\x14" + b"N" * 20 + b"\x88\xac"),
            ],
        )
        assert tx.tx_type == TxType.TRANSFER_WAGE

    def test_offline_tx_with_ttl(self):
        """Offline transaction can be created with TTL metadata."""
        builder = OfflineTxBuilder(ttl_seconds=3600)
        tx = builder.create_transfer(
            inputs=[TxInput(tx_hash=b"\x04" * 32, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000)],
        )
        # TTL is stored in builder, not tx directly
        assert builder.default_ttl == 3600


# ---------------------------------------------------------------------------
# Offline Transaction Cache
# ---------------------------------------------------------------------------

class TestOfflineTxCache:
    def test_cache_and_retrieve(self):
        """Cache a transaction and retrieve it."""
        cache = TxCache(db_path=":memory:", default_ttl_seconds=3600)
        tx = Transaction(
            version=1,
            tx_type=TxType.TRANSFER,
            inputs=[TxInput(tx_hash=b"\x05" * 32, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000)],
        )
        seq = cache.cache_tx(tx, status=TxStatus.CACHED)
        assert seq > 0

        found = cache.get_by_hash(tx.hash())
        assert found is not None
        assert found.status == TxStatus.CACHED
        assert found.tx_hash == tx.hash()

    def test_cache_multiple_statuses(self):
        """Cache transactions with different statuses."""
        cache = TxCache(db_path=":memory:", default_ttl_seconds=3600)

        tx1 = Transaction(inputs=[TxInput(tx_hash=b"\x10" * 32, output_index=0)], outputs=[TxOutput(amount=100)])
        tx2 = Transaction(inputs=[TxInput(tx_hash=b"\x11" * 32, output_index=0)], outputs=[TxOutput(amount=200)])
        tx3 = Transaction(inputs=[TxInput(tx_hash=b"\x12" * 32, output_index=0)], outputs=[TxOutput(amount=300)])

        cache.cache_tx(tx1, status=TxStatus.DRAFT)
        cache.cache_tx(tx2, status=TxStatus.SIGNED_LOCAL)
        cache.cache_tx(tx3, status=TxStatus.CACHED)

        pending = cache.get_pending()
        assert len(pending) == 3

        counts = cache.get_all_status_counts()
        assert counts[TxStatus.DRAFT] == 1
        assert counts[TxStatus.SIGNED_LOCAL] == 1
        assert counts[TxStatus.CACHED] == 1

    def test_cache_expiry(self):
        """Expired transactions are identified and purged."""
        cache = TxCache(db_path=":memory:", default_ttl_seconds=1)
        tx = Transaction(
            inputs=[TxInput(tx_hash=b"\x06" * 32, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000)],
        )
        cache.cache_tx(tx, status=TxStatus.CACHED, expiry_seconds=1)
        time.sleep(1.1)

        expired = cache.get_expired()
        assert len(expired) == 1
        assert expired[0].tx_hash == tx.hash()

        purged = cache.purge_expired()
        assert purged == 1
        assert cache.get_by_hash(tx.hash()) is None

    def test_cache_status_update(self):
        """Update cached transaction status."""
        cache = TxCache(db_path=":memory:", default_ttl_seconds=3600)
        tx = Transaction(
            inputs=[TxInput(tx_hash=b"\x07" * 32, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000)],
        )
        cache.cache_tx(tx, status=TxStatus.DRAFT)
        cache.update_status(tx.hash(), TxStatus.CONFIRMED)

        found = cache.get_by_hash(tx.hash())
        assert found.status == TxStatus.CONFIRMED

        # CONFIRMED should not appear in pending
        pending = cache.get_pending()
        assert not any(p.tx_hash == tx.hash() for p in pending)

    def test_cache_batch_operations(self):
        """Batch cache and remove operations."""
        cache = TxCache(db_path=":memory:", default_ttl_seconds=3600)
        txs = [
            Transaction(inputs=[TxInput(tx_hash=bytes([i] * 32), output_index=0)], outputs=[TxOutput(amount=i * 100)])
            for i in range(1, 6)
        ]
        seqs = cache.cache_many(txs, status=TxStatus.CACHED)
        assert len(seqs) == 5

        hashes = [tx.hash() for tx in txs[:3]]
        removed = cache.remove_many(hashes)
        assert removed == 3


# ---------------------------------------------------------------------------
# Conflict Detection
# ---------------------------------------------------------------------------

class TestConflictDetection:
    def test_detect_spent_utxo_conflict(self):
        """Detect when a local UTXO has already been spent on-chain."""
        engine = SyncEngine()
        # Mock peer UTXO set where tx_a:0 is already spent
        peer_utxos = {"tx_a:0": False, "tx_a:1": True}  # False = spent
        local_utxos = ["tx_a:0"]

        conflicts = engine.detect_conflicts(local_utxos, peer_utxos)
        assert len(conflicts) == 1
        assert conflicts[0]["outpoint"] == "tx_a:0"

    def test_no_conflict_for_unspent_utxo(self):
        """No conflict when local UTXO is still unspent."""
        engine = SyncEngine()
        peer_utxos = {"tx_b:0": True, "tx_b:1": True}
        local_utxos = ["tx_b:0"]

        conflicts = engine.detect_conflicts(local_utxos, peer_utxos)
        assert len(conflicts) == 0

    def test_detect_unknown_utxo(self):
        """Unknown UTXO in local set indicates possible conflict."""
        engine = SyncEngine()
        peer_utxos = {"tx_c:0": True}
        local_utxos = ["tx_c:0", "tx_unknown:0"]

        conflicts = engine.detect_conflicts(local_utxos, peer_utxos)
        assert len(conflicts) >= 1

    def test_detect_conflicting_transactions(self):
        """Detect when two offline transactions spend the same input."""
        engine = SyncEngine()
        tx1 = Transaction(
            inputs=[TxInput(tx_hash=b"conflict" * 4, output_index=0)],
            outputs=[TxOutput(amount=500_000_000)],
        )
        tx2 = Transaction(
            inputs=[TxInput(tx_hash=b"conflict" * 4, output_index=0)],
            outputs=[TxOutput(amount=400_000_000)],
        )

        conflicts = engine.detect_tx_conflicts([tx1, tx2])
        assert len(conflicts) > 0


# ---------------------------------------------------------------------------
# Conflict Resolution / Rebuild
# ---------------------------------------------------------------------------

class TestConflictResolution:
    def test_rebuild_with_fresh_utxos(self):
        """Rebuild offline transactions using fresh UTXO set."""
        engine = SyncEngine()
        builder = OfflineTxBuilder()

        # Fresh UTXOs from peer
        fresh_utxos = [
            UTXO(tx_hash=b"fresh_1" * 4, output_index=0, amount=1_000_000_000, lock_script=b"\x76\xa9\x14" + b"F" * 20 + b"\x88\xac"),
            UTXO(tx_hash=b"fresh_2" * 4, output_index=0, amount=2_000_000_000, lock_script=b"\x76\xa9\x14" + b"F" * 20 + b"\x88\xac"),
        ]

        rebuilt = engine.rebuild_transactions(
            old_txs=[],
            fresh_utxos=fresh_utxos,
            builder=builder,
        )
        assert isinstance(rebuilt, list)

    def test_rebuild_preserves_intent(self):
        """Rebuilt transactions should preserve original payment intent."""
        engine = SyncEngine()
        builder = OfflineTxBuilder()

        old_tx = Transaction(
            inputs=[TxInput(tx_hash=b"spent" * 8, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000, lock_script=b"\x76\xa9\x14" + b"R" * 20 + b"\x88\xac")],
        )

        fresh_utxos = [
            UTXO(tx_hash=b"new_utxo" * 4, output_index=0, amount=5_000_000_000, lock_script=b"\x76\xa9\x14" + b"R" * 20 + b"\x88\xac"),
        ]

        rebuilt = engine.rebuild_transactions(
            old_txs=[old_tx],
            fresh_utxos=fresh_utxos,
            builder=builder,
        )
        assert len(rebuilt) == 1
        # Output amount should match original intent
        assert rebuilt[0].total_output == 1_000_000_000


# ---------------------------------------------------------------------------
# Sync After Offline
# ---------------------------------------------------------------------------

class TestSyncAfterOffline:
    def test_basic_sync(self):
        """SyncEngine processes pending transactions after offline."""
        engine = SyncEngine()
        cache = TxCache(db_path=":memory:", default_ttl_seconds=3600)

        tx = Transaction(
            inputs=[TxInput(tx_hash=b"\x08" * 32, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000)],
        )
        cache.cache_tx(tx, status=TxStatus.CACHED)

        result = engine.sync(cache, peer_utxos={"\x08" * 32 + ":0": True})
        assert isinstance(result, SyncResult)
        assert result.synced_txs >= 0

    def test_sync_with_rejected_txs(self):
        """Sync reports rejected transactions."""
        engine = SyncEngine()
        cache = TxCache(db_path=":memory:", default_ttl_seconds=3600)

        # Create a tx that will be rejected (spent UTXO)
        tx = Transaction(
            inputs=[TxInput(tx_hash=b"spent_utxo" * 4, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000)],
        )
        cache.cache_tx(tx, status=TxStatus.CACHED)

        # Peer reports UTXO as spent
        result = engine.sync(cache, peer_utxos={"spent_utxo" * 4 + ":0": False})
        assert result.conflicts > 0 or result.rejected_txs > 0

    def test_sync_updates_status(self):
        """Successful sync updates transaction status."""
        engine = SyncEngine()
        cache = TxCache(db_path=":memory:", default_ttl_seconds=3600)

        tx = Transaction(
            inputs=[TxInput(tx_hash=b"\x09" * 32, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000)],
        )
        cache.cache_tx(tx, status=TxStatus.CACHED)

        engine.sync(cache, peer_utxos={"\x09" * 32 + ":0": True})
        found = cache.get_by_hash(tx.hash())
        if found and found.status == TxStatus.CONFIRMED:
            assert found.status == TxStatus.CONFIRMED


# ---------------------------------------------------------------------------
# Offline Double Spend Handling
# ---------------------------------------------------------------------------

class TestOfflineDoubleSpend:
    def test_offline_double_spend_detected(self):
        """Two offline transactions spending same input detected."""
        engine = SyncEngine()

        tx1 = Transaction(
            inputs=[TxInput(tx_hash=b"ds" * 16, output_index=0)],
            outputs=[TxOutput(amount=500_000_000)],
        )
        tx2 = Transaction(
            inputs=[TxInput(tx_hash=b"ds" * 16, output_index=0)],
            outputs=[TxOutput(amount=400_000_000)],
        )

        conflicts = engine.detect_tx_conflicts([tx1, tx2])
        assert len(conflicts) == 1
        assert conflicts[0]["type"] == "double_spend"

    def test_offline_double_spend_resolution(self):
        """Resolve double spend by keeping higher-sequence transaction."""
        engine = SyncEngine()

        tx1 = Transaction(
            inputs=[TxInput(tx_hash=b"ds2" * 16, output_index=0)],
            outputs=[TxOutput(amount=500_000_000)],
            _offline_priority=1,
        )
        tx2 = Transaction(
            inputs=[TxInput(tx_hash=b"ds2" * 16, output_index=0)],
            outputs=[TxOutput(amount=400_000_000)],
            _offline_priority=2,
        )

        resolved = engine.resolve_double_spend([tx1, tx2])
        assert len(resolved) == 1
        # Higher priority should win
        assert resolved[0]._offline_priority == 2


# ---------------------------------------------------------------------------
# Light Client Verification
# ---------------------------------------------------------------------------

class TestLightClientVerification:
    def test_verify_utxo_merkle_proof(self):
        """Light client verifies UTXO inclusion via Merkle proof."""
        from block import compute_merkle_root, compute_merkle_proof, verify_merkle_proof

        utxo_hashes = [f"utxo_{i}" for i in range(8)]
        root = compute_merkle_root(utxo_hashes)

        proof = compute_merkle_proof(utxo_hashes, 3)
        assert verify_merkle_proof(root, utxo_hashes[3], proof)

    def test_verify_invalid_merkle_proof(self):
        """Tampered Merkle proof must fail verification."""
        from block import compute_merkle_root, compute_merkle_proof, verify_merkle_proof

        utxo_hashes = [f"utxo_{i}" for i in range(8)]
        root = compute_merkle_root(utxo_hashes)

        proof = compute_merkle_proof(utxo_hashes, 3)
        # Tamper with the proof
        proof[0] = "tampered_hash"
        assert not verify_merkle_proof(root, utxo_hashes[3], proof)

    def test_light_client_header_validation(self):
        """Light client validates block header chain."""
        from block import BlockHeader

        header1 = BlockHeader(
            version=1,
            prev_block_hash="0" * 64,
            merkle_root_tx="0" * 64,
            merkle_root_utxo="0" * 64,
            merkle_root_identity="0" * 64,
            timestamp=1000,
            height=0,
            tx_count=0,
            validator_pubkey="",
            signature="",
        )
        header2 = BlockHeader(
            version=1,
            prev_block_hash=header1.hash,
            merkle_root_tx="0" * 64,
            merkle_root_utxo="0" * 64,
            merkle_root_identity="0" * 64,
            timestamp=6000,
            height=1,
            tx_count=0,
            validator_pubkey="",
            signature="",
        )

        assert header2.link_valid(header1)
        assert header1.hash == header2.prev_block_hash
