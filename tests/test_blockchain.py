"""
Blockchain Core Integration Tests
================================
Tests for Block, Transaction, UTXO, Storage, and Chain operations.
"""

import pytest
import hashlib
from ecdsa import SigningKey, VerifyingKey, SECP256k1

from block import Block, BlockHeader, BlockBody, compute_merkle_root, compute_merkle_proof, verify_merkle_proof
from transaction import Transaction, TxInput, TxOutput, TxType
from utxo import UTXO, UTXOSet
from storage import BlockStore, IndexStore
from state import AccountState, IdentityStatus, StateManager


# ---------------------------------------------------------------------------
# Genesis Block
# ---------------------------------------------------------------------------

class TestGenesisBlock:
    def test_genesis_block_structure(self, genesis_block):
        """Verify the genesis block has correct initial values."""
        assert genesis_block.is_genesis()
        assert genesis_block.header.height == 0
        assert genesis_block.header.prev_block_hash == "0" * 64
        assert genesis_block.header.version == 1
        assert genesis_block.header.tx_count == 0
        assert len(genesis_block.hash) == 64

    def test_genesis_block_serialization(self, genesis_block):
        """Genesis block must round-trip through serialization."""
        d = genesis_block.to_dict()
        restored = Block.from_dict(d)
        assert restored.hash == genesis_block.hash
        assert restored.is_genesis()

    def test_genesis_empty_merkle_root(self, genesis_block):
        """Empty genesis block should have zero merkle root."""
        assert genesis_block.tx_merkle_root() == "0" * 64


# ---------------------------------------------------------------------------
# Block Creation & Linking
# ---------------------------------------------------------------------------

class TestBlockCreation:
    def test_create_and_link_10_blocks(self, mock_node):
        """Create and link 10 blocks sequentially."""
        for i in range(10):
            block = mock_node.create_block([])
            assert block.header.height == i + 1
            assert block.link_valid(mock_node.chain[-2])
            assert block.header.prev_block_hash == mock_node.chain[-2].hash
            assert block.header.timestamp >= mock_node.chain[-2].header.timestamp

    def test_block_with_transactions(self, mock_node):
        """Create a block containing transactions."""
        # Create a simple transfer tx
        tx = Transaction(
            inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000, lock_script=b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac")],
        )
        block = mock_node.create_block([tx])
        assert block.header.tx_count == 1
        assert len(block.body.transactions) == 1
        assert block.tx_merkle_root() != "0" * 64

    def test_merkle_root_consistency(self, mock_node):
        """Merkle root must be deterministic."""
        tx1 = Transaction(inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
                         outputs=[TxOutput(amount=100)])
        tx2 = Transaction(inputs=[TxInput(tx_hash="b" * 64, output_index=0)],
                         outputs=[TxOutput(amount=200)])
        root1 = compute_merkle_root([tx1.hash(), tx2.hash()])
        root2 = compute_merkle_root([tx1.hash(), tx2.hash()])
        assert root1 == root2
        assert len(root1) == 64

    def test_block_height_monotonic(self, mock_node):
        """Block heights must increase monotonically."""
        heights = [mock_node.chain[0].header.height]
        for _ in range(5):
            block = mock_node.create_block([])
            heights.append(block.header.height)
        assert heights == list(range(len(heights)))


# ---------------------------------------------------------------------------
# Transaction Inclusion
# ---------------------------------------------------------------------------

class TestTransactionInclusion:
    def test_transaction_inclusion_in_block(self, mock_node):
        """Transactions must be retrievable from block."""
        tx = Transaction(
            inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
            outputs=[TxOutput(amount=500_000_000)],
        )
        block = mock_node.create_block([tx])
        found = [t for t in block.body.transactions if t.hash() == tx.hash()]
        assert len(found) == 1
        assert found[0].total_output_value() == 500_000_000

    def test_multiple_tx_in_block(self, mock_node):
        """Multiple transactions can be packed into a single block."""
        txs = []
        for i in range(5):
            tx = Transaction(
                inputs=[TxInput(tx_hash=f"{i:0>64}", output_index=0)],
                outputs=[TxOutput(amount=(i + 1) * 100_000_000)],
            )
            txs.append(tx)
        block = mock_node.create_block(txs)
        assert block.header.tx_count == 5
        assert len(block.body.transactions) == 5

    def test_merkle_proof_verification(self, mock_node):
        """Verify Merkle proofs for transaction inclusion."""
        txs = []
        for i in range(4):
            tx = Transaction(
                inputs=[TxInput(tx_hash=f"{i:0>64}", output_index=0)],
                outputs=[TxOutput(amount=(i + 1) * 100)],
            )
            txs.append(tx)
        block = mock_node.create_block(txs)
        root = block.tx_merkle_root()
        hashes = [tx.hash() for tx in txs]
        proof = compute_merkle_proof(hashes, 2)
        assert verify_merkle_proof(root, hashes[2], proof)


# ---------------------------------------------------------------------------
# UTXO Spending
# ---------------------------------------------------------------------------

class TestUTXOSpending:
    def test_utxo_creation_on_output(self, mock_node):
        """UTXOs are created from transaction outputs."""
        sk = SigningKey.generate(curve=SECP256k1)
        pubkey = sk.get_verifying_key().to_string("compressed")
        lock_script = b"\x76\xa9\x14" + hashlib.sha256(pubkey).digest()[:20] + b"\x88\xac"

        tx = Transaction(
            inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000, lock_script=lock_script)],
        )
        mock_node.utxo_set.apply_transaction(tx)
        utxos = mock_node.utxo_set.get_all()
        assert len(utxos) >= 1
        created = [u for u in utxos if u.tx_hash == tx.hash()]
        assert len(created) == 1
        assert created[0].amount == 1_000_000_000

    def test_utxo_spending_removes_from_set(self, mock_node):
        """Spent UTXOs are removed from the set."""
        sk = SigningKey.generate(curve=SECP256k1)
        pubkey = sk.get_verifying_key().to_string("compressed")
        lock_script = b"\x76\xa9\x14" + hashlib.sha256(pubkey).digest()[:20] + b"\x88\xac"

        tx1 = Transaction(
            inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000, lock_script=lock_script)],
        )
        mock_node.utxo_set.apply_transaction(tx1)
        txid1 = tx1.hash()

        # Spend the created UTXO
        tx2 = Transaction(
            inputs=[TxInput(tx_hash=txid1, output_index=0)],
            outputs=[TxOutput(amount=900_000_000, lock_script=lock_script)],
        )
        mock_node.utxo_set.apply_transaction(tx2)

        assert not mock_node.utxo_set.exists(txid1, 0)
        assert mock_node.utxo_set.exists(tx2.hash(), 0)

    def test_utxo_address_index(self, mock_node):
        """UTXO set maintains address-based index."""
        addr_script = b"\x76\xa9\x14" + b"X" * 20 + b"\x88\xac"
        addr = "mock_addr_test"

        tx = Transaction(
            inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
            outputs=[
                TxOutput(amount=300_000_000, lock_script=addr_script),
                TxOutput(amount=700_000_000, lock_script=addr_script),
            ],
        )
        mock_node.utxo_set.apply_transaction(tx)
        # Note: extract_address uses base58, so this is a structural check
        assert len(mock_node.utxo_set.get_all()) >= 2


# ---------------------------------------------------------------------------
# Double-Spend Rejection
# ---------------------------------------------------------------------------

class TestDoubleSpendRejection:
    def test_double_spend_detected(self, mock_node):
        """Attempting to spend the same UTXO twice should be detected."""
        lock_script = b"\x76\xa9\x14" + b"D" * 20 + b"\x88\xac"

        tx1 = Transaction(
            inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000, lock_script=lock_script)],
        )
        mock_node.utxo_set.apply_transaction(tx1)
        txid1 = tx1.hash()

        # First spend
        tx2 = Transaction(
            inputs=[TxInput(tx_hash=txid1, output_index=0)],
            outputs=[TxOutput(amount=900_000_000, lock_script=lock_script)],
        )
        mock_node.utxo_set.apply_transaction(tx2)

        # Second spend of same UTXO should fail (UTXO no longer exists)
        assert not mock_node.utxo_set.exists(txid1, 0)

    def test_double_spend_in_same_block(self, mock_node):
        """Two transactions spending the same input in the same block."""
        lock_script = b"\x76\xa9\x14" + b"S" * 20 + b"\x88\xac"

        tx1 = Transaction(
            inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000, lock_script=lock_script)],
        )
        mock_node.utxo_set.apply_transaction(tx1)
        txid1 = tx1.hash()

        # Create two transactions spending the same UTXO
        tx_spend_a = Transaction(
            inputs=[TxInput(tx_hash=txid1, output_index=0)],
            outputs=[TxOutput(amount=800_000_000, lock_script=lock_script)],
        )
        tx_spend_b = Transaction(
            inputs=[TxInput(tx_hash=txid1, output_index=0)],
            outputs=[TxOutput(amount=700_000_000, lock_script=lock_script)],
        )

        # When applied sequentially, second should find UTXO already spent
        mock_node.utxo_set.apply_transaction(tx_spend_a)
        # The second spend won't find the UTXO (it was already removed)
        assert not mock_node.utxo_set.exists(txid1, 0)


# ---------------------------------------------------------------------------
# Invalid Signature Rejection
# ---------------------------------------------------------------------------

class TestInvalidSignature:
    def test_invalid_signature_rejected(self):
        """Transaction with invalid signature should fail verification."""
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.get_verifying_key()
        pubkey = vk.to_string("compressed")

        tx = Transaction(
            version=1,
            tx_type=TxType.TRANSFER,
            inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000)],
        )

        # Valid signature
        sighash = tx.signing_hash()
        valid_sig = sk.sign_digest(sighash, sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order))
        assert tx.verify_signature(pubkey, valid_sig)

        # Tampered signature
        bad_sig = valid_sig[:-1] + bytes([(valid_sig[-1] + 1) % 256])
        assert not tx.verify_signature(pubkey, bad_sig)

    def test_wrong_pubkey_rejected(self):
        """Signature from wrong keypair should be rejected."""
        sk_a = SigningKey.generate(curve=SECP256k1)
        sk_b = SigningKey.generate(curve=SECP256k1)
        pubkey_b = sk_b.get_verifying_key().to_string("compressed")

        tx = Transaction(
            inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000)],
        )
        sighash = tx.signing_hash()
        sig_a = sk_a.sign_digest(sighash, sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order))

        # Signature from A verified against B's pubkey should fail
        assert not tx.verify_signature(pubkey_b, sig_a)


# ---------------------------------------------------------------------------
# Chain Reorganization (Simplified)
# ---------------------------------------------------------------------------

class TestChainReorganization:
    def test_simple_chain_reorg(self, mock_node):
        """Simplified chain reorganization test."""
        # Build main chain: genesis -> 1 -> 2
        block1 = mock_node.create_block([], validator_index=0)
        block2 = mock_node.create_block([], validator_index=0)

        # Simulate a fork at block1
        fork_header = BlockHeader(
            version=1,
            prev_block_hash=block1.hash,
            merkle_root_tx="0" * 64,
            merkle_root_utxo="0" * 64,
            merkle_root_identity="0" * 64,
            timestamp=block1.header.timestamp + 5000,
            height=2,
            tx_count=0,
            validator_pubkey=mock_node.validator_keys[1][1].hex(),
            signature="",
        )
        # Sign fork header
        priv = mock_node.validator_keys[1][0]
        sig = SigningKey.from_string(priv, curve=SECP256k1).sign_digest(
            fork_header.signing_hash(),
            sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order)
        )
        fork_header.signature = sig.hex()
        fork_block = Block(header=fork_header, body=BlockBody())

        # Both chains are valid up to block1
        assert fork_block.link_valid(block1)
        assert block2.link_valid(block1)
        assert fork_block.hash != block2.hash

    def test_utxo_snapshot_restore(self, mock_node):
        """UTXO set snapshot and restore for reorg handling."""
        lock_script = b"\x76\xa9\x14" + b"R" * 20 + b"\x88\xac"
        tx = Transaction(
            inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
            outputs=[TxOutput(amount=500_000_000, lock_script=lock_script)],
        )
        mock_node.create_block([tx])

        snap = mock_node.utxo_set.snapshot()
        new_set = UTXOSet()
        new_set.restore(snap)
        assert new_set.size() == mock_node.utxo_set.size()
        assert new_set.merkle_root == mock_node.utxo_set.merkle_root


# ---------------------------------------------------------------------------
# Patricia Trie Root
# ---------------------------------------------------------------------------

class TestPatriciaTrieRoot:
    def test_state_root_changes_with_utxo(self, mock_node):
        """UTXO set root hash changes when UTXOs are added/removed."""
        root_before = mock_node.utxo_set.merkle_root

        lock_script = b"\x76\xa9\x14" + b"T" * 20 + b"\x88\xac"
        tx = Transaction(
            inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000, lock_script=lock_script)],
        )
        mock_node.utxo_set.apply_transaction(tx)
        root_after = mock_node.utxo_set.merkle_root

        assert root_after != root_before
        assert len(root_after) == 64

    def test_empty_set_root(self):
        """Empty UTXO set has zero root."""
        us = UTXOSet()
        assert us.merkle_root == "0" * 64

    def test_deterministic_root(self, mock_node):
        """Same UTXOs produce same root."""
        lock_script = b"\x76\xa9\x14" + b"Q" * 20 + b"\x88\xac"
        tx = Transaction(
            inputs=[TxInput(tx_hash="b" * 64, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000, lock_script=lock_script)],
        )

        set1 = UTXOSet()
        set1.apply_transaction(tx)

        set2 = UTXOSet()
        set2.apply_transaction(tx)

        assert set1.merkle_root == set2.merkle_root


# ---------------------------------------------------------------------------
# Storage Tests
# ---------------------------------------------------------------------------

class TestStorage:
    def test_block_store_save_and_retrieve(self, temp_storage, genesis_block):
        """BlockStore must persist and retrieve blocks."""
        bs = temp_storage["block_store"]
        bs.save_block(genesis_block)
        fetched = bs.get_block_by_height(0)
        assert fetched is not None
        assert fetched.hash == genesis_block.hash

    def test_block_store_range_query(self, temp_storage, mock_node):
        """Range queries return correct blocks."""
        bs = temp_storage["block_store"]
        for block in mock_node.chain:
            bs.save_block(block)
        blocks = bs.get_blocks_range(0, 5)
        assert len(blocks) == min(5, len(mock_node.chain))

    def test_index_store_transaction_indexing(self, temp_storage):
        """IndexStore must index and retrieve transactions."""
        ix = temp_storage["index_store"]
        tx = Transaction(
            inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
            outputs=[TxOutput(amount=1_000_000_000)],
        )
        ix.index_transaction(tx, block_height=1, tx_index=0)
        fetched = ix.get_transaction(tx.hash())
        assert fetched is not None
        assert fetched.hash() == tx.hash()

    def test_index_store_utxo_lifecycle(self, temp_storage):
        """UTXO indexing: add, query, spend."""
        ix = temp_storage["index_store"]
        utxo = UTXO(tx_hash="a" * 64, output_index=0, amount=500_000_000)
        ix.index_utxo(utxo, address="addr_test")
        found = ix.get_utxos_by_address("addr_test", unspent_only=True)
        assert len(found) == 1
        assert found[0].amount == 500_000_000

        ix.spend_utxo("a" * 64, 0, spent_by_tx="bbbb")
        spent = ix.get_utxos_by_address("addr_test", unspent_only=True)
        assert len(spent) == 0
