"""
BCS Blockchain Core — Block Structure
=====================================
Implements the BlockHeader, BlockBody, and Block dataclasses
for the BCS blockchain.

Block headers carry three Merkle roots:
  • merkle_root_tx       — transaction tree
  • merkle_root_utxo     — UTXO state tree (Patricia Trie root)
  • merkle_root_identity — identity state tree

All hashes use SHA3-256.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from transaction import Transaction, TxInput, TxOutput


# ---------------------------------------------------------------------------
# BlockHeader
# ---------------------------------------------------------------------------

@dataclass
class BlockHeader:
    """
    BCS block header.

    Fields:
        version: Protocol version (currently 1).
        prev_block_hash: Hex string of the previous block's hash (32 bytes).
        merkle_root_tx: Hex string of the transaction Merkle root.
        merkle_root_utxo: Hex string of the UTXO Patricia Trie root.
        merkle_root_identity: Hex string of the identity state root.
        timestamp: Unix timestamp in milliseconds.
        height: Block height (genesis = 0).
        tx_count: Number of transactions in the block.
        validator_pubkey: Compressed secp256k1 pubkey of the proposer (hex).
        signature: ECDSA signature over the header hash (hex).
        extra_data: Arbitrary governance/auxiliary data (RLP-style, raw bytes).
    """
    version: int = 1
    prev_block_hash: str = "0" * 64
    merkle_root_tx: str = "0" * 64
    merkle_root_utxo: str = "0" * 64
    merkle_root_identity: str = "0" * 64
    timestamp: int = 0
    height: int = 0
    tx_count: int = 0
    validator_pubkey: str = ""
    signature: str = ""
    extra_data: bytes = field(default_factory=bytes)

    def __post_init__(self) -> None:
        if not isinstance(self.extra_data, bytes):
            object.__setattr__(self, "extra_data", bytes(self.extra_data))
        if self.timestamp == 0:
            object.__setattr__(self, "timestamp", int(time.time() * 1000))

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    def _canonical_bytes(self) -> bytes:
        """Deterministic raw bytes for hashing (excludes signature)."""
        payload = {
            "version": self.version,
            "prev_block_hash": self.prev_block_hash,
            "merkle_root_tx": self.merkle_root_tx,
            "merkle_root_utxo": self.merkle_root_utxo,
            "merkle_root_identity": self.merkle_root_identity,
            "timestamp": self.timestamp,
            "height": self.height,
            "tx_count": self.tx_count,
            "validator_pubkey": self.validator_pubkey,
            "extra_data": self.extra_data.hex(),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def hash(self) -> str:
        """Return SHA3-256 hex digest of the header (block hash)."""
        return hashlib.sha3_256(self._canonical_bytes()).hexdigest()

    def signing_hash(self) -> bytes:
        """Return the 32-byte digest that the proposer signs."""
        return hashlib.sha3_256(self._canonical_bytes()).digest()

    def verify_header(self, pubkey_bytes: bytes) -> bool:
        """
        Verify the block header signature using the validator's public key.

        Args:
            pubkey_bytes: 33-byte compressed or 65-byte uncompressed public key.
        """
        if not self.signature:
            return False
        try:
            from ecdsa import SECP256k1, BadSignatureError
            from ecdsa.keys import VerifyingKey
            from ecdsa.util import sigdecode_der

            vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1)
            sig_bytes = bytes.fromhex(self.signature)
            return vk.verify_digest(sig_bytes, self.signing_hash(), sigdecode=sigdecode_der)
        except (BadSignatureError, Exception):
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "prev_block_hash": self.prev_block_hash,
            "merkle_root_tx": self.merkle_root_tx,
            "merkle_root_utxo": self.merkle_root_utxo,
            "merkle_root_identity": self.merkle_root_identity,
            "timestamp": self.timestamp,
            "height": self.height,
            "tx_count": self.tx_count,
            "validator_pubkey": self.validator_pubkey,
            "signature": self.signature,
            "extra_data": self.extra_data.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BlockHeader":
        return cls(
            version=d["version"],
            prev_block_hash=d["prev_block_hash"],
            merkle_root_tx=d["merkle_root_tx"],
            merkle_root_utxo=d["merkle_root_utxo"],
            merkle_root_identity=d["merkle_root_identity"],
            timestamp=d["timestamp"],
            height=d["height"],
            tx_count=d["tx_count"],
            validator_pubkey=d["validator_pubkey"],
            signature=d["signature"],
            extra_data=bytes.fromhex(d["extra_data"]),
        )


# ---------------------------------------------------------------------------
# BlockBody
# ---------------------------------------------------------------------------

@dataclass
class BlockBody:
    """Container for the transaction list inside a block."""
    transactions: list[Transaction] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"transactions": [tx.to_dict() for tx in self.transactions]}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BlockBody":
        return cls(transactions=[Transaction.from_dict(t) for t in d["transactions"]])


# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------

@dataclass
class Block:
    """
    Complete BCS block: header + body.

    Provides convenience accessors for Merkle root computation and
    chain-link validation.
    """
    header: BlockHeader = field(default_factory=BlockHeader)
    body: BlockBody = field(default_factory=BlockBody)

    def __post_init__(self) -> None:
        # Ensure tx_count matches body
        actual_count = len(self.body.transactions)
        if self.header.tx_count != actual_count:
            object.__setattr__(
                self.header, "tx_count", actual_count
            )

    @property
    def hash(self) -> str:
        return self.header.hash()

    @property
    def height(self) -> int:
        return self.header.height

    @property
    def prev_block_hash(self) -> str:
        return self.header.prev_block_hash

    def tx_merkle_root(self) -> str:
        """Compute the transaction Merkle root from body transactions."""
        if not self.body.transactions:
            return "0" * 64
        return compute_merkle_root([tx.hash() for tx in self.body.transactions])

    def verify_header(self, pubkey_bytes: bytes) -> bool:
        """Delegate to BlockHeader.verify_header."""
        return self.header.verify_header(pubkey_bytes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "header": self.header.to_dict(),
            "body": self.body.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Block":
        return cls(
            header=BlockHeader.from_dict(d["header"]),
            body=BlockBody.from_dict(d["body"]),
        )

    def is_genesis(self) -> bool:
        """Return True if this is a genesis block (height == 0)."""
        return self.header.height == 0

    def link_valid(self, previous_block: "Block") -> bool:
        """
        Check whether this block correctly links to *previous_block*.

        Validates:
          • prev_block_hash == previous_block.hash
          • height == previous_block.height + 1
          • timestamp >= previous_block.header.timestamp
        """
        return (
            self.header.prev_block_hash == previous_block.hash
            and self.header.height == previous_block.header.height + 1
            and self.header.timestamp >= previous_block.header.timestamp
        )


# ---------------------------------------------------------------------------
# Merkle tree helpers
# ---------------------------------------------------------------------------

def compute_merkle_root(hashes: list[str]) -> str:
    """
    Compute the Merkle root of a list of hex string hashes.

    Uses binary SHA3-256 hashing with duplication of the last element
    when the count is odd (Bitcoin convention).
    """
    if not hashes:
        return "0" * 64

    layer = [bytes.fromhex(h) for h in hashes]
    while len(layer) > 1:
        next_layer: list[bytes] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            next_layer.append(hashlib.sha3_256(left + right).digest())
        layer = next_layer
    return layer[0].hex()


def compute_merkle_proof(hashes: list[str], index: int) -> list[tuple[str, str]]:
    """
    Build a Merkle proof path for the element at *index*.

    Returns a list of (sibling_hash, direction) tuples where direction
    is 'L' (sibling is left) or 'R' (sibling is right).
    """
    if not hashes or index < 0 or index >= len(hashes):
        return []

    layer = [bytes.fromhex(h) for h in hashes]
    proof: list[tuple[str, str]] = []
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        sibling = layer[index - 1] if index % 2 == 1 else layer[index + 1]
        direction = "L" if index % 2 == 1 else "R"
        proof.append((sibling.hex(), direction))
        layer = [
            hashlib.sha3_256(layer[i] + layer[i + 1]).digest()
            for i in range(0, len(layer), 2)
        ]
        index //= 2
    return proof


def verify_merkle_proof(
    root: str, leaf_hash: str, proof: list[tuple[str, str]]
) -> bool:
    """Verify a Merkle proof against a known root."""
    current = bytes.fromhex(leaf_hash)
    for sibling_hex, direction in proof:
        sibling = bytes.fromhex(sibling_hex)
        if direction == "L":
            current = hashlib.sha3_256(sibling + current).digest()
        else:
            current = hashlib.sha3_256(current + sibling).digest()
    return current.hex() == root


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from ecdsa.keys import SigningKey, VerifyingKey
    from ecdsa import SECP256k1
    import time as _time

    # 1. Genesis block
    genesis_header = BlockHeader(
        version=1,
        prev_block_hash="0" * 64,
        merkle_root_tx="0" * 64,
        merkle_root_utxo="0" * 64,
        merkle_root_identity="0" * 64,
        timestamp=int(_time.time() * 1000),
        height=0,
        tx_count=0,
    )
    genesis = Block(header=genesis_header, body=BlockBody())
    assert genesis.is_genesis()
    print("Genesis block hash:", genesis.hash)
    assert len(genesis.hash) == 64

    # 2. Block with one tx
    tx = Transaction(
        inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
        outputs=[TxOutput(amount=500_000_000)],
    )
    block2_header = BlockHeader(
        version=1,
        prev_block_hash=genesis.hash,
        height=1,
        tx_count=1,
    )
    block2 = Block(header=block2_header, body=BlockBody(transactions=[tx]))
    block2.header.merkle_root_tx = block2.tx_merkle_root()
    assert block2.header.tx_count == 1
    assert block2.link_valid(genesis)
    print("Block2 hash:", block2.hash)

    # 3. Sign and verify header
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = vk.to_string("compressed")
    block2.header.validator_pubkey = pubkey.hex()
    sig = sk.sign_digest(block2.header.signing_hash(), sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order))
    block2.header.signature = sig.hex()
    assert block2.verify_header(pubkey)
    print("Header signature verified")

    # 4. Serialization round-trip
    block2_rt = Block.from_dict(block2.to_dict())
    assert block2_rt.hash == block2.hash
    assert block2_rt.body.transactions[0].hash() == tx.hash()
    print("Round-trip OK")

    # 5. Merkle tree tests
    hashes = ["a" * 64, "b" * 64, "c" * 64, "d" * 64]
    root = compute_merkle_root(hashes)
    assert len(root) == 64
    proof = compute_merkle_proof(hashes, 1)
    assert verify_merkle_proof(root, hashes[1], proof)
    print("Merkle tree tests OK")

    # 6. Odd number of leaves
    odd_hashes = ["aa" * 32, "bb" * 32, "cc" * 32]
    odd_root = compute_merkle_root(odd_hashes)
    odd_proof = compute_merkle_proof(odd_hashes, 2)
    assert verify_merkle_proof(odd_root, odd_hashes[2], odd_proof)
    print("Odd-leaf Merkle OK")

    print("block.py self-test PASSED")
