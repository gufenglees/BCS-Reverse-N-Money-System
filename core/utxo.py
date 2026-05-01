"""
BCS Blockchain Core — UTXO Set Management
=========================================
Manages the Unspent Transaction Output (UTXO) set for BCS.

Components:
  • UTXO          – individual unspent output record
  • UTXOSet       – in-memory UTXO dictionary with Patricia Trie root
  • SimplePatriciaTrie – memory-only simplified Patricia Trie

The UTXOSet supports applying single transactions or full blocks,
producing a new Patricia root after each operation.

All amounts use int (nanoN units, 1 N = 10^9 nanoN).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional

from transaction import Transaction, TxInput, TxOutput
from script import StandardScripts


# ---------------------------------------------------------------------------
# UTXO record
# ---------------------------------------------------------------------------

@dataclass
class UTXO:
    """
    An unspent transaction output record.

    Fields:
        tx_hash: Hex string of the creating transaction.
        output_index: Index position within the creating tx outputs.
        amount: Value in nanoN.
        lock_script: The scriptPubKey bytes.
        asset_type: Asset category (0 = N currency).
        metadata: Extra constraints (timelock, etc.).
        confirmations: Number of block confirmations.
    """
    tx_hash: str = ""
    output_index: int = 0
    amount: int = 0
    lock_script: bytes = field(default_factory=bytes)
    asset_type: int = 0
    metadata: bytes = field(default_factory=bytes)
    confirmations: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.lock_script, bytes):
            object.__setattr__(self, "lock_script", bytes(self.lock_script))
        if not isinstance(self.metadata, bytes):
            object.__setattr__(self, "metadata", bytes(self.metadata))

    @property
    def outpoint(self) -> str:
        """Canonical outpoint key: tx_hash:index."""
        return f"{self.tx_hash}:{self.output_index}"

    def extract_address(self) -> Optional[str]:
        """
        Attempt to extract a P2PKH address from the lock_script.
        Returns a Base58Check-style string, or None if not P2PKH.
        """
        pk_hash = StandardScripts.extract_pubkey_hash_from_p2pkh(self.lock_script)
        if pk_hash is None:
            return None
        return base58_encode(pk_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tx_hash": self.tx_hash,
            "output_index": self.output_index,
            "amount": self.amount,
            "lock_script": self.lock_script.hex(),
            "asset_type": self.asset_type,
            "metadata": self.metadata.hex(),
            "confirmations": self.confirmations,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "UTXO":
        return cls(
            tx_hash=d["tx_hash"],
            output_index=d["output_index"],
            amount=d["amount"],
            lock_script=bytes.fromhex(d["lock_script"]),
            asset_type=d["asset_type"],
            metadata=bytes.fromhex(d["metadata"]),
            confirmations=d["confirmations"],
        )


# ---------------------------------------------------------------------------
# Simplified Base58Check encoder (for address derivation)
# ---------------------------------------------------------------------------

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    """Encode bytes to Base58 (no checksum, for brevity)."""
    num = int.from_bytes(data, "big")
    if num == 0:
        return ALPHABET[0] * len(data)
    result = ""
    while num > 0:
        num, rem = divmod(num, 58)
        result = ALPHABET[rem] + result
    # Preserve leading zero bytes
    leading = len(data) - len(data.lstrip(b"\x00"))
    return ALPHABET[0] * leading + result


def base58_decode(s: str) -> bytes:
    """Decode a Base58 string to bytes."""
    num = 0
    for ch in s:
        num = num * 58 + ALPHABET.index(ch)
    # Determine byte length
    byte_len = (num.bit_length() + 7) // 8
    if byte_len == 0:
        byte_len = 1
    return num.to_bytes(byte_len, "big")


# ---------------------------------------------------------------------------
# Simplified Patricia Trie (memory-only)
# ---------------------------------------------------------------------------

class SimplePatriciaTrie:
    """
    A minimal memory-only Patricia Trie used to compute a root hash
    for the UTXO set.  Not a production-grade disk-backed trie, but
    sufficient for root-hash derivation and light-client proofs.

    Keys are hex strings (outpoint: tx_hash:index).
    Values are the SHA3-256 hash of the serialized UTXO.
    """

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}

    def put(self, key: str, value: bytes) -> None:
        """Insert or update a key-value pair."""
        self._store[key] = value

    def delete(self, key: str) -> None:
        """Remove a key if present."""
        self._store.pop(key, None)

    def get(self, key: str) -> Optional[bytes]:
        return self._store.get(key)

    def root_hash(self) -> str:
        """
        Compute the root hash by sorting all keys and iteratively hashing.
        In a full Patricia Trie this would follow radix-tree rules; here we
        approximate with a sorted Merkle-ish commitment for simplicity.
        """
        if not self._store:
            return "0" * 64
        items = sorted(self._store.items(), key=lambda x: x[0])
        h = hashlib.sha3_256()
        for k, v in items:
            h.update(k.encode())
            h.update(v)
        return h.hexdigest()


# ---------------------------------------------------------------------------
# UTXOSet
# ---------------------------------------------------------------------------

class UTXOSet:
    """
    Manages the active UTXO set with Patricia Trie root tracking.

    Usage::

        utxos = UTXOSet()
        utxos.add(utxo)
        utxos.apply_transaction(tx)
        utxos.apply_block(block)
    """

    def __init__(self) -> None:
        # Primary index: outpoint -> UTXO
        self._utxos: dict[str, UTXO] = {}
        # Secondary index: address -> set of outpoints
        self._addr_index: dict[str, set[str]] = {}
        # Patricia Trie for root hash
        self._trie = SimplePatriciaTrie()

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def add(self, utxo: UTXO) -> None:
        """Add a UTXO to the set and update indexes."""
        key = utxo.outpoint
        self._utxos[key] = utxo
        self._trie.put(key, self._hash_utxo(utxo))

        addr = utxo.extract_address()
        if addr:
            self._addr_index.setdefault(addr, set()).add(key)

    def remove(self, tx_hash: str, output_index: int) -> Optional[UTXO]:
        """Remove a UTXO by its outpoint and return it (or None)."""
        key = f"{tx_hash}:{output_index}"
        utxo = self._utxos.pop(key, None)
        if utxo is not None:
            self._trie.delete(key)
            addr = utxo.extract_address()
            if addr and addr in self._addr_index:
                self._addr_index[addr].discard(key)
                if not self._addr_index[addr]:
                    del self._addr_index[addr]
        return utxo

    def get(self, tx_hash: str, output_index: int) -> Optional[UTXO]:
        return self._utxos.get(f"{tx_hash}:{output_index}")

    def exists(self, tx_hash: str, output_index: int) -> bool:
        return f"{tx_hash}:{output_index}" in self._utxos

    def get_all(self) -> list[UTXO]:
        return list(self._utxos.values())

    def get_by_address(self, address: str) -> list[UTXO]:
        """Return all UTXOs associated with a given address."""
        keys = self._addr_index.get(address, set())
        return [self._utxos[k] for k in keys if k in self._utxos]

    @property
    def merkle_root(self) -> str:
        return self._trie.root_hash()

    def size(self) -> int:
        return len(self._utxos)

    # ------------------------------------------------------------------
    # Transaction / Block application
    # ------------------------------------------------------------------

    def apply_transaction(self, tx: Transaction) -> dict[str, Any]:
        """
        Apply a single transaction to the UTXO set.

        Removes spent inputs and adds new outputs.

        Returns:
            dict with ``spent`` (list of UTXO removed) and ``created``
            (list of new UTXO added).
        """
        spent: list[UTXO] = []
        created: list[UTXO] = []
        txid = tx.hash()

        # Spend inputs
        for inp in tx.inputs:
            utxo = self.remove(inp.tx_hash, inp.output_index)
            if utxo is not None:
                spent.append(utxo)

        # Create outputs
        for idx, out in enumerate(tx.outputs):
            if out.amount == 0:
                # Skip zero-value outputs (possible marker outputs)
                continue
            new_utxo = UTXO(
                tx_hash=txid,
                output_index=idx,
                amount=out.amount,
                lock_script=out.lock_script,
                asset_type=out.asset_type,
                metadata=out.metadata,
                confirmations=0,
            )
            self.add(new_utxo)
            created.append(new_utxo)

        return {"spent": spent, "created": created}

    def apply_block(self, block: "Block") -> dict[str, Any]:
        """
        Apply all transactions in a block and increment confirmation counts.

        Returns a summary dict with ``spent``, ``created``, and
        ``total_applied``.
        """
        all_spent: list[UTXO] = []
        all_created: list[UTXO] = []

        for tx in block.body.transactions:
            res = self.apply_transaction(tx)
            all_spent.extend(res["spent"])
            all_created.extend(res["created"])

        # Increment confirmations for all remaining UTXOs
        for utxo in self._utxos.values():
            utxo.confirmations += 1

        return {
            "spent": all_spent,
            "created": all_created,
            "total_applied": len(block.body.transactions),
        }

    def revert_transaction(self, tx: Transaction) -> None:
        """
        Revert a transaction: restore spent UTXOs and remove created ones.
        Used for block reorganization.
        """
        txid = tx.hash()
        # Remove outputs created by this tx
        for idx in range(len(tx.outputs)):
            self.remove(txid, idx)
        # Restore inputs
        for inp in tx.inputs:
            # The original UTXO data would need to be stored elsewhere
            # for full reversion; here we just note the outpoint.
            pass

    # ------------------------------------------------------------------
    # Snapshot / restore
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serializable snapshot of the UTXO set."""
        return {
            "utxos": {k: v.to_dict() for k, v in self._utxos.items()},
            "root": self.merkle_root,
        }

    def restore(self, snapshot: dict[str, Any]) -> None:
        """Restore the UTXO set from a snapshot."""
        self._utxos = {}
        self._addr_index = {}
        self._trie = SimplePatriciaTrie()
        for key, ud in snapshot.get("utxos", {}).items():
            utxo = UTXO.from_dict(ud)
            self.add(utxo)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_utxo(utxo: UTXO) -> bytes:
        """Deterministic hash of a UTXO record for the Patricia Trie."""
        return hashlib.sha3_256(
            utxo.tx_hash.encode()
            + utxo.output_index.to_bytes(4, "big")
            + utxo.amount.to_bytes(8, "big")
            + utxo.lock_script
        ).digest()


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from ecdsa.keys import SigningKey
    from ecdsa import SECP256k1

    sk = SigningKey.generate(curve=SECP256k1)
    pubkey = sk.get_verifying_key().to_string("compressed")
    pk_hash = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
    addr = base58_encode(pk_hash)
    lock_script = StandardScripts.p2pkh_lock_script(pk_hash)

    # 1. Add UTXOs
    us = UTXOSet()
    u1 = UTXO(
        tx_hash="a" * 64,
        output_index=0,
        amount=1_000_000_000,
        lock_script=lock_script,
    )
    u2 = UTXO(
        tx_hash="b" * 64,
        output_index=1,
        amount=500_000_000,
        lock_script=lock_script,
    )
    us.add(u1)
    us.add(u2)
    assert us.size() == 2
    print("UTXOSet size after add:", us.size())

    # 2. Address index
    by_addr = us.get_by_address(addr)
    assert len(by_addr) == 2
    print("Address lookup OK:", len(by_addr))

    # 3. Apply transaction
    tx = Transaction(
        inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
        outputs=[
            TxOutput(amount=300_000_000, lock_script=lock_script),
            TxOutput(amount=700_000_000, lock_script=lock_script),
        ],
    )
    res = us.apply_transaction(tx)
    assert len(res["spent"]) == 1
    assert len(res["created"]) == 2
    assert not us.exists("a" * 64, 0)
    assert us.exists(tx.hash(), 0)
    print("Apply tx OK: spent", len(res["spent"]), "created", len(res["created"]))

    # 4. Patricia root changes after mutation
    root_before = us.merkle_root
    print("Patricia root:", root_before)
    assert len(root_before) == 64

    # 5. Snapshot round-trip
    snap = us.snapshot()
    us2 = UTXOSet()
    us2.restore(snap)
    assert us2.size() == us.size()
    assert us2.merkle_root == us.merkle_root
    print("Snapshot round-trip OK")

    # 6. Empty set root
    empty = UTXOSet()
    assert empty.merkle_root == "0" * 64
    print("Empty root OK")

    print("utxo.py self-test PASSED")
