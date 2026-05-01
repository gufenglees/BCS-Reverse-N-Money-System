"""
BCS Chain — Core Data Stubs (Minimal interface definitions)
Provides dataclasses for Transaction, UTXO, Block, etc.
Used by the offline module implementations.
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional, Dict, Any


class TxType(IntEnum):
    TRANSFER = 0
    TRANSFER_SALE = 1
    TRANSFER_WAGE = 2
    MINT = 10
    REPLENISH = 11
    BURN = 12
    REGISTER_IDENTITY = 20
    UPDATE_IDENTITY = 21
    GOV_PARAMETER_CHANGE = 30
    GOV_VALIDATOR_CHANGE = 31


@dataclass
class TxInput:
    tx_hash: bytes
    output_index: int
    unlock_script: bytes = b""

    def __hash__(self) -> int:
        return hash((self.tx_hash, self.output_index))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TxInput):
            return NotImplemented
        return self.tx_hash == other.tx_hash and self.output_index == other.output_index


@dataclass
class TxOutput:
    amount: int
    lock_script: bytes
    asset_type: int = 0
    metadata: bytes = b""


@dataclass
class Transaction:
    version: int = 1
    tx_type: TxType = TxType.TRANSFER
    inputs: List[TxInput] = field(default_factory=list)
    outputs: List[TxOutput] = field(default_factory=list)
    lock_time: int = 0
    extra: bytes = b""
    witnesses: List[bytes] = field(default_factory=list)
    # Offline metadata (not serialized to wire)
    _tx_hash: Optional[bytes] = field(default=None, repr=False)
    _offline_priority: int = 0  # higher = earlier creation / more important

    def hash(self) -> bytes:
        if self._tx_hash is not None:
            return self._tx_hash
        # Deterministic hash over wire-relevant fields
        h = hashlib.sha3_256()
        h.update(self.version.to_bytes(4, "big"))
        h.update(int(self.tx_type).to_bytes(4, "big"))
        for inp in self.inputs:
            h.update(inp.tx_hash)
            h.update(inp.output_index.to_bytes(4, "big"))
        for out in self.outputs:
            h.update(out.amount.to_bytes(8, "big"))
            h.update(out.lock_script)
        h.update(self.lock_time.to_bytes(8, "big"))
        h.update(self.extra)
        self._tx_hash = h.digest()
        return self._tx_hash

    @property
    def total_output(self) -> int:
        return sum(o.amount for o in self.outputs)

    def copy_without_witnesses(self) -> "Transaction":
        """Return a copy suitable for signing (hash excludes witnesses)."""
        return Transaction(
            version=self.version,
            tx_type=self.tx_type,
            inputs=[TxInput(i.tx_hash, i.output_index, b"") for i in self.inputs],
            outputs=[TxOutput(o.amount, o.lock_script, o.asset_type, o.metadata) for o in self.outputs],
            lock_time=self.lock_time,
            extra=self.extra,
            witnesses=[],
        )

    def serialize(self) -> bytes:
        """Simple serialization for caching."""
        import pickle
        return pickle.dumps(self)

    @classmethod
    def deserialize(cls, data: bytes) -> "Transaction":
        import pickle
        return pickle.loads(data)


@dataclass
class BlockHeader:
    version: int = 1
    prev_block_hash: bytes = b""
    merkle_root_tx: bytes = b""
    merkle_root_utxo: bytes = b""
    merkle_root_identity: bytes = b""
    timestamp: int = 0
    height: int = 0
    tx_count: int = 0
    validator_pubkey: bytes = b""
    signature: bytes = b""
    extra_data: bytes = b""

    def hash(self) -> bytes:
        h = hashlib.sha3_256()
        h.update(self.version.to_bytes(4, "big"))
        h.update(self.prev_block_hash)
        h.update(self.merkle_root_tx)
        h.update(self.merkle_root_utxo)
        h.update(self.merkle_root_identity)
        h.update(self.timestamp.to_bytes(8, "big"))
        h.update(self.height.to_bytes(8, "big"))
        h.update(self.tx_count.to_bytes(4, "big"))
        h.update(self.validator_pubkey)
        h.update(self.extra_data)
        return h.digest()


@dataclass
class Block:
    header: BlockHeader = field(default_factory=BlockHeader)
    transactions: List[Transaction] = field(default_factory=list)


@dataclass
class UTXO:
    tx_hash: bytes
    output_index: int
    amount: int
    lock_script: bytes
    confirmations: int = 0

    def __hash__(self) -> int:
        return hash((self.tx_hash, self.output_index))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UTXO):
            return NotImplemented
        return self.tx_hash == other.tx_hash and self.output_index == other.output_index


class UTXOSet:
    """In-memory UTXO set for testing / stubbing."""

    def __init__(self) -> None:
        self._utxos: Dict[tuple, UTXO] = {}

    def add(self, utxo: UTXO) -> None:
        self._utxos[(utxo.tx_hash, utxo.output_index)] = utxo

    def remove(self, tx_hash: bytes, output_index: int) -> None:
        key = (tx_hash, output_index)
        if key in self._utxos:
            del self._utxos[key]

    def exists(self, tx_hash: bytes, output_index: int) -> bool:
        return (tx_hash, output_index) in self._utxos

    def get(self, tx_hash: bytes, output_index: int) -> Optional[UTXO]:
        return self._utxos.get((tx_hash, output_index))

    def all(self) -> List[UTXO]:
        return list(self._utxos.values())

    def for_address(self, address: bytes) -> List[UTXO]:
        return [u for u in self._utxos.values() if address in u.lock_script]

    def apply_transaction(self, tx: Transaction) -> None:
        """Spend inputs and create outputs."""
        for inp in tx.inputs:
            self.remove(inp.tx_hash, inp.output_index)
        for idx, out in enumerate(tx.outputs):
            self.add(UTXO(tx.hash(), idx, out.amount, out.lock_script))

    def copy(self) -> "UTXOSet":
        new_set = UTXOSet()
        new_set._utxos = dict(self._utxos)
        return new_set


@dataclass
class AccountState:
    address: bytes = b""
    did: str = ""
    n_balance: int = 0
    n_locked: int = 0
    n_available: int = 0
    max_sale_capacity: int = 0
    current_sale_volume: int = 0
    identity_status: int = 0
    first_auth_height: int = 0
    last_replenish_height: int = 0
    nonce: int = 0
    last_activity: int = 0


@dataclass
class SystemParameters:
    phi_numerator: int = 3
    phi_denominator: int = 100
    psi_numerator: int = 2
    psi_denominator: int = 100
    block_interval_ms: int = 5000
    max_block_size: int = 1024 * 1024
    max_tx_per_block: int = 2000
    min_n_mint: int = 1000000000
    replenish_threshold: int = 500000000
    validators: List[bytes] = field(default_factory=list)
    required_gov_signatures: int = 3

    @property
    def phi(self) -> float:
        return self.phi_numerator / self.phi_denominator

    @property
    def psi(self) -> float:
        return self.psi_numerator / self.psi_denominator
