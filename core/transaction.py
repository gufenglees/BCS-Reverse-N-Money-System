"""
BCS Blockchain Core — Transaction Structure
============================================
Implements the UTXO-based transaction model for BCS.
Supports multiple tx types including BCS-specific SALE, WAGE, MINT,
identity registration, and governance operations.

All monetary amounts use int (nanoN units, 1 N = 10^9 nanoN).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional

from ecdsa import SECP256k1, BadSignatureError
from ecdsa.ellipticcurve import Point
from ecdsa.keys import SigningKey, VerifyingKey


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ASSET_TYPE_N_CURRENCY: int = 0  # Native N currency
NANO_N_PER_N: int = 1_000_000_000


# ---------------------------------------------------------------------------
# TxType enumeration
# ---------------------------------------------------------------------------

class TxType(IntEnum):
    """Transaction type codes used in BCS."""

    TRANSFER = 0               # Ordinary N transfer (P2PKH)
    TRANSFER_SALE = 1          # Sale: external amount + optional reference + N(φ)
    TRANSFER_WAGE = 2          # Wage: external amount + optional reference + N(ψ)

    MINT = 10                  # Initial N issuance (gov only)
    REPLENISH = 11             # N replenishment (gov only)
    BURN = 12                  # N burn / destruction (gov only)

    REGISTER_IDENTITY = 20     # Register DID + VC on-chain
    UPDATE_IDENTITY = 21       # Update DID Document

    GOV_PARAMETER_CHANGE = 30  # Governance parameter change (φ, ψ, etc.)
    GOV_VALIDATOR_CHANGE = 31  # Validator set change


# ---------------------------------------------------------------------------
# TxInput
# ---------------------------------------------------------------------------

@dataclass
class TxInput:
    """
    A transaction input referencing an unspent output from a previous tx.

    Fields:
        tx_hash: Hash of the referenced transaction (hex str).
        output_index: Index of the referenced output in that tx.
        unlock_script: ScriptSig bytes that satisfies the referenced lock_script.
    """
    tx_hash: str = ""
    output_index: int = 0
    unlock_script: bytes = field(default_factory=bytes)

    def __post_init__(self) -> None:
        if not isinstance(self.unlock_script, bytes):
            object.__setattr__(self, "unlock_script", bytes(self.unlock_script))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tx_hash": self.tx_hash,
            "output_index": self.output_index,
            "unlock_script": self.unlock_script.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TxInput":
        return cls(
            tx_hash=d["tx_hash"],
            output_index=d["output_index"],
            unlock_script=bytes.fromhex(d["unlock_script"]),
        )


# ---------------------------------------------------------------------------
# TxOutput
# ---------------------------------------------------------------------------

@dataclass
class TxOutput:
    """
    A transaction output that locks an amount of N to a script condition.

    Fields:
        amount: Value in nanoN.
        lock_script: ScriptPubKey bytes defining spending conditions.
        asset_type: Asset category (0 = N currency).
        metadata: Additional constraints (timelock, multisig threshold, etc.).
    """
    amount: int = 0
    lock_script: bytes = field(default_factory=bytes)
    asset_type: int = ASSET_TYPE_N_CURRENCY
    metadata: bytes = field(default_factory=bytes)

    def __post_init__(self) -> None:
        if not isinstance(self.lock_script, bytes):
            object.__setattr__(self, "lock_script", bytes(self.lock_script))
        if not isinstance(self.metadata, bytes):
            object.__setattr__(self, "metadata", bytes(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "amount": self.amount,
            "lock_script": self.lock_script.hex(),
            "asset_type": self.asset_type,
            "metadata": self.metadata.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TxOutput":
        return cls(
            amount=d["amount"],
            lock_script=bytes.fromhex(d["lock_script"]),
            asset_type=d["asset_type"],
            metadata=bytes.fromhex(d["metadata"]),
        )


# ---------------------------------------------------------------------------
# ZKProof (optional attachment)
# ---------------------------------------------------------------------------

@dataclass
class ZKProof:
    """Zero-knowledge proof attachment for shielded transactions."""
    proof_data: bytes = field(default_factory=bytes)
    public_inputs: bytes = field(default_factory=bytes)
    circuit_id: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "proof_data": self.proof_data.hex(),
            "public_inputs": self.public_inputs.hex(),
            "circuit_id": self.circuit_id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ZKProof":
        return cls(
            proof_data=bytes.fromhex(d["proof_data"]),
            public_inputs=bytes.fromhex(d["public_inputs"]),
            circuit_id=d["circuit_id"],
        )


# ---------------------------------------------------------------------------
# Transaction
# ---------------------------------------------------------------------------

@dataclass
class Transaction:
    """
    Full transaction structure for BCS.

    Fields:
        version: Protocol version of the tx format.
        tx_type: Transaction semantic category (see TxType).
        inputs: List of inputs referencing previous UTXOs.
        outputs: List of outputs creating new UTXOs.
        lock_time: Earliest time/block the tx can be mined (0 = immediate).
        extra: Type-specific auxiliary data (governance params, identity docs, …).
        witnesses: List of witness bytes (signatures, redeem scripts, etc.).
        zk_proof: Optional ZK proof for shielded transactions.
    """
    version: int = 1
    tx_type: TxType = TxType.TRANSFER
    inputs: list[TxInput] = field(default_factory=list)
    outputs: list[TxOutput] = field(default_factory=list)
    lock_time: int = 0
    extra: bytes = field(default_factory=bytes)
    witnesses: list[bytes] = field(default_factory=list)
    zk_proof: Optional[ZKProof] = None

    def __post_init__(self) -> None:
        if isinstance(self.tx_type, int):
            object.__setattr__(self, "tx_type", TxType(self.tx_type))
        if not isinstance(self.extra, bytes):
            object.__setattr__(self, "extra", bytes(self.extra))

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    def _canonical_bytes(self) -> bytes:
        """Return deterministic raw bytes for hashing (excludes witnesses, unlock_scripts & zk_proof)."""
        # Inputs without unlock_script (like Bitcoin's sighash)
        inputs_canon = [
            {"tx_hash": i.tx_hash, "output_index": i.output_index}
            for i in self.inputs
        ]
        payload = {
            "version": self.version,
            "tx_type": int(self.tx_type),
            "inputs": inputs_canon,
            "outputs": [o.to_dict() for o in self.outputs],
            "lock_time": self.lock_time,
            "extra": self.extra.hex(),
        }
        # Sort keys for determinism
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def hash(self) -> str:
        """Return SHA3-256 hex digest of the transaction (txid)."""
        return hashlib.sha3_256(self._canonical_bytes()).hexdigest()

    # ------------------------------------------------------------------
    # Signature helpers
    # ------------------------------------------------------------------

    def signing_hash(self) -> bytes:
        """Return the 32-byte digest that signers commit to."""
        return hashlib.sha3_256(self._canonical_bytes()).digest()

    def verify_signature(
        self,
        pubkey_bytes: bytes,
        signature: bytes,
        sighash: Optional[bytes] = None,
    ) -> bool:
        """
        Verify an ECDSA (secp256k1) signature against this transaction.

        Args:
            pubkey_bytes: 33-byte compressed or 65-byte uncompressed public key.
            signature: DER-encoded ECDSA signature.
            sighash: Optional override hash; defaults to self.signing_hash().
        """
        try:
            vk = VerifyingKey.from_string(pubkey_bytes, curve=SECP256k1)
            digest = sighash if sighash is not None else self.signing_hash()
            return vk.verify_digest(signature, digest, sigdecode=lambda sig, order: __import__("ecdsa").util.sigdecode_der(sig, order))
        except (BadSignatureError, Exception):
            return False

    # ------------------------------------------------------------------
    # Dict serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "version": self.version,
            "tx_type": int(self.tx_type),
            "inputs": [i.to_dict() for i in self.inputs],
            "outputs": [o.to_dict() for o in self.outputs],
            "lock_time": self.lock_time,
            "extra": self.extra.hex(),
            "witnesses": [w.hex() for w in self.witnesses],
        }
        if self.zk_proof is not None:
            d["zk_proof"] = self.zk_proof.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Transaction":
        zk: Optional[ZKProof] = None
        if "zk_proof" in d:
            zk = ZKProof.from_dict(d["zk_proof"])
        return cls(
            version=d["version"],
            tx_type=TxType(d["tx_type"]),
            inputs=[TxInput.from_dict(i) for i in d["inputs"]],
            outputs=[TxOutput.from_dict(o) for o in d["outputs"]],
            lock_time=d["lock_time"],
            extra=bytes.fromhex(d["extra"]),
            witnesses=[bytes.fromhex(w) for w in d.get("witnesses", [])],
            zk_proof=zk,
        )

    def total_input_value(self) -> int:
        """Return the sum of input amounts (only meaningful when inputs are resolved)."""
        return sum(i.output_index for i in self.inputs)  # placeholder; real value comes from UTXO

    def total_output_value(self) -> int:
        """Return the sum of all output amounts."""
        return sum(o.amount for o in self.outputs)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import secrets

    # 1. Create a simple transfer tx
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = vk.to_string("compressed")

    tx = Transaction(
        version=1,
        tx_type=TxType.TRANSFER,
        inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
        outputs=[TxOutput(amount=1_000_000_000, lock_script=b"\x76\xa9" + b"\x00" * 20 + b"\x88\xac")],
    )

    txid = tx.hash()
    print("TxID:", txid)
    assert len(txid) == 64

    # 2. Sign and verify
    sighash = tx.signing_hash()
    sig = sk.sign_digest(sighash, sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order))
    ok = tx.verify_signature(pubkey, sig)
    print("Signature valid:", ok)
    assert ok

    # 3. Serialization round-trip
    tx2 = Transaction.from_dict(tx.to_dict())
    assert tx2.hash() == tx.hash()
    print("Round-trip OK")

    # 4. ZK proof tx
    zk_tx = Transaction(
        version=1,
        tx_type=TxType.TRANSFER,
        outputs=[TxOutput(amount=500_000_000)],
        zk_proof=ZKProof(proof_data=b"\x00\x01\x02", public_inputs=b"\xab\xcd", circuit_id=1),
    )
    zk_rt = Transaction.from_dict(zk_tx.to_dict())
    assert zk_rt.zk_proof is not None
    assert zk_rt.zk_proof.circuit_id == 1
    print("ZKProof round-trip OK")

    print("transaction.py self-test PASSED")
