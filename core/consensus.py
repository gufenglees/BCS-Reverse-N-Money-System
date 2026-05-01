"""
BCS Blockchain Core — PoA-BFT Consensus
=========================================
Proof-of-Authority with BFT-like finality for the BCS blockchain.

Key design points:
  • Round-robin block proposer: validator_for_height = height % len(validators)
  • 2/3 signature threshold for finality (CLASSIC BFT: n = 3f + 1)
  • 5-second block interval
  • ValidatorSet manages the authorized validator list

All cryptographic operations use ECDSA secp256k1 + SHA3-256.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from ecdsa import SECP256k1, BadSignatureError
from ecdsa.keys import SigningKey, VerifyingKey

from block import Block, BlockHeader, BlockBody, compute_merkle_root
from transaction import Transaction
from mempool import Mempool
from utxo import UTXOSet
from state import StateManager
from validator import TxValidator, BlockValidator, SystemParams, ValidationResult
from script import StandardScripts


# ---------------------------------------------------------------------------
# Validator info
# ---------------------------------------------------------------------------

@dataclass
class ValidatorInfo:
    """Metadata for a single authorized validator."""
    validator_id: int
    pubkey_hex: str           # Compressed secp256k1 pubkey
    name: str = ""
    weight: int = 1           # Voting weight (default 1)

    def pubkey_bytes(self) -> bytes:
        return bytes.fromhex(self.pubkey_hex)


# ---------------------------------------------------------------------------
# ValidatorSet
# ---------------------------------------------------------------------------

class ValidatorSet:
    """
    Manages the authorized validator list and proposer rotation.

    Provides:
      • proposer_for_height(height) -> ValidatorInfo
      • is_authorized(pubkey) -> bool
      • threshold() -> minimum signatures for finality
    """

    def __init__(self, validators: list[ValidatorInfo]) -> None:
        if not validators:
            raise ValueError("ValidatorSet cannot be empty")
        self._validators = validators
        self._pubkey_map: dict[str, ValidatorInfo] = {
            v.pubkey_hex: v for v in validators
        }

    @property
    def count(self) -> int:
        return len(self._validators)

    @property
    def total_weight(self) -> int:
        return sum(v.weight for v in self._validators)

    def threshold(self) -> int:
        """
        Return the minimum weight required for BFT finality.
        Classic formula: floor(2*n/3) + 1 for n validators of equal weight.
        """
        return (2 * self.total_weight) // 3 + 1

    def proposer_for_height(self, height: int) -> ValidatorInfo:
        """Return the validator scheduled to propose at *height*."""
        idx = height % self.count
        return self._validators[idx]

    def is_authorized(self, pubkey_hex: str) -> bool:
        return pubkey_hex in self._pubkey_map

    def get_by_pubkey(self, pubkey_hex: str) -> Optional[ValidatorInfo]:
        return self._pubkey_map.get(pubkey_hex)

    def all_pubkeys(self) -> list[str]:
        return list(self._pubkey_map.keys())

    def to_dict(self) -> dict[str, Any]:
        return {
            "validators": [
                {
                    "validator_id": v.validator_id,
                    "pubkey_hex": v.pubkey_hex,
                    "name": v.name,
                    "weight": v.weight,
                }
                for v in self._validators
            ],
            "threshold": self.threshold(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ValidatorSet":
        vals = [
            ValidatorInfo(
                validator_id=v["validator_id"],
                pubkey_hex=v["pubkey_hex"],
                name=v.get("name", ""),
                weight=v.get("weight", 1),
            )
            for v in d["validators"]
        ]
        return cls(vals)


# ---------------------------------------------------------------------------
# PoA-BFT Consensus
# ---------------------------------------------------------------------------

class PoABFTConsensus:
    """
    Proof-of-Authority consensus with BFT-like finality.

    Lifecycle:
      1. propose_block()    — scheduled validator creates a candidate block.
      2. validate_block()   — all validators verify the candidate.
      3. commit_block()     — collect signatures, finalize when threshold met.
    """

    BLOCK_INTERVAL_MS: int = 5_000
    CLOCK_DRIFT_TOLERANCE_MS: int = 10_000

    def __init__(
        self,
        validator_set: ValidatorSet,
        mempool: Mempool,
        utxo_set: UTXOSet,
        state_manager: StateManager,
        params: SystemParams,
        block_store: Optional[Any] = None,
    ) -> None:
        self.validator_set = validator_set
        self.mempool = mempool
        self.utxo_set = utxo_set
        self.state_manager = state_manager
        self.params = params
        self.block_store = block_store

        self.tx_validator = TxValidator()
        self.block_validator = BlockValidator(
            self.tx_validator,
            clock_drift_tolerance_ms=self.CLOCK_DRIFT_TOLERANCE_MS,
        )

        # Tracking
        self.chain_tip: Optional[Block] = None
        self.pending_signatures: dict[str, dict[str, bytes]] = {}

    # ------------------------------------------------------------------
    # Propose
    # ------------------------------------------------------------------

    def propose_block(
        self,
        validator_id: int,
        height: int,
        privkey: bytes,
        prev_block: Optional[Block] = None,
    ) -> Block:
        """
        Create a candidate block.

        Args:
            validator_id: ID of the proposing validator (must match rotation).
            height: Block height to propose.
            privkey: Raw private key bytes for signing.
            prev_block: Previous block (tip). If None, uses self.chain_tip.

        Raises:
            PermissionError: If it's not this validator's turn.
        """
        expected = self.validator_set.proposer_for_height(height)
        if expected.validator_id != validator_id:
            raise PermissionError(
                f"Not my turn: expected validator {expected.validator_id}, got {validator_id}"
            )

        previous = prev_block or self.chain_tip
        if previous is None and height != 0:
            raise ValueError("Missing previous block for non-genesis proposal")

        prev_hash = previous.hash if previous else "0" * 64

        # Select transactions from mempool
        txs = self.mempool.select_transactions(
            max_count=self.params.max_tx_per_block,
            max_size_bytes=self.params.max_block_size,
        )

        # Build header
        header = BlockHeader(
            version=1,
            prev_block_hash=prev_hash,
            merkle_root_tx=compute_merkle_root([tx.hash() for tx in txs]),
            merkle_root_utxo=self.utxo_set.merkle_root,
            merkle_root_identity="0" * 64,  # placeholder
            timestamp=int(time.time() * 1000),
            height=height,
            tx_count=len(txs),
            validator_pubkey=expected.pubkey_hex,
        )
        block = Block(header=header, body=BlockBody(transactions=txs))

        # Sign header
        sk = SigningKey.from_string(privkey, curve=SECP256k1)
        sig = sk.sign_digest(
            block.header.signing_hash(),
            sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order),
        )
        block.header.signature = sig.hex()

        return block

    # ------------------------------------------------------------------
    # Validate
    # ------------------------------------------------------------------

    def validate_block(
        self,
        block: Block,
        previous_block: Optional[Block] = None,
    ) -> ValidationResult:
        """
        Validate a candidate block.

        Checks: proposer rotation, timestamp, signature, Merkle root,
        tx validity, UTXO transition.
        """
        prev = previous_block or self.chain_tip

        # 1. Proposer rotation
        expected = self.validator_set.proposer_for_height(block.header.height)
        if block.header.validator_pubkey != expected.pubkey_hex:
            return ValidationResult.fail(
                f"Wrong validator for height {block.header.height}: expected {expected.pubkey_hex[:16]}..."
            )

        # 2. Timestamp bounds
        now_ms = int(time.time() * 1000)
        if block.header.timestamp > now_ms + self.CLOCK_DRIFT_TOLERANCE_MS:
            return ValidationResult.fail("Future timestamp")
        if prev is not None and block.header.timestamp < prev.header.timestamp:
            return ValidationResult.fail("Timestamp regression")

        # 3. Delegate to BlockValidator
        return self.block_validator.validate_block(
            block=block,
            previous_block=prev,
            utxo_set=self.utxo_set,
            state_manager=self.state_manager,
            params=self.params,
            expected_validator_pubkey=expected.pubkey_bytes(),
        )

    # ------------------------------------------------------------------
    # Commit / Finality
    # ------------------------------------------------------------------

    def commit_block(self, block: Block) -> bool:
        """
        Attempt to finalize a block.

        The block must already carry the proposer's signature.
        Additional validator signatures are tracked in ``pending_signatures``.

        Returns:
            True if the block reached finality threshold and was committed.
        """
        block_hash = block.hash
        sigs = self.pending_signatures.setdefault(block_hash, {})

        # Include proposer signature
        if block.header.signature:
            sigs[block.header.validator_pubkey] = bytes.fromhex(block.header.signature)

        # Check BFT threshold
        total_weight = sum(
            self.validator_set.get_by_pubkey(pk).weight
            for pk in sigs.keys()
            if self.validator_set.is_authorized(pk)
        )
        if total_weight < self.validator_set.threshold():
            return False

        # Finalize
        self.chain_tip = block
        if self.block_store is not None:
            self.block_store.save_block(block)

        # Apply to UTXO set
        self.utxo_set.apply_block(block)

        # Update derived state
        for tx in block.body.transactions:
            # Remove confirmed txs from mempool
            self.mempool.remove_tx(tx.hash())
            # Update account activity (simplified)
            # Full state rebuild would be done by a currency module callback

        # Clear pending signatures for this block
        self.pending_signatures.pop(block_hash, None)
        return True

    def add_signature(self, block_hash: str, pubkey_hex: str, signature: bytes) -> None:
        """Add a validator signature for a pending block."""
        if not self.validator_set.is_authorized(pubkey_hex):
            raise PermissionError("Unauthorized validator signature")
        self.pending_signatures.setdefault(block_hash, {})[pubkey_hex] = signature

    def get_signature_count(self, block_hash: str) -> int:
        """Return the number of distinct signatures collected for a block."""
        return len(self.pending_signatures.get(block_hash, {}))

    def is_finalized(self, block_hash: str) -> bool:
        """Check whether a block has collected enough signatures for finality."""
        sigs = self.pending_signatures.get(block_hash, {})
        weight = sum(
            self.validator_set.get_by_pubkey(pk).weight
            for pk in sigs.keys()
            if self.validator_set.is_authorized(pk)
        )
        return weight >= self.validator_set.threshold()

    # ------------------------------------------------------------------
    # Genesis helper
    # ------------------------------------------------------------------

    @staticmethod
    def create_genesis_block(
        validator_pubkey_hex: str,
        alloc_transactions: Optional[list[Transaction]] = None,
    ) -> Block:
        """Create a genesis block (height=0)."""
        txs = alloc_transactions or []
        header = BlockHeader(
            version=1,
            prev_block_hash="0" * 64,
            merkle_root_tx=compute_merkle_root([tx.hash() for tx in txs]),
            merkle_root_utxo="0" * 64,
            merkle_root_identity="0" * 64,
            timestamp=int(time.time() * 1000),
            height=0,
            tx_count=len(txs),
            validator_pubkey=validator_pubkey_hex,
            signature="",  # genesis block unsigned
        )
        return Block(header=header, body=BlockBody(transactions=txs))


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from ecdsa.keys import SigningKey
    from transaction import TxInput, TxOutput, TxType
    from utxo import UTXO
    from script import StandardScripts
    import hashlib

    # Setup 3 validators
    keys = [SigningKey.generate(curve=SECP256k1) for _ in range(3)]
    validators = [
        ValidatorInfo(
            validator_id=i,
            pubkey_hex=k.get_verifying_key().to_string("compressed").hex(),
            name=f"val{i}",
        )
        for i, k in enumerate(keys)
    ]
    vset = ValidatorSet(validators)
    assert vset.threshold() == 3  # 2*3/3 + 1 = 3 (all 3 for small set)
    print("ValidatorSet threshold:", vset.threshold())

    # Check rotation
    for h in range(5):
        prop = vset.proposer_for_height(h)
        print(f"  Height {h} -> validator {prop.validator_id}")

    # Setup consensus
    mempool = Mempool()
    utxo_set = UTXOSet()
    state_mgr = StateManager()
    params = SystemParams(max_tx_per_block=100, max_block_size=500_000)
    consensus = PoABFTConsensus(vset, mempool, utxo_set, state_mgr, params)

    # Fund a UTXO so we can build a real tx
    pk = keys[0].get_verifying_key().to_string("compressed")
    pk_hash = hashlib.new("ripemd160", hashlib.sha256(pk).digest()).digest()
    lock = StandardScripts.p2pkh_lock_script(pk_hash)
    utxo_set.add(UTXO(tx_hash="a" * 64, output_index=0, amount=1_000_000_000, lock_script=lock))

    # Build a signed tx and add to mempool
    tx = Transaction(
        inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
        outputs=[TxOutput(amount=900_000_000, lock_script=lock)],
    )
    sighash = tx.signing_hash()
    sig = keys[0].sign_digest(sighash, sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order))
    tx.inputs[0].unlock_script = StandardScripts.p2pkh_unlock_script(sig, pk)
    mempool.add_tx(tx, fee=100_000_000)

    # 1. Genesis
    genesis = PoABFTConsensus.create_genesis_block(validators[0].pubkey_hex)
    consensus.chain_tip = genesis
    print("Genesis hash:", genesis.hash[:16], "...")

    # 2. Propose block at height=1 (validator 1's turn: 1 % 3 = 1)
    block1 = consensus.propose_block(
        validator_id=1,
        height=1,
        privkey=keys[1].to_string(),
        prev_block=genesis,
    )
    print("Proposed block 1, txs:", len(block1.body.transactions))

    # 3. Validate
    res = consensus.validate_block(block1, genesis)
    assert res.valid, f"Block validation failed: {res.reason}"
    print("Block 1 validation OK")

    # 4. Collect signatures & commit
    # Sign with all 3 validators
    for k in keys:
        vk = k.get_verifying_key()
        pk_hex = vk.to_string("compressed").hex()
        sig = k.sign_digest(
            block1.header.signing_hash(),
            sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order),
        )
        consensus.add_signature(block1.hash, pk_hex, sig)

    assert consensus.get_signature_count(block1.hash) == 3
    print("Signatures collected:", consensus.get_signature_count(block1.hash))

    ok = consensus.commit_block(block1)
    assert ok
    assert consensus.chain_tip.hash == block1.hash
    print("Block 1 committed, new tip:", consensus.chain_tip.hash[:16], "...")

    # 5. Wrong validator should be rejected
    try:
        consensus.propose_block(validator_id=0, height=2, privkey=keys[0].to_string())
        # height 2 -> validator 2, so 0 should raise
        raise AssertionError("Should have raised PermissionError")
    except PermissionError:
        print("Wrong validator correctly rejected")

    # 6. Serialization
    vset_dict = vset.to_dict()
    vset2 = ValidatorSet.from_dict(vset_dict)
    assert vset2.count == vset.count
    assert vset2.threshold() == vset.threshold()
    print("ValidatorSet serialization OK")

    print("consensus.py self-test PASSED")
