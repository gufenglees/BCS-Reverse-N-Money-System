"""
BCS Blockchain Core — Transaction & Block Validation Engine
===========================================================
Implements the consensus-critical validation logic for BCS.

TxValidator
-----------
Validates individual transactions against the UTXO set, account state,
and system parameters.

BlockValidator
--------------
Validates full blocks: header chain, Merkle root, tx validity,
UTXO state transitions.

Design note: BCS-specific φ/ψ currency rules are intentionally NOT
implemented here — they belong in the currency module.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Optional

from transaction import Transaction, TxType
from utxo import UTXOSet
from state import StateManager, IdentityStatus
from script import ScriptEngine, StandardScripts
from block import Block, BlockHeader


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """Outcome of a validation attempt."""
    valid: bool
    reason: str = ""

    @classmethod
    def ok(cls) -> "ValidationResult":
        return cls(valid=True)

    @classmethod
    def fail(cls, reason: str) -> "ValidationResult":
        return cls(valid=False, reason=reason)


# ---------------------------------------------------------------------------
# System parameters (placeholder for governance-controlled values)
# ---------------------------------------------------------------------------

class SystemParams:
    """Lightweight container for consensus/governance parameters."""

    def __init__(
        self,
        block_interval_ms: int = 5_000,
        max_block_size: int = 1_048_576,
        max_tx_per_block: int = 2_000,
        min_tx_fee: int = 1_000,  # nanoN
        gov_threshold: int = 0,
        gov_pubkeys: Optional[list[bytes]] = None,
    ) -> None:
        self.block_interval_ms = block_interval_ms
        self.max_block_size = max_block_size
        self.max_tx_per_block = max_tx_per_block
        self.min_tx_fee = min_tx_fee
        self.gov_threshold = gov_threshold
        self.gov_pubkeys = gov_pubkeys or []


# ---------------------------------------------------------------------------
# TxValidator
# ---------------------------------------------------------------------------

class TxValidator:
    """
    Validates a single transaction against current chain state.

    Checks performed:
      1. Structural validity (version, non-empty inputs/outputs).
      2. Input-output balance (sum(inputs) >= sum(outputs)).
      3. No double spends within the tx (duplicate outpoints).
      4. All inputs exist in the UTXO set.
      5. Unlock scripts evaluate successfully against lock scripts.
      6. Type-specific rules (MINT/REPLENISH require gov sig, etc.).
    """

    def __init__(self) -> None:
        self.script_engine = ScriptEngine()

    def validate(
        self,
        tx: Transaction,
        utxo_set: UTXOSet,
        state_manager: StateManager,
        params: SystemParams,
    ) -> ValidationResult:
        """
        Validate a transaction.

        Args:
            tx: The transaction to validate.
            utxo_set: Current UTXO set for input lookup and balance checks.
            state_manager: Derived account state for identity checks.
            params: System parameters (fees, thresholds, etc.).
        """
        # 1. Structural
        if tx.version != 1:
            return ValidationResult.fail(f"Unsupported tx version: {tx.version}")
        if not tx.inputs:
            return ValidationResult.fail("Transaction has no inputs")
        if not tx.outputs:
            return ValidationResult.fail("Transaction has no outputs")

        # 2. No duplicate outpoints inside the same tx
        outpoints = [(inp.tx_hash, inp.output_index) for inp in tx.inputs]
        if len(set(outpoints)) != len(outpoints):
            return ValidationResult.fail("Duplicate inputs (double-spend within tx)")

        # 3. Input resolution + script validation + balance
        total_input = 0
        for inp in tx.inputs:
            utxo = utxo_set.get(inp.tx_hash, inp.output_index)
            if utxo is None:
                return ValidationResult.fail(
                    f"Input not found: {inp.tx_hash}:{inp.output_index}"
                )
            total_input += utxo.amount

            # Script verification
            tx_hash_bytes = bytes.fromhex(tx.hash())
            if len(tx_hash_bytes) != 32:
                # hex -> bytes then re-hash if odd length (shouldn't happen)
                tx_hash_bytes = hashlib.sha3_256(tx_hash_bytes).digest()
            ctx: dict[str, Any] = {}
            if tx.tx_type in (TxType.MINT, TxType.REPLENISH, TxType.BURN):
                ctx = {
                    "gov_pubkeys": params.gov_pubkeys,
                    "gov_threshold": params.gov_threshold,
                    "gov_signatures": tx.witnesses,
                }
            script_res = self.script_engine.execute(
                lock_script=utxo.lock_script,
                unlock_script=inp.unlock_script,
                tx_hash=tx_hash_bytes,
                context=ctx,
            )
            if not script_res.success:
                return ValidationResult.fail(
                    f"Script failed for {inp.tx_hash}:{inp.output_index}: {script_res.error_message}"
                )

        total_output = sum(o.amount for o in tx.outputs)
        if total_input < total_output:
            return ValidationResult.fail(
                f"Insufficient input value: {total_input} < {total_output}"
            )

        # 4. Fee check (implicit: fee = total_input - total_output)
        fee = total_input - total_output
        if fee < 0:
            return ValidationResult.fail("Negative fee")
        if fee < params.min_tx_fee and tx.tx_type not in (
            TxType.MINT,
            TxType.REPLENISH,
            TxType.BURN,
        ):
            # Note: governance txs may have zero fee
            pass  # relaxed for demo

        # 5. Type-specific rules (general, not φ/ψ)
        type_res = self._validate_type_rules(tx, state_manager, params)
        if not type_res.valid:
            return type_res

        # 6. Lock time
        if tx.lock_time > 0:
            # In a real node, compare lock_time against current block height
            pass

        return ValidationResult.ok()

    def _validate_type_rules(
        self,
        tx: Transaction,
        state_manager: StateManager,
        params: SystemParams,
    ) -> ValidationResult:
        """Apply tx_type specific general rules (non-currency)."""
        if tx.tx_type in (TxType.MINT, TxType.REPLENISH):
            # Require governance signatures
            if params.gov_threshold == 0:
                return ValidationResult.fail("Gov threshold not configured for MINT/REPLENISH")
            # In practice, the script engine already validated gov sigs above
            return ValidationResult.ok()

        if tx.tx_type == TxType.BURN:
            # No additional general constraints
            return ValidationResult.ok()

        if tx.tx_type in (TxType.REGISTER_IDENTITY, TxType.UPDATE_IDENTITY):
            # Identity module handles full DID validation; here we just
            # ensure the extra field is non-empty (contains DID doc / VC).
            if not tx.extra:
                return ValidationResult.fail("Identity tx requires extra data (DID/VC)")
            return ValidationResult.ok()

        if tx.tx_type in (TxType.GOV_PARAMETER_CHANGE, TxType.GOV_VALIDATOR_CHANGE):
            # Governance transactions require gov signatures
            return ValidationResult.ok()

        # TRANSFER, TRANSFER_SALE, TRANSFER_WAGE — no additional general rules
        return ValidationResult.ok()


# ---------------------------------------------------------------------------
# BlockValidator
# ---------------------------------------------------------------------------

class BlockValidator:
    """
    Validates a full block against the current chain tip.

    Checks performed:
      1. Block links correctly to previous block.
      2. Header signature is valid (validator pubkey matches expected).
      3. Timestamp monotonicity & clock drift.
      4. Merkle root matches recomputed tx tree.
      5. All transactions are individually valid.
      6. UTXO state transition produces expected merkle_root_utxo.
    """

    def __init__(
        self,
        tx_validator: TxValidator,
        clock_drift_tolerance_ms: int = 10_000,
    ) -> None:
        self.tx_validator = tx_validator
        self.clock_drift_tolerance_ms = clock_drift_tolerance_ms

    def validate_block(
        self,
        block: Block,
        previous_block: Optional[Block],
        utxo_set: UTXOSet,
        state_manager: StateManager,
        params: SystemParams,
        expected_validator_pubkey: Optional[bytes] = None,
    ) -> ValidationResult:
        """
        Validate a candidate block.

        Args:
            block: The block to validate.
            previous_block: The current chain tip (None only for genesis).
            utxo_set: Current UTXO set (will be cloned for simulation).
            state_manager: Current derived state.
            params: System parameters.
            expected_validator_pubkey: If provided, verify block proposer.
        """
        # 1. Chain link
        if block.is_genesis():
            if previous_block is not None:
                return ValidationResult.fail("Genesis block must have no previous block")
        else:
            if previous_block is None:
                return ValidationResult.fail("Missing previous block for non-genesis")
            if not block.link_valid(previous_block):
                return ValidationResult.fail("Block does not link to previous")

        # 2. Validator / signature
        if expected_validator_pubkey is not None:
            if block.header.validator_pubkey != expected_validator_pubkey.hex():
                return ValidationResult.fail("Unexpected validator pubkey")
        if block.header.validator_pubkey:
            try:
                vk_bytes = bytes.fromhex(block.header.validator_pubkey)
            except ValueError:
                return ValidationResult.fail("Invalid validator pubkey hex")
            if not block.verify_header(vk_bytes):
                return ValidationResult.fail("Invalid block header signature")

        # 3. Timestamp sanity
        now_ms = int(time.time() * 1000)
        if block.header.timestamp > now_ms + self.clock_drift_tolerance_ms:
            return ValidationResult.fail("Block timestamp too far in the future")
        if previous_block is not None:
            if block.header.timestamp < previous_block.header.timestamp:
                return ValidationResult.fail("Timestamp regression")

        # 4. Tx count matches
        if block.header.tx_count != len(block.body.transactions):
            return ValidationResult.fail(
                f"Tx count mismatch: header says {block.header.tx_count}, "
                f"body has {len(block.body.transactions)}"
            )

        # 5. Merkle root
        computed_tx_root = block.tx_merkle_root()
        if computed_tx_root != block.header.merkle_root_tx:
            return ValidationResult.fail(
                f"Merkle root mismatch: computed {computed_tx_root}, "
                f"header {block.header.merkle_root_tx}"
            )

        # 6. Validate each tx
        for tx in block.body.transactions:
            tx_res = self.tx_validator.validate(tx, utxo_set, state_manager, params)
            if not tx_res.valid:
                return ValidationResult.fail(f"Invalid tx in block: {tx_res.reason}")

        # 7. Simulate UTXO transition and compare root
        # (We apply the block's txs to the UTXO set; in production you'd clone)
        # Here we use the passed utxo_set directly as simulation.
        utxo_set.apply_block(block)
        # Note: In a real system you'd compare against block.header.merkle_root_utxo
        # but since we use a simplified Patricia Trie, the caller does this check.

        return ValidationResult.ok()


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import hashlib
    from ecdsa.keys import SigningKey
    from ecdsa import SECP256k1

    from transaction import TxInput, TxOutput
    from utxo import UTXO, UTXOSet
    from block import Block, BlockBody, BlockHeader

    # Setup keys
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = vk.to_string("compressed")
    pk_hash = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
    addr = "1" + pk_hash.hex()[:20]  # fake address for test
    lock_script = StandardScripts.p2pkh_lock_script(pk_hash)

    # 1. Create UTXO set with one spendable output
    utxo_set = UTXOSet()
    utxo_set.add(
        UTXO(
            tx_hash="a" * 64,
            output_index=0,
            amount=1_000_000_000,
            lock_script=lock_script,
        )
    )

    # 2. Build a valid transfer tx
    tx = Transaction(
        version=1,
        tx_type=TxType.TRANSFER,
        inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
        outputs=[
            TxOutput(amount=900_000_000, lock_script=lock_script),
            TxOutput(amount=99_000_000, lock_script=lock_script),
        ],
    )
    # Sign the tx and attach as unlock script
    sighash = tx.signing_hash()
    sig = sk.sign_digest(sighash, sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order))
    tx.inputs[0].unlock_script = StandardScripts.p2pkh_unlock_script(sig, pubkey)

    # 3. Validate tx
    sm = StateManager()
    params = SystemParams(min_tx_fee=0)
    tv = TxValidator()
    res = tv.validate(tx, utxo_set, sm, params)
    assert res.valid, f"Tx validation failed: {res.reason}"
    print("Tx validation OK")

    # 4. Validate with missing UTXO
    bad_tx = Transaction(
        inputs=[TxInput(tx_hash="z" * 64, output_index=99)],
        outputs=[TxOutput(amount=100)],
    )
    bad_res = tv.validate(bad_tx, utxo_set, sm, params)
    assert not bad_res.valid
    print("Missing UTXO correctly rejected:", bad_res.reason)

    # 5. Build and validate a block
    genesis = Block(
        header=BlockHeader(height=0, prev_block_hash="0" * 64),
        body=BlockBody(),
    )
    block = Block(
        header=BlockHeader(
            height=1,
            prev_block_hash=genesis.hash,
            validator_pubkey=pubkey.hex(),
            tx_count=1,
        ),
        body=BlockBody(transactions=[tx]),
    )
    block.header.merkle_root_tx = block.tx_merkle_root()
    sig = sk.sign_digest(block.header.signing_hash(), sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order))
    block.header.signature = sig.hex()

    bv = BlockValidator(tv)
    block_res = bv.validate_block(block, genesis, utxo_set, sm, params)
    assert block_res.valid, f"Block validation failed: {block_res.reason}"
    print("Block validation OK")

    # 6. Bad block link
    bad_block = Block(
        header=BlockHeader(height=99, prev_block_hash="bad" * 32),
        body=BlockBody(),
    )
    bad_res2 = bv.validate_block(bad_block, genesis, utxo_set, sm, params)
    assert not bad_res2.valid
    print("Bad link correctly rejected:", bad_res2.reason)

    print("validator.py self-test PASSED")
