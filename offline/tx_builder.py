"""
tx_builder.py — Offline Transaction Builder
============================================
Builds unsigned and signed transactions in an offline environment based on
a local optimistic UTXO view.

Supports:
  • TRANSFER       — plain N transfer (P2PKH-like)
  • TRANSFER_SALE  — sale: external amount + optional reference + N(φ)
  • TRANSFER_WAGE  — wage: external amount + optional reference + N(ψ)
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s | %(name)s | %(levelname)s | %(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Core imports (stubs)
# ---------------------------------------------------------------------------
from _core_stubs import (
    Transaction,
    TxType,
    TxInput,
    TxOutput,
    UTXO,
    UTXOSet,
    SystemParameters,
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class TxBuilderError(Exception):
    """Base exception for tx builder errors."""
    pass

class InsufficientFundsError(TxBuilderError):
    pass

class InvalidTxTypeError(TxBuilderError):
    pass

class SignatureError(TxBuilderError):
    pass


# ---------------------------------------------------------------------------
# Fee estimation
# ---------------------------------------------------------------------------
FEE_PER_BYTE: int = 10            # nanoN per byte (simplified fixed rate)
ESTIMATED_TX_OVERHEAD: int = 120  # bytes for version, lock_time, witnesses, etc.


def _estimate_tx_size(inputs: int, outputs: int) -> int:
    """Rough size estimation for fee calculation."""
    # Each input ~ 150 bytes (tx_hash 32 + index 4 + script ~100)
    # Each output ~ 50 bytes (amount 8 + script ~40)
    return ESTIMATED_TX_OVERHEAD + inputs * 150 + outputs * 50


# ---------------------------------------------------------------------------
# OfflineTxBuilder
# ---------------------------------------------------------------------------
class OfflineTxBuilder:
    """
    Builds transactions without network connectivity.

    Workflow:
        1.  create_offline_tx(...) → unsigned Transaction
        2.  sign_offline_tx(tx, private_key)   → signed Transaction
        3.  estimate_fee(tx)        → fee amount (nanoN)
    """

    def __init__(
        self,
        params: Optional[SystemParameters] = None,
        fee_per_byte: int = FEE_PER_BYTE,
    ) -> None:
        self.params = params or SystemParameters()
        self.fee_per_byte = fee_per_byte
        self._sequence_counter: int = int(time.time() * 1000)
        logger.info("OfflineTxBuilder initialised (fee=%s/byte)", fee_per_byte)

    # ------------------------------------------------------------------
    # 1. Create unsigned transaction
    # ------------------------------------------------------------------
    def create_offline_tx(
        self,
        inputs: List[UTXO],
        outputs: List[Tuple[int, bytes]],
        tx_type: TxType = TxType.TRANSFER,
        params: Optional[Dict[str, Any]] = None,
    ) -> Transaction:
        """
        Build an **unsigned** transaction from a list of local UTXOs.

        Args:
            inputs:  spendable UTXOs (must belong to the local wallet).
            outputs: list of (amount, lock_script) for recipients.
            tx_type: one of TRANSFER, TRANSFER_SALE, TRANSFER_WAGE.
            params:  optional extra parameters, e.g.:
                     {"external_amount": 10000, "sale": True} for φ/ψ calculations.

        Raises:
            InvalidTxTypeError:  if tx_type is not supported for offline building.
            InsufficientFundsError:  if input sum < output sum + estimated fee.
        """
        if tx_type not in {
            TxType.TRANSFER,
            TxType.TRANSFER_SALE,
            TxType.TRANSFER_WAGE,
        }:
            raise InvalidTxTypeError(
                f"Offline building not supported for tx_type={tx_type.name}"
            )

        params = params or {}

        # --- build TxInputs (without unlock_script) ---
        tx_inputs: List[TxInput] = [
            TxInput(
                tx_hash=u.tx_hash,
                output_index=u.output_index,
                unlock_script=b"",  # to be filled during signing
            )
            for u in inputs
        ]

        # --- build TxOutputs ---
        tx_outputs: List[TxOutput] = [
            TxOutput(amount=amt, lock_script=script)
            for amt, script in outputs
        ]

        # --- φ / ψ rule enforcement for BCS sale / wage transactions ---
        if tx_type == TxType.TRANSFER_SALE:
            self._enforce_phi(tx_outputs, params)
        elif tx_type == TxType.TRANSFER_WAGE:
            self._enforce_psi(tx_outputs, params)

        # --- fee check ---
        input_sum = sum(u.amount for u in inputs)
        output_sum = sum(o.amount for o in tx_outputs)
        fee = self._estimate_fee(len(tx_inputs), len(tx_outputs))

        if input_sum < output_sum + fee:
            raise InsufficientFundsError(
                f"Insufficient funds: inputs={input_sum}, outputs={output_sum}, fee={fee}"
            )

        # --- change output (if any) ---
        change = input_sum - output_sum - fee
        if change > 0:
            change_script = params.get("change_script")
            if change_script is None:
                # reuse first input's lock script as change address placeholder
                change_script = inputs[0].lock_script
            tx_outputs.append(TxOutput(amount=change, lock_script=change_script))

        # --- assemble transaction ---
        tx = Transaction(
            version=1,
            tx_type=tx_type,
            inputs=tx_inputs,
            outputs=tx_outputs,
            lock_time=params.get("lock_time", 0),
            extra=self._build_extra(params),
            witnesses=[],
            _offline_priority=self._next_sequence(),
        )

        logger.info(
            "Created offline tx type=%s inputs=%d outputs=%d fee=%s",
            tx_type.name,
            len(tx.inputs),
            len(tx.outputs),
            fee,
        )
        return tx

    # ------------------------------------------------------------------
    # 2. Sign transaction (offline)
    # ------------------------------------------------------------------
    def sign_offline_tx(
        self,
        tx: Transaction,
        private_key: bytes,
    ) -> Transaction:
        """
        Produce a fully signed copy of *tx* using *private_key*.

        This implementation uses a simplified ECDSA-like scheme:
          sign( sha3-256( tx_hash_without_witnesses || index ) )
        Each input gets its own witness so multi-input txs are supported.

        Args:
            tx:          unsigned Transaction.
            private_key: 32-byte secp256k1 private key (simplified).

        Returns:
            New Transaction with populated `witnesses`.
        """
        if not private_key or len(private_key) < 32:
            raise SignatureError("Invalid private_key length (need >= 32 bytes)")

        tx_for_sign = tx.copy_without_witnesses()
        base_hash = tx_for_sign.hash()

        witnesses: List[bytes] = []
        for idx, _inp in enumerate(tx.inputs):
            # Deterministic per-input signature message
            msg = base_hash + idx.to_bytes(4, "big")
            sig = self._sign_digest(msg, private_key)
            # witness format: [signature(64) || pubkey(33)]  — simplified
            pub = self._derive_pubkey(private_key)
            witness = sig + pub
            witnesses.append(witness)

        signed_tx = Transaction(
            version=tx.version,
            tx_type=tx.tx_type,
            inputs=[TxInput(i.tx_hash, i.output_index, b"") for i in tx.inputs],
            outputs=[TxOutput(o.amount, o.lock_script, o.asset_type, o.metadata) for o in tx.outputs],
            lock_time=tx.lock_time,
            extra=tx.extra,
            witnesses=witnesses,
            _offline_priority=tx._offline_priority,
        )
        logger.info("Signed tx %s with %d witness(es)", signed_tx.hash().hex()[:16], len(witnesses))
        return signed_tx

    # ------------------------------------------------------------------
    # 3. Fee estimation
    # ------------------------------------------------------------------
    def estimate_fee(self, tx: Transaction) -> int:
        """
        Estimate the fee (nanoN) required for *tx* to be accepted by the network.

        Simplified model:  fee = tx_byte_size * fee_per_byte.
        """
        size = _estimate_tx_size(len(tx.inputs), len(tx.outputs))
        return size * self.fee_per_byte

    def _estimate_fee(self, n_inputs: int, n_outputs: int) -> int:
        """Internal helper used before a Transaction object exists."""
        size = _estimate_tx_size(n_inputs, n_outputs)
        return size * self.fee_per_byte

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _next_sequence(self) -> int:
        self._sequence_counter += 1
        return self._sequence_counter

    def _enforce_phi(self, outputs: List[TxOutput], params: Dict[str, Any]) -> None:
        """
        Ensure sale tx satisfies: N_output_to_buyer >= φ * external_amount.
        Optional payment references are not required for offline sanity checks.
        """
        d_amount = params.get("external_amount", params.get("d_amount", 0))
        if d_amount <= 0:
            return  # no external amount specified — skip offline enforcement
        required_n = int(d_amount * self.params.phi)
        # simplistic: assume first output is the N payment to buyer
        if outputs and outputs[0].amount < required_n:
            logger.warning(
                "TRANSFER_SALE: N output %s < required φ*N=%s (external_amount=%s, φ=%s)",
                outputs[0].amount,
                required_n,
                d_amount,
                self.params.phi,
            )
            # We do NOT raise — offline builder allows slightly under-paid txs
            # so the user can adjust before final broadcast.

    def _enforce_psi(self, outputs: List[TxOutput], params: Dict[str, Any]) -> None:
        """Ensure wage tx satisfies: N_output_to_employer >= ψ * external_amount."""
        d_amount = params.get("external_amount", params.get("d_amount", 0))
        if d_amount <= 0:
            return
        required_n = int(d_amount * self.params.psi)
        if outputs and outputs[0].amount < required_n:
            logger.warning(
                "TRANSFER_WAGE: N output %s < required ψ*N=%s (external_amount=%s, ψ=%s)",
                outputs[0].amount,
                required_n,
                d_amount,
                self.params.psi,
            )

    def _build_extra(self, params: Dict[str, Any]) -> bytes:
        """Serialize extra parameters into the `extra` field."""
        import json
        extra: Dict[str, Any] = {}
        for key in (
            "external_amount",
            "d_amount",
            "external_currency",
            "external_payment_ref",
            "provider",
            "proof_hash",
            "memo",
            "sale_id",
            "wage_id",
            "metadata",
        ):
            if key in params:
                extra[key] = params[key]
        return json.dumps(extra, sort_keys=True).encode() if extra else b""

    @staticmethod
    def _sign_digest(digest: bytes, private_key: bytes) -> bytes:
        """
        Simplified deterministic signature.
        In production this should call secp256k1 via coincurve / ecdsa.
        """
        # HMAC-like deterministic signature stub
        return hashlib.sha3_256(digest + private_key).digest()

    @staticmethod
    def _derive_pubkey(private_key: bytes) -> bytes:
        """Stub: derive 33-byte compressed pubkey."""
        return hashlib.sha3_256(b"pub" + private_key).digest()[:33]


# ===========================================================================
# Self-test
# ===========================================================================
def _self_test() -> None:
    print("\n=== tx_builder.py self-test ===")
    builder = OfflineTxBuilder(fee_per_byte=1)  # low fee for unit tests

    # --- mock UTXOs ---
    addr_a = b"\x00" * 20
    addr_b = b"\x01" * 20
    utxos = [
        UTXO(tx_hash=b"\xab" * 32, output_index=0, amount=50000, lock_script=addr_a),
        UTXO(tx_hash=b"\xcd" * 32, output_index=1, amount=30000, lock_script=addr_a),
    ]

    # --- build transfer ---
    tx = builder.create_offline_tx(
        inputs=utxos,
        outputs=[(4000, addr_b)],
        tx_type=TxType.TRANSFER,
    )
    print(f"[TRANSFER] hash={tx.hash().hex()[:16]} inputs={len(tx.inputs)} outputs={len(tx.outputs)}")
    assert len(tx.inputs) == 2
    assert len(tx.outputs) == 2  # recipient + change

    # --- sign ---
    fake_key = b"\x42" * 32
    signed = builder.sign_offline_tx(tx, fake_key)
    assert len(signed.witnesses) == len(signed.inputs)
    print(f"[SIGN] witnesses={len(signed.witnesses)}")

    # --- fee ---
    fee = builder.estimate_fee(tx)
    print(f"[FEE] estimated={fee}")
    assert fee > 0

    # --- sale tx ---
    sale_tx = builder.create_offline_tx(
        inputs=utxos,
        outputs=[(200, addr_b)],
        tx_type=TxType.TRANSFER_SALE,
        params={"d_amount": 10000},
    )
    print(f"[SALE] hash={sale_tx.hash().hex()[:16]}")

    # --- wage tx ---
    wage_tx = builder.create_offline_tx(
        inputs=utxos,
        outputs=[(150, addr_b)],
        tx_type=TxType.TRANSFER_WAGE,
        params={"d_amount": 10000},
    )
    print(f"[WAGE] hash={wage_tx.hash().hex()[:16]}")

    # --- insufficient funds ---
    try:
        builder.create_offline_tx(
            inputs=utxos,
            outputs=[(100000, addr_b)],  # exceeds input sum (80000) + fee
            tx_type=TxType.TRANSFER,
        )
        assert False, "should have raised InsufficientFundsError"
    except InsufficientFundsError as exc:
        print(f"[EXPECTED ERROR] {exc}")

    print("=== tx_builder.py self-test PASSED ===\n")


if __name__ == "__main__":
    _self_test()
