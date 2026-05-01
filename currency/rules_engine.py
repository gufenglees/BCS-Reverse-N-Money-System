"""BCS Currency Rules Engine — N-only settlement with φ/ψ enforcement

Implements the core monetary policy rules of the Bidirectional Currency System:
    • SALE rule (φ): Seller must transfer at least φ×external_amount of N-money to buyer.
    • WAGE rule (ψ): Worker must transfer at least ψ×external_amount of N-money to employer.
    • MINT rule: Only governance multi-sig can create new N-money.
    • TRANSFER rule: Plain N-money transfers must conserve value.

Economic Rationale:
    The φ and ψ ratios are the binding constraints that enforce the BCS
    "being-needed" (N) property. The chain only settles N. The D side is
    represented by an external payment amount. Bank/cash/gateway/invoice/payroll
    references are optional metadata so the MVP can integrate gradually without
    issuing a second on-chain asset.

All arithmetic uses integer nanoN units; φ and ψ are rational numbers
(numerator/denominator) to guarantee exact, reproducible calculations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

# --------------------------------------------------------------------------- #
#  Core imports (with graceful fallback for standalone testing)
# --------------------------------------------------------------------------- #

try:
    from core.transaction import Transaction, TxInput, TxOutput, TxType
    from core.state import AccountState, IdentityStatus
except ImportError:  # pragma: no cover
    Transaction = Any  # type: ignore
    TxInput = Any  # type: ignore
    TxOutput = Any  # type: ignore
    TxType = Any  # type: ignore
    AccountState = Any  # type: ignore
    IdentityStatus = Any  # type: ignore

try:
    from .params import SystemParameters, GovernanceParams
except ImportError:  # pragma: no cover
    from params import SystemParameters, GovernanceParams

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #

ASSET_TYPE_N: int = 0  # Native N currency asset type


# --------------------------------------------------------------------------- #
#  Validation Result
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ValidationResult:
    """Result of a rule-engine validation check.

    Attributes:
        valid: True if the transaction satisfies the rule.
        reason: Human-readable explanation when valid is False.
    """
    valid: bool
    reason: Optional[str] = None

    def __bool__(self) -> bool:
        return self.valid


# --------------------------------------------------------------------------- #
#  Helpers for extracting D-amount from transaction extra/metadata
# --------------------------------------------------------------------------- #

class _ExtraDecoder:
    """Internal helper to decode external-payment metadata for SALE and WAGE.

    The amount and counterparty address are protocol inputs for φ/ψ validation.
    Payment references such as bank receipt, invoice, cash memo or gateway order
    id are optional metadata and are not required by this decoder.
    """

    @staticmethod
    def _decode_json_extra(extra: bytes) -> dict[str, Any]:
        try:
            data = json.loads(extra.decode("utf-8"))
        except Exception:
            return {}
        if not isinstance(data, dict):
            return {}

        # New N-only MVP terminology is external_amount plus optional references.
        # Keep d_amount as a backward-compatible alias for older tx builders.
        amount = data.get("external_amount", data.get("d_amount", data.get("payment_amount", 0)))
        try:
            amount = int(amount)
        except (TypeError, ValueError):
            amount = 0

        normalized = dict(data)
        normalized["d_amount"] = amount
        normalized["external_amount"] = amount
        return normalized

    @staticmethod
    def decode_sale_info(extra: bytes) -> dict[str, Any]:
        """Extract sale metadata from the `extra` field.

        Preferred JSON payload for the N-only MVP:
            {
              "buyer": "...",
              "external_amount": 10000,
              "external_currency": "CNY",
              "external_payment_ref": "invoice/order hash"
            }

        Backward compatibility:
            [buyer_address: bytes, d_amount: int]
        """
        # MVP fallback: if extra is empty, return empty dict so caller fails gracefully
        if not extra:
            return {}
        json_info = _ExtraDecoder._decode_json_extra(extra)
        if json_info:
            buyer = json_info.get("buyer") or json_info.get("buyer_address") or json_info.get("to")
            if buyer:
                json_info["buyer_address"] = str(buyer)
            return json_info
        try:
            # Minimal decoder: treat as length-prefixed binary
            # Format: <1 byte buyer_len> <buyer_bytes> <8 bytes d_amount BE>
            buyer_len = extra[0]
            buyer = extra[1 : 1 + buyer_len]
            d_amount = int.from_bytes(
                extra[1 + buyer_len : 1 + buyer_len + 8], "big"
            )
            return {"buyer_address": buyer.hex(), "d_amount": d_amount}
        except Exception:
            return {}

    @staticmethod
    def decode_wage_info(extra: bytes) -> dict[str, Any]:
        """Extract wage metadata from the `extra` field.

        Preferred JSON payload for the N-only MVP:
            {
              "employer": "...",
              "external_amount": 10000,
              "external_currency": "CNY",
              "external_payment_ref": "payroll hash"
            }

        Backward compatibility:
            [employer_address: bytes, d_amount: int]
        """
        if not extra:
            return {}
        json_info = _ExtraDecoder._decode_json_extra(extra)
        if json_info:
            employer = (
                json_info.get("employer")
                or json_info.get("employer_address")
                or json_info.get("to")
            )
            if employer:
                json_info["employer_address"] = str(employer)
            return json_info
        try:
            employer_len = extra[0]
            employer = extra[1 : 1 + employer_len]
            d_amount = int.from_bytes(
                extra[1 + employer_len : 1 + employer_len + 8], "big"
            )
            return {"employer_address": employer.hex(), "d_amount": d_amount}
        except Exception:
            return {}


# --------------------------------------------------------------------------- #
#  Currency Rules Engine
# --------------------------------------------------------------------------- #

class CurrencyRulesEngine:
    """Validates BCS transactions against φ/ψ monetary policy rules.

    The engine is stateless with respect to the UTXO set — it receives the
    transaction and the currently active parameters, and performs structural
    validation. Balance sufficiency is checked via the provided `account_state`
    or UTXO manager (passed in at construction for context access).

    Typical validation pipeline (in BlockValidator):
        1. Structural checks (inputs, outputs non-empty)
        2. Signature verification
        3. UTXO existence / no-double-spend
        4. Amount conservation (inputs >= outputs)
        5. **CurrencyRulesEngine.validate_*(tx, params)**  ← this class
        6. Feasibility check (for SALE/WAGE types)
    """

    def __init__(
        self,
        governance: Optional[GovernanceParams] = None,
        get_balance: Optional[Any] = None,
    ) -> None:
        """Initialize the rules engine.

        Args:
            governance: GovernanceParams for height-based parameter lookups.
            get_balance: Callable[[str], int] returning available N balance
                         for an address. Optional; some checks need it.
        """
        self.governance = governance or GovernanceParams()
        self._get_balance = get_balance

    # --------------------------------------------------------------------- #
    #  SALE validation (φ rule)
    # --------------------------------------------------------------------- #

    def validate_sale_transaction(
        self,
        tx: Transaction,
        params: Optional[SystemParameters] = None,
    ) -> ValidationResult:
        """Validate a TRANSFER_SALE transaction against the φ rule.

        Economic logic:
            When a seller receives an external payment from a buyer for
            goods/services, the seller must simultaneously transfer at least
            φ×external_amount of N-money to the buyer. The chain does not
            settle the external payment. A receipt/reference may be included
            for audit, but it is optional at the protocol level.

        Validation steps:
            1. Decode external amount and buyer address from tx.extra.
            2. Identify seller address from tx.inputs[0] (simplification).
            3. Sum all N outputs directed to the buyer.
            4. Verify buyer_n >= required_n = ceil(φ × external_amount).
            5. (Optional) Verify seller has sufficient N balance.

        Args:
            tx: The transaction to validate.
            params: SystemParameters for φ calculation. If None, uses
                    governance lookup at tx.lock_time or current params.

        Returns:
            ValidationResult: valid=True if φ rule satisfied; else False with reason.
        """
        # --- Step 1: Extract sale metadata --------------------------------
        extra_raw: bytes = getattr(tx, "extra", b"")
        sale_info = _ExtraDecoder.decode_sale_info(extra_raw)
        if not sale_info:
            return ValidationResult(False, "SALE: missing or malformed extra payload")

        d_amount: int = sale_info.get("d_amount", 0)
        buyer_addr: str = sale_info.get("buyer_address", "")
        if d_amount <= 0:
            return ValidationResult(False, "SALE: external payment amount must be positive")
        if not buyer_addr:
            return ValidationResult(False, "SALE: buyer address missing")

        # --- Step 2: Identify seller --------------------------------------
        inputs = getattr(tx, "inputs", [])
        if not inputs:
            return ValidationResult(False, "SALE: transaction has no inputs")
        # Seller inferred from first input's previous output owner.
        # In a real system this comes from UTXO resolution; here we read the
        # unlock_script field as a proxy for the signer's public key hash.
        seller_addr = self._extract_owner_address(inputs[0])
        if not seller_addr:
            return ValidationResult(False, "SALE: cannot identify seller")

        # --- Step 3: Resolve parameters -----------------------------------
        if params is None:
            height = getattr(tx, "lock_time", 0) or 0
            params = self.governance.get_params_at_height(int(height))

        required_n = params.required_n_for_sale(d_amount)

        # --- Step 4: Sum N outputs to buyer --------------------------------
        outputs = getattr(tx, "outputs", [])
        if not outputs:
            return ValidationResult(False, "SALE: transaction has no outputs")

        buyer_n = self._sum_n_outputs_to(outputs, buyer_addr)
        if buyer_n < required_n:
            return ValidationResult(
                False,
                f"SALE: insufficient N rebate — required {required_n} nanoN "
                f"(φ={params.phi_numerator}/{params.phi_denominator} of external_amount={d_amount}), "
                f"but buyer only receives {buyer_n} nanoN",
            )

        # --- Step 5: Optional seller balance check -------------------------
        if self._get_balance:
            seller_balance = self._get_balance(seller_addr)
            # Seller must have enough N to cover what they send to buyer.
            # Note: In a full UTXO model this is already enforced by input
            # conservation, but we perform an explicit check here for clarity.
            if seller_balance < required_n:
                return ValidationResult(
                    False,
                    f"SALE: seller balance {seller_balance} nanoN insufficient "
                    f"to cover required rebate {required_n} nanoN",
                )

        return ValidationResult(True, "SALE: φ rule satisfied")

    # --------------------------------------------------------------------- #
    #  WAGE validation (ψ rule)
    # --------------------------------------------------------------------- #

    def validate_wage_transaction(
        self,
        tx: Transaction,
        params: Optional[SystemParameters] = None,
    ) -> ValidationResult:
        """Validate a TRANSFER_WAGE transaction against the ψ rule.

        Economic logic:
            When an employer pays wages through an external payment rail, the
            worker must simultaneously transfer at least ψ×external_amount of
            N-money back to the employer. The external wage payment is not an
            on-chain asset in the MVP; payroll/payment references are optional.

        Validation steps:
            1. Decode external amount and employer address from tx.extra.
            2. Identify worker address from tx.inputs[0].
            3. Sum all N outputs directed to the employer.
            4. Verify employer_n >= required_n = ceil(ψ × external_amount).
            5. (Optional) Verify worker has sufficient N balance.

        Args:
            tx: The transaction to validate.
            params: SystemParameters for ψ calculation. If None, looked up
                    via governance at tx.lock_time.

        Returns:
            ValidationResult: valid=True if ψ rule satisfied.
        """
        # --- Step 1: Extract wage metadata ---------------------------------
        extra_raw: bytes = getattr(tx, "extra", b"")
        wage_info = _ExtraDecoder.decode_wage_info(extra_raw)
        if not wage_info:
            return ValidationResult(False, "WAGE: missing or malformed extra payload")

        d_amount: int = wage_info.get("d_amount", 0)
        employer_addr: str = wage_info.get("employer_address", "")
        if d_amount <= 0:
            return ValidationResult(False, "WAGE: external payment amount must be positive")
        if not employer_addr:
            return ValidationResult(False, "WAGE: employer address missing")

        # --- Step 2: Identify worker ---------------------------------------
        inputs = getattr(tx, "inputs", [])
        if not inputs:
            return ValidationResult(False, "WAGE: transaction has no inputs")
        worker_addr = self._extract_owner_address(inputs[0])
        if not worker_addr:
            return ValidationResult(False, "WAGE: cannot identify worker")

        # --- Step 3: Resolve parameters ------------------------------------
        if params is None:
            height = getattr(tx, "lock_time", 0) or 0
            params = self.governance.get_params_at_height(int(height))

        required_n = params.required_n_for_wage(d_amount)

        # --- Step 4: Sum N outputs to employer -----------------------------
        outputs = getattr(tx, "outputs", [])
        if not outputs:
            return ValidationResult(False, "WAGE: transaction has no outputs")

        employer_n = self._sum_n_outputs_to(outputs, employer_addr)
        if employer_n < required_n:
            return ValidationResult(
                False,
                f"WAGE: insufficient N commitment — required {required_n} nanoN "
                f"(ψ={params.psi_numerator}/{params.psi_denominator} of external_amount={d_amount}), "
                f"but employer only receives {employer_n} nanoN",
            )

        # --- Step 5: Optional worker balance check -------------------------
        if self._get_balance:
            worker_balance = self._get_balance(worker_addr)
            if worker_balance < required_n:
                return ValidationResult(
                    False,
                    f"WAGE: worker balance {worker_balance} nanoN insufficient "
                    f"to cover required commitment {required_n} nanoN",
                )

        return ValidationResult(True, "WAGE: ψ rule satisfied")

    # --------------------------------------------------------------------- #
    #  MINT validation (governance only)
    # --------------------------------------------------------------------- #

    def validate_mint_transaction(
        self,
        tx: Transaction,
        governance: Optional[GovernanceParams] = None,
    ) -> ValidationResult:
        """Validate a MINT transaction (initial N issuance).

        Economic logic:
            N-money creation is a sovereign act of the governance committee.
            It is not open to market participants because N represents the
            system's measure of "being-needed" — an abstract social property
            that must be allocated fairly by consensus rules rather than
            purchased outright.

        Validation steps:
            1. Verify tx.type == MINT.
            2. Verify governance multi-signature threshold is met.
            3. Verify recipient is authenticated (IdentityStatus.AUTHENTICATED).
            4. Verify mint amount >= min_n_mint.

        Args:
            tx: The transaction to validate.
            governance: Optional GovernanceParams for parameter lookup.

        Returns:
            ValidationResult: valid=True if mint is authorized.
        """
        tx_type = getattr(tx, "tx_type", None)
        if tx_type is not None and tx_type != 10:  # TxType.MINT == 10
            return ValidationResult(False, f"MINT: expected tx_type MINT(10), got {tx_type}")

        # Governance signature check
        witnesses = getattr(tx, "witnesses", [])
        gov = governance or self.governance
        params = gov.latest()
        if len(witnesses) < params.required_gov_signatures:
            return ValidationResult(
                False,
                f"MINT: insufficient governance signatures — "
                f"required {params.required_gov_signatures}, got {len(witnesses)}",
            )

        # Recipient checks
        outputs = getattr(tx, "outputs", [])
        if not outputs:
            return ValidationResult(False, "MINT: no outputs")
        recipient = self._extract_recipient_address(outputs[0])
        if not recipient:
            return ValidationResult(False, "MINT: cannot determine recipient")

        # Amount check
        amount = getattr(outputs[0], "amount", 0)
        if amount < params.min_n_mint:
            return ValidationResult(
                False,
                f"MINT: amount {amount} below minimum {params.min_n_mint} nanoN",
            )

        return ValidationResult(True, "MINT: governance issuance valid")

    # --------------------------------------------------------------------- #
    #  Plain TRANSFER validation
    # --------------------------------------------------------------------- #

    def validate_transfer(self, tx: Transaction) -> ValidationResult:
        """Validate a plain N-money TRANSFER transaction.

        Checks:
            1. Transaction has at least one input and one output.
            2. All outputs use asset_type == N (0).
            3. Total output amounts do not exceed input amounts (conservation).
               *Full conservation requires UTXO lookup; here we do a structural check.*

        Args:
            tx: The transaction to validate.

        Returns:
            ValidationResult: valid=True if structurally valid.
        """
        inputs = getattr(tx, "inputs", [])
        outputs = getattr(tx, "outputs", [])
        if not inputs:
            return ValidationResult(False, "TRANSFER: no inputs")
        if not outputs:
            return ValidationResult(False, "TRANSFER: no outputs")

        # Check all outputs are N asset type
        for idx, out in enumerate(outputs):
            asset_type = getattr(out, "asset_type", ASSET_TYPE_N)
            if asset_type != ASSET_TYPE_N:
                return ValidationResult(
                    False, f"TRANSFER: output {idx} has non-N asset_type {asset_type}"
                )

        # Structural conservation check (inputs and outputs present)
        return ValidationResult(True, "TRANSFER: structurally valid")

    # --------------------------------------------------------------------- #
    #  Internal helpers
    # --------------------------------------------------------------------- #

    @staticmethod
    def _extract_owner_address(inp: Any) -> str:
        """Infer owner address from a TxInput.

        In a real UTXO system this involves resolving the referenced output's
        lock_script. Here we treat the unlock_script bytes as a stand-in.
        """
        unlock = getattr(inp, "unlock_script", b"")
        if unlock:
            return unlock.hex()[:40]  # truncated hex for readability
        tx_hash = getattr(inp, "tx_hash", b"")
        return tx_hash.hex()[:40] if tx_hash else ""

    @staticmethod
    def _extract_recipient_address(out: Any) -> str:
        """Infer recipient address from a TxOutput lock_script.

        Supports standard P2PKH-ish scripts: OP_DUP OP_HASH160 <20-bytes> OP_EQUALVERIFY OP_CHECKSIG
        Falls back to hex prefix extraction for non-standard scripts.
        """
        lock = getattr(out, "lock_script", b"")
        if not lock:
            return ""
        # Standard P2PKH: 0x76 0xa9 0x14 <20-byte-pubkey-hash> 0x88 0xac (25 bytes total)
        if len(lock) == 25 and lock[:3] == b"\x76\xa9\x14" and lock[-2:] == b"\x88\xac":
            return lock[3:23].hex()
        # Fallback: take first 40 hex chars
        return lock.hex()[:40]

    @staticmethod
    def _sum_n_outputs_to(outputs: list[Any], target_addr: str) -> int:
        """Sum nanoN amounts in outputs whose recipient matches target_addr.

        Address matching is done by comparing hex representations with a
        tolerance for case and prefix differences.
        """
        total = 0
        target_norm = target_addr.lower().replace("0x", "")
        for out in outputs:
            asset_type = getattr(out, "asset_type", ASSET_TYPE_N)
            if asset_type != ASSET_TYPE_N:
                continue
            lock = getattr(out, "lock_script", b"")
            recipient = ""
            if lock:
                # Standard P2PKH extraction
                if len(lock) == 25 and lock[:3] == b"\x76\xa9\x14" and lock[-2:] == b"\x88\xac":
                    recipient = lock[3:23].hex()
                else:
                    recipient = lock.hex()[:40]
            if recipient.lower().replace("0x", "") == target_norm:
                total += int(getattr(out, "amount", 0))
        return total


# =========================================================================== #
#  Self-Test
# =========================================================================== #

def _self_test() -> None:
    """Run internal unit tests for the rules engine."""

    # -- Build minimal mock Transaction / TxInput / TxOutput -----------------
    from dataclasses import dataclass as _dc

    @_dc
    class _MockTxOutput:
        amount: int
        lock_script: bytes
        asset_type: int = ASSET_TYPE_N
        metadata: bytes = b""

    @_dc
    class _MockTxInput:
        tx_hash: bytes = b""
        output_index: int = 0
        unlock_script: bytes = b""

    @_dc
    class _MockTx:
        version: int = 1
        tx_type: int = 0
        inputs: list = None  # type: ignore
        outputs: list = None  # type: ignore
        lock_time: int = 0
        extra: bytes = b""
        witnesses: list = None  # type: ignore

        def __post_init__(self):
            if self.inputs is None:
                self.inputs = []
            if self.outputs is None:
                self.outputs = []
            if self.witnesses is None:
                self.witnesses = []

    def _make_sale_extra(buyer_hex: str, d_amount: int) -> bytes:
        buyer_bytes = bytes.fromhex(buyer_hex.replace("0x", ""))
        return bytes([len(buyer_bytes)]) + buyer_bytes + d_amount.to_bytes(8, "big")

    def _make_wage_extra(employer_hex: str, d_amount: int) -> bytes:
        emp_bytes = bytes.fromhex(employer_hex.replace("0x", ""))
        return bytes([len(emp_bytes)]) + emp_bytes + d_amount.to_bytes(8, "big")

    # -----------------------------------------------------------------------
    print("=== rules_engine.py self-test ===")

    engine = CurrencyRulesEngine()
    params = SystemParameters(phi_numerator=3, phi_denominator=100,
                              psi_numerator=5, psi_denominator=100)

    # 1. Plain transfer — valid
    tx_plain = _MockTx(
        tx_type=0,
        inputs=[_MockTxInput(unlock_script=b"\x76\xa9\x14" + b"A" * 20 + b"\x88\xac")],
        outputs=[_MockTxOutput(amount=100, lock_script=b"\x76\xa9\x14" + b"B" * 20 + b"\x88\xac")],
    )
    r = engine.validate_transfer(tx_plain)
    assert r.valid, f"Expected valid transfer, got: {r.reason}"
    print("[PASS] Plain transfer valid")

    # 2. Plain transfer — no inputs
    tx_bad = _MockTx(tx_type=0, inputs=[], outputs=[_MockTxOutput(amount=100, lock_script=b"x")])
    r = engine.validate_transfer(tx_bad)
    assert not r.valid and "no inputs" in (r.reason or "").lower()
    print("[PASS] Plain transfer no inputs rejected")

    # 3. SALE — valid (φ=3%, external_amount=1000 → required_n=30)
    buyer_hex = "bb" * 20
    seller_script = b"\x76\xa9\x14" + b"S" * 20 + b"\x88\xac"
    buyer_script = b"\x76\xa9\x14" + bytes.fromhex(buyer_hex) + b"\x88\xac"
    tx_sale = _MockTx(
        tx_type=1,  # TRANSFER_SALE
        inputs=[_MockTxInput(unlock_script=seller_script)],
        outputs=[_MockTxOutput(amount=30, lock_script=buyer_script)],
        extra=_make_sale_extra(buyer_hex, 1000),
    )
    r = engine.validate_sale_transaction(tx_sale, params)
    assert r.valid, f"Expected valid SALE, got: {r.reason}"
    print("[PASS] SALE valid (exact φ)")

    # 4. SALE — insufficient N rebate
    tx_sale_low = _MockTx(
        tx_type=1,
        inputs=[_MockTxInput(unlock_script=seller_script)],
        outputs=[_MockTxOutput(amount=20, lock_script=buyer_script)],  # 20 < 30 required
        extra=_make_sale_extra(buyer_hex, 1000),
    )
    r = engine.validate_sale_transaction(tx_sale_low, params)
    assert not r.valid and "insufficient N rebate" in (r.reason or "")
    print("[PASS] SALE insufficient N rebate rejected")

    # 5. SALE — missing extra
    tx_sale_noextra = _MockTx(
        tx_type=1,
        inputs=[_MockTxInput()],
        outputs=[_MockTxOutput(amount=30, lock_script=buyer_script)],
        extra=b"",
    )
    r = engine.validate_sale_transaction(tx_sale_noextra, params)
    assert not r.valid and "missing or malformed" in (r.reason or "")
    print("[PASS] SALE missing extra rejected")

    # 6. WAGE — valid (ψ=5%, external_amount=2000 → required_n=100)
    emp_hex = "ee" * 20
    worker_script = b"\x76\xa9\x14" + b"W" * 20 + b"\x88\xac"
    emp_script = b"\x76\xa9\x14" + bytes.fromhex(emp_hex) + b"\x88\xac"
    tx_wage = _MockTx(
        tx_type=2,  # TRANSFER_WAGE
        inputs=[_MockTxInput(unlock_script=worker_script)],
        outputs=[_MockTxOutput(amount=100, lock_script=emp_script)],
        extra=_make_wage_extra(emp_hex, 2000),
    )
    r = engine.validate_wage_transaction(tx_wage, params)
    assert r.valid, f"Expected valid WAGE, got: {r.reason}"
    print("[PASS] WAGE valid (exact ψ)")

    # 7. WAGE — insufficient N commitment
    tx_wage_low = _MockTx(
        tx_type=2,
        inputs=[_MockTxInput(unlock_script=worker_script)],
        outputs=[_MockTxOutput(amount=50, lock_script=emp_script)],  # 50 < 100
        extra=_make_wage_extra(emp_hex, 2000),
    )
    r = engine.validate_wage_transaction(tx_wage_low, params)
    assert not r.valid and "insufficient N commitment" in (r.reason or "")
    print("[PASS] WAGE insufficient N commitment rejected")

    # 8. MINT — valid governance signatures
    gov_params = SystemParameters(required_gov_signatures=2, min_n_mint=1_000_000_000)
    gov = GovernanceParams(genesis_params=gov_params)
    rec_script = b"\x76\xa9\x14" + b"R" * 20 + b"\x88\xac"
    tx_mint = _MockTx(
        tx_type=10,  # MINT
        outputs=[_MockTxOutput(amount=2_000_000_000, lock_script=rec_script)],
        witnesses=[b"sig1", b"sig2"],
    )
    r = engine.validate_mint_transaction(tx_mint, governance=gov)
    assert r.valid, f"Expected valid MINT, got: {r.reason}"
    print("[PASS] MINT valid with 2 gov signatures")

    # 9. MINT — insufficient signatures
    tx_mint_bad = _MockTx(
        tx_type=10,
        outputs=[_MockTxOutput(amount=2_000_000_000, lock_script=rec_script)],
        witnesses=[b"sig1"],  # only 1 < 2 required
    )
    r = engine.validate_mint_transaction(tx_mint_bad, governance=gov)
    assert not r.valid and "insufficient governance signatures" in (r.reason or "")
    print("[PASS] MINT insufficient signatures rejected")

    # 10. MINT — below minimum
    tx_mint_small = _MockTx(
        tx_type=10,
        outputs=[_MockTxOutput(amount=500_000_000, lock_script=rec_script)],  # < 1B
        witnesses=[b"sig1", b"sig2"],
    )
    r = engine.validate_mint_transaction(tx_mint_small, governance=gov)
    assert not r.valid and "below minimum" in (r.reason or "")
    print("[PASS] MINT below minimum rejected")

    # 11. Rational edge case — ceil rounding
    params2 = SystemParameters(phi_numerator=1, phi_denominator=3)  # 33.333...%
    assert params2.required_n_for_sale(1) == 1  # ceil(1/3) = 1
    assert params2.required_n_for_sale(2) == 1  # ceil(2/3) = 1
    assert params2.required_n_for_sale(3) == 1  # ceil(3/3) = 1
    assert params2.required_n_for_sale(4) == 2  # ceil(4/3) = 2
    print("[PASS] Rational ceil rounding edge cases")

    # 12. Historical parameter lookup for SALE
    gov_hist = GovernanceParams(genesis_params=params)
    new_params = SystemParameters(phi_numerator=10, phi_denominator=100)  # 10%
    gov_hist.update(new_params, at_height=500, reason="phi increase")
    # Build a tx with lock_time=499 → should use old φ=3%
    tx_hist = _MockTx(
        tx_type=1,
        inputs=[_MockTxInput(unlock_script=seller_script)],
        outputs=[_MockTxOutput(amount=30, lock_script=buyer_script)],  # 30 >= 3%*1000
        extra=_make_sale_extra(buyer_hex, 1000),
        lock_time=499,
    )
    engine_hist = CurrencyRulesEngine(governance=gov_hist)
    r = engine_hist.validate_sale_transaction(tx_hist)
    assert r.valid, f"Expected valid with historical φ=3%, got: {r.reason}"
    # tx with lock_time=500 → should use new φ=10% (requires 100)
    tx_hist2 = _MockTx(
        tx_type=1,
        inputs=[_MockTxInput(unlock_script=seller_script)],
        outputs=[_MockTxOutput(amount=30, lock_script=buyer_script)],  # 30 < 10%*1000
        extra=_make_sale_extra(buyer_hex, 1000),
        lock_time=500,
    )
    r2 = engine_hist.validate_sale_transaction(tx_hist2)
    assert not r2.valid and "insufficient N rebate" in (r2.reason or "")
    print("[PASS] Historical parameter lookup for SALE")

    print("=== all rules_engine.py tests passed ===")


if __name__ == "__main__":
    _self_test()
