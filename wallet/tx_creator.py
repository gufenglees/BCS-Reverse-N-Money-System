"""
BCS Transaction Creator — Build UTXO-based Transactions
=========================================================
Helpers to construct BCS transactions from wallet keys and UTXO sets.

Supports all BCS transaction types:
  • TRANSFER      — ordinary N transfer (P2PKH)
  • TRANSFER_SALE — seller→buyer N settlement with φ ratio enforcement
  • TRANSFER_WAGE — worker→employer N settlement with ψ ratio enforcement
  • MINT          — governance-only N issuance

UTXO selection strategies:
  • smallest_first  — prefer small UTXOs to reduce dust / fragmentation
  • largest_first   — prefer large UTXOs to minimize input count

Architecture reference: architecture_design.md §2.7, §3.2
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

# Core imports (assumed to be in PYTHONPATH)
from core.transaction import Transaction, TxInput, TxOutput, TxType
from core.script import StandardScripts
from core.utxo import UTXO


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Fee rate: nanoN per byte (configurable, default ~0.001 N per 1kB)
DEFAULT_FEE_RATE: int = 1_000  # nanoN / byte

# Estimated sizes for fee calculation (bytes)
# These are rough estimates for ECDSA + P2PKH transactions.
SIZE_TX_HEADER: int = 12         # version(4) + tx_type(4) + input_count(var) + output_count(var) + lock_time(8)
SIZE_PER_INPUT: int = 148      # tx_hash(32) + vout(4) + scriptSig(~107) + sequence(4)
SIZE_PER_OUTPUT: int = 34      # value(8) + scriptPubKey(~25) + asset_type(4) + metadata_len
SIZE_WITNESS: int = 0          # BCS uses scriptSig, not SegWit
SIZE_EXTRA_BASE: int = 16      # extra field overhead


# --------------------------------------------------------------------------- #
# UTXO selection strategy
# --------------------------------------------------------------------------- #

class UTXOStrategy(Enum):
    """UTXO selection strategy."""
    SMALLEST_FIRST = "smallest_first"   # Reduce fragmentation (default)
    LARGEST_FIRST = "largest_first"     # Minimize input count


# --------------------------------------------------------------------------- #
# TxCreator
# --------------------------------------------------------------------------- #

class TxCreator:
    """
    Transaction builder for BCS wallets.

    Usage::

        creator = TxCreator()
        tx = creator.create_transfer(
            wallet=my_wallet,
            from_addr="abc...",
            recipient="def...",
            amount=5_000_000_000,
            fee=1_000_000,
            password="secret"
        )
    """

    def __init__(self, fee_rate: int = DEFAULT_FEE_RATE) -> None:
        self.fee_rate = fee_rate

    # ------------------------------------------------------------------ #
    # Public API — transaction builders
    # ------------------------------------------------------------------ #

    def create_transfer(
        self,
        wallet,
        from_addr: str,
        recipient: str,
        amount: int,
        fee: int,
        password: str,
        available_utxos: list[UTXO],
        change_address: Optional[str] = None,
    ) -> Transaction:
        """
        Build a standard P2PKH TRANSFER transaction.

        Args:
            wallet: Wallet instance for signing.
            from_addr: Sender address (must have UTXOs).
            recipient: Recipient BCS address.
            amount: N amount to send (nanoN).
            fee: Transaction fee (nanoN).
            password: Wallet password to unlock keys.
            available_utxos: UTXOs available for this address.
            change_address: Address to receive change (default: from_addr).

        Returns:
            Fully signed Transaction.

        Raises:
            ValueError: If insufficient balance.
        """
        if change_address is None:
            change_address = from_addr

        total_needed = amount + fee
        selected, total_input = self.select_utxos(available_utxos, total_needed)
        if total_input < total_needed:
            raise ValueError(
                f"Insufficient balance: need {total_needed}, have {total_input}"
            )

        # Recipient output
        recipient_pubkey_hash = self._address_to_pubkey_hash(recipient)
        recipient_lock = StandardScripts.p2pkh_lock_script(recipient_pubkey_hash)
        outputs = [TxOutput(amount=amount, lock_script=recipient_lock)]

        # Change output (if any)
        change = total_input - total_needed
        if change > 0:
            change_pubkey_hash = self._address_to_pubkey_hash(change_address)
            change_lock = StandardScripts.p2pkh_lock_script(change_pubkey_hash)
            outputs.append(TxOutput(amount=change, lock_script=change_lock))

        # Build transaction skeleton
        tx = Transaction(
            version=1,
            tx_type=TxType.TRANSFER,
            inputs=[self._utxo_to_input(u) for u in selected],
            outputs=outputs,
            lock_time=0,
            extra=b"",
        )

        # Sign each input
        self._sign_all_inputs(tx, wallet, from_addr, password)
        return tx

    def create_sale(
        self,
        wallet,
        from_addr: str,
        buyer: str,
        d_amount: int,
        n_amount: int,
        fee: int,
        password: str,
        available_utxos: list[UTXO],
        change_address: Optional[str] = None,
        external_currency: str = "",
        external_payment_ref: str = "",
    ) -> Transaction:
        """
        Build a TRANSFER_SALE transaction (seller perspective).

        BCS rule: seller must transfer at least φ × external payment amount
        of N to buyer. The chain settles only N. Bank/cash/gateway/invoice
        references are optional metadata, not required protocol fields.
        The *n_amount* parameter is the actual N being transferred; the caller
        is responsible for ensuring n_amount is at least the φ-based required N.

        Args:
            wallet: Wallet instance.
            from_addr: Seller address.
            buyer: Buyer address.
            d_amount: External payment amount in the configured smallest unit.
            n_amount: N amount to transfer to buyer.
            fee: Transaction fee.
            password: Wallet password.
            available_utxos: Seller's available UTXOs.
            change_address: Address for change.
            external_currency: Optional real-world currency/unit label.
            external_payment_ref: Optional bank/cash/gateway/invoice reference.

        Returns:
            Signed Transaction with extra SaleInfo metadata.
        """
        if change_address is None:
            change_address = from_addr

        total_needed = n_amount + fee
        selected, total_input = self.select_utxos(available_utxos, total_needed)
        if total_input < total_needed:
            raise ValueError(
                f"Insufficient balance for sale: need {total_needed}, have {total_input}"
            )

        # Buyer output (N transfer)
        buyer_pubkey_hash = self._address_to_pubkey_hash(buyer)
        buyer_lock = StandardScripts.p2pkh_lock_script(buyer_pubkey_hash)
        outputs = [TxOutput(amount=n_amount, lock_script=buyer_lock)]

        # Change
        change = total_input - total_needed
        if change > 0:
            change_pubkey_hash = self._address_to_pubkey_hash(change_address)
            change_lock = StandardScripts.p2pkh_lock_script(change_pubkey_hash)
            outputs.append(TxOutput(amount=change, lock_script=change_lock))

        # Sale metadata
        sale_extra = {
            "d_amount": d_amount,
            "external_amount": d_amount,
            "n_amount": n_amount,
            "seller": from_addr,
            "buyer": buyer,
        }
        if external_currency:
            sale_extra["external_currency"] = external_currency
        if external_payment_ref:
            sale_extra["external_payment_ref"] = external_payment_ref

        tx = Transaction(
            version=1,
            tx_type=TxType.TRANSFER_SALE,
            inputs=[self._utxo_to_input(u) for u in selected],
            outputs=outputs,
            lock_time=0,
            extra=json.dumps(sale_extra, sort_keys=True).encode("utf-8"),
        )

        self._sign_all_inputs(tx, wallet, from_addr, password)
        return tx

    def create_wage(
        self,
        wallet,
        from_addr: str,
        employer: str,
        d_amount: int,
        n_amount: int,
        fee: int,
        password: str,
        available_utxos: list[UTXO],
        change_address: Optional[str] = None,
        external_currency: str = "",
        external_payment_ref: str = "",
    ) -> Transaction:
        """
        Build a TRANSFER_WAGE transaction (worker perspective).

        BCS rule: worker must transfer at least ψ × external wage amount of N
        to employer. The chain settles only N. Payroll, bank, cash and gateway
        references are optional metadata, not required protocol fields.

        Args:
            wallet: Wallet instance.
            from_addr: Worker address.
            employer: Employer address.
            d_amount: External wage amount in the configured smallest unit.
            n_amount: N amount to transfer to employer.
            fee: Transaction fee.
            password: Wallet password.
            available_utxos: Worker's available UTXOs.
            change_address: Address for change.
            external_currency: Optional real-world currency/unit label.
            external_payment_ref: Optional payroll/bank/cash/gateway reference.

        Returns:
            Signed Transaction with extra WageInfo metadata.
        """
        if change_address is None:
            change_address = from_addr

        total_needed = n_amount + fee
        selected, total_input = self.select_utxos(available_utxos, total_needed)
        if total_input < total_needed:
            raise ValueError(
                f"Insufficient balance for wage: need {total_needed}, have {total_input}"
            )

        # Employer output (N transfer)
        employer_pubkey_hash = self._address_to_pubkey_hash(employer)
        employer_lock = StandardScripts.p2pkh_lock_script(employer_pubkey_hash)
        outputs = [TxOutput(amount=n_amount, lock_script=employer_lock)]

        # Change
        change = total_input - total_needed
        if change > 0:
            change_pubkey_hash = self._address_to_pubkey_hash(change_address)
            change_lock = StandardScripts.p2pkh_lock_script(change_pubkey_hash)
            outputs.append(TxOutput(amount=change, lock_script=change_lock))

        # Wage metadata
        wage_extra = {
            "d_amount": d_amount,
            "external_amount": d_amount,
            "n_amount": n_amount,
            "worker": from_addr,
            "employer": employer,
        }
        if external_currency:
            wage_extra["external_currency"] = external_currency
        if external_payment_ref:
            wage_extra["external_payment_ref"] = external_payment_ref

        tx = Transaction(
            version=1,
            tx_type=TxType.TRANSFER_WAGE,
            inputs=[self._utxo_to_input(u) for u in selected],
            outputs=outputs,
            lock_time=0,
            extra=json.dumps(wage_extra, sort_keys=True).encode("utf-8"),
        )

        self._sign_all_inputs(tx, wallet, from_addr, password)
        return tx

    def create_mint(
        self,
        wallet,
        recipient: str,
        amount: int,
        gov_keys: list[bytes],
        password: str,
        available_utxos: Optional[list[UTXO]] = None,
    ) -> Transaction:
        """
        Build a MINT transaction (governance operation).

        MINT transactions have no regular inputs — they are authorized by
        governance multi-signatures via OP_CHECKGOVSIG in the first output's
        lock script, or via witness signatures.

        Args:
            wallet: Wallet instance (signing with a governance key).
            recipient: Address receiving the newly minted N.
            amount: N amount to mint (nanoN).
            gov_keys: List of governance public keys (for the lock script).
            password: Wallet password.
            available_utxos: Not used for MINT (no inputs), kept for API consistency.

        Returns:
            Signed MINT Transaction.
        """
        recipient_pubkey_hash = self._address_to_pubkey_hash(recipient)
        lock_script = StandardScripts.p2pkh_lock_script(recipient_pubkey_hash)

        # Governance metadata
        mint_extra = {
            "recipient": recipient,
            "amount": amount,
            "gov_key_count": len(gov_keys),
        }

        tx = Transaction(
            version=1,
            tx_type=TxType.MINT,
            inputs=[],  # MINT has no inputs
            outputs=[TxOutput(amount=amount, lock_script=lock_script)],
            lock_time=0,
            extra=json.dumps(mint_extra, sort_keys=True).encode("utf-8"),
        )

        # Sign with governance key (single witness for now; multi-sig extension
        # would collect signatures from multiple gov keys)
        sighash = tx.signing_hash()
        if wallet and password:
            # Find which of the wallet's addresses is a governance key
            gov_address = None
            for addr in wallet.list_addresses():
                pubkey = wallet.get_public_key(addr)
                if pubkey in gov_keys or any(pubkey == gk for gk in gov_keys):
                    gov_address = addr
                    break
            if gov_address:
                sig = wallet.sign_transaction(gov_address, sighash, password)
                tx.witnesses.append(sig)
            else:
                # Wallet doesn't hold a governance key; leave unsigned
                pass

        return tx

    # ------------------------------------------------------------------ #
    # UTXO selection
    # ------------------------------------------------------------------ #

    def select_utxos(
        self,
        utxos: list[UTXO],
        amount: int,
        strategy: UTXOStrategy = UTXOStrategy.SMALLEST_FIRST,
        exclude: Optional[list[str]] = None,
    ) -> tuple[list[UTXO], int]:
        """
        Select UTXOs to cover *amount* (nanoN).

        Args:
            utxos: Available UTXO list.
            amount: Target sum in nanoN.
            strategy: Selection heuristic.
            exclude: List of outpoint strings to skip.

        Returns:
            (selected_utxos, total_selected_amount)

        Raises:
            ValueError: If no UTXOs available or insufficient funds.
        """
        if not utxos:
            raise ValueError("No UTXOs available")

        exclude_set = set(exclude or [])
        candidates = [u for u in utxos if u.outpoint not in exclude_set]
        if not candidates:
            raise ValueError("All UTXOs excluded")

        if strategy == UTXOStrategy.SMALLEST_FIRST:
            candidates.sort(key=lambda u: u.amount)
        else:
            candidates.sort(key=lambda u: u.amount, reverse=True)

        selected: list[UTXO] = []
        total = 0
        for utxo in candidates:
            selected.append(utxo)
            total += utxo.amount
            if total >= amount:
                break

        if total < amount:
            raise ValueError(
                f"Insufficient funds: need {amount}, available {sum(u.amount for u in candidates)}"
            )

        return selected, total

    # ------------------------------------------------------------------ #
    # Fee estimation
    # ------------------------------------------------------------------ #

    def estimate_fee(self, num_inputs: int, num_outputs: int, extra_size: int = 0) -> int:
        """
        Estimate transaction fee based on serialized size.

        Args:
            num_inputs: Number of tx inputs.
            num_outputs: Number of tx outputs.
            extra_size: Estimated extra metadata size in bytes.

        Returns:
            Fee in nanoN.
        """
        tx_size = (
            SIZE_TX_HEADER
            + num_inputs * SIZE_PER_INPUT
            + num_outputs * SIZE_PER_OUTPUT
            + extra_size
        )
        return tx_size * self.fee_rate

    def estimate_fee_for_tx(self, tx: Transaction) -> int:
        """Estimate fee for an existing (unsigned) transaction skeleton."""
        return self.estimate_fee(
            num_inputs=len(tx.inputs),
            num_outputs=len(tx.outputs),
            extra_size=len(tx.extra),
        )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _utxo_to_input(utxo: UTXO) -> TxInput:
        """Convert a UTXO to a TxInput (unlock_script is empty until signed)."""
        return TxInput(
            tx_hash=utxo.tx_hash,
            output_index=utxo.output_index,
            unlock_script=b"",
        )

    @staticmethod
    def _address_to_pubkey_hash(address: str) -> bytes:
        """
        Decode a BCS Base58 address back to its 20-byte pubkey hash.

        In a full implementation this would verify the checksum.
        """
        from wallet import base58_decode
        decoded = base58_decode(address)
        # BCS addresses are currently just Base58(RIPEMD160) without version/checksum prefix
        # If we add a 1-byte version prefix in the future, strip it here.
        if len(decoded) == 21:
            return decoded[1:]  # 1-byte version prefix
        return decoded[-20:] if len(decoded) > 20 else decoded

    @staticmethod
    def _sign_all_inputs(
        tx: Transaction, wallet, from_addr: str, password: str
    ) -> None:
        """Sign every input in *tx* using *from_addr*'s key."""
        sighash = tx.signing_hash()
        # For each input, build unlock_script
        for idx in range(len(tx.inputs)):
            unlock = wallet.build_unlock_script(from_addr, sighash, password)
            tx.inputs[idx].unlock_script = unlock
            tx.witnesses.append(unlock)


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

def _self_test() -> None:
    import os
    import tempfile

    print("=" * 60)
    print("BCS TxCreator Self-Test")
    print("=" * 60)

    from wallet import Wallet

    tmpdir = tempfile.mkdtemp(prefix="bcs_tx_test_")
    db_path = os.path.join(tmpdir, "wallet.db")
    password = "tx_test_password"

    with Wallet(db_path) as w:
        addr1 = w.create_new(label="alice", password=password)
        addr2 = w.create_new(label="bob", password=password)
        addr3 = w.create_new(label="carol", password=password)

        creator = TxCreator(fee_rate=1_000)

        # Create synthetic UTXOs for addr1
        pk1 = w.get_public_key(addr1)
        from core.script import StandardScripts
        lock1 = StandardScripts.p2pkh_lock_script(hashlib.new("ripemd160", hashlib.sha256(pk1).digest()).digest())

        utxos = [
            UTXO(tx_hash="a" * 64, output_index=0, amount=1_000_000_000, lock_script=lock1),
            UTXO(tx_hash="b" * 64, output_index=1, amount=500_000_000, lock_script=lock1),
            UTXO(tx_hash="c" * 64, output_index=2, amount=200_000_000, lock_script=lock1),
        ]

        # 1. UTXO selection — smallest_first
        selected, total = creator.select_utxos(utxos, 600_000_000, strategy=UTXOStrategy.SMALLEST_FIRST)
        assert len(selected) == 2  # 200M + 500M = 700M >= 600M
        assert selected[0].amount == 200_000_000
        assert total == 700_000_000
        print(f"[1] UTXO selection (smallest_first) OK: {len(selected)} inputs, total={total}")

        # 2. UTXO selection — largest_first
        selected2, total2 = creator.select_utxos(utxos, 600_000_000, strategy=UTXOStrategy.LARGEST_FIRST)
        assert len(selected2) == 1  # 1_000M >= 600M
        assert selected2[0].amount == 1_000_000_000
        print(f"[2] UTXO selection (largest_first) OK: {len(selected2)} inputs, total={total2}")

        # 3. Fee estimation
        fee = creator.estimate_fee(num_inputs=2, num_outputs=2)
        assert fee > 0
        print(f"[3] Fee estimate for 2in/2out: {fee} nanoN")

        # 4. Create transfer
        tx = creator.create_transfer(
            wallet=w,
            from_addr=addr1,
            recipient=addr2,
            amount=300_000_000,
            fee=1_000_000,
            password=password,
            available_utxos=utxos,
        )
        assert tx.tx_type == TxType.TRANSFER
        assert len(tx.inputs) > 0
        assert len(tx.outputs) >= 1
        assert tx.hash() is not None
        print(f"[4] Transfer tx created: {tx.hash()[:16]}...")

        # 5. Create sale
        sale_tx = creator.create_sale(
            wallet=w,
            from_addr=addr1,
            buyer=addr2,
            d_amount=10_000,
            n_amount=300_000_000,
            fee=1_000_000,
            password=password,
            available_utxos=utxos,
        )
        assert sale_tx.tx_type == TxType.TRANSFER_SALE
        extra = json.loads(sale_tx.extra.decode("utf-8"))
        assert extra["buyer"] == addr2
        print(f"[5] Sale tx created: {sale_tx.hash()[:16]}...")

        # 6. Create wage
        wage_tx = creator.create_wage(
            wallet=w,
            from_addr=addr1,
            employer=addr3,
            d_amount=5_000,
            n_amount=250_000_000,
            fee=1_000_000,
            password=password,
            available_utxos=utxos,
        )
        assert wage_tx.tx_type == TxType.TRANSFER_WAGE
        extra_w = json.loads(wage_tx.extra.decode("utf-8"))
        assert extra_w["employer"] == addr3
        print(f"[6] Wage tx created: {wage_tx.hash()[:16]}...")

        # 7. Create mint (no inputs)
        gov_key = w.get_public_key(addr3)
        mint_tx = creator.create_mint(
            wallet=w,
            recipient=addr2,
            amount=1_000_000_000,
            gov_keys=[gov_key],
            password=password,
        )
        assert mint_tx.tx_type == TxType.MINT
        assert len(mint_tx.inputs) == 0
        assert mint_tx.outputs[0].amount == 1_000_000_000
        print(f"[7] Mint tx created: {mint_tx.hash()[:16]}...")

        # 8. Tx serialization round-trip
        tx_dict = tx.to_dict()
        from core.transaction import Transaction as TxClass
        tx2 = TxClass.from_dict(tx_dict)
        assert tx2.hash() == tx.hash()
        print("[8] Tx serialization round-trip OK")

    # Cleanup
    os.remove(db_path)
    os.rmdir(tmpdir)

    print("\n" + "=" * 60)
    print("All tx_creator.py self-tests PASSED")
    print("=" * 60)


if __name__ == "__main__":
    import hashlib
    _self_test()
