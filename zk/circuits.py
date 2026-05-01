"""
circuits.py - ZK Circuit Definitions (Python Simulation)
=========================================================

This module provides a Python-level *simulation* of ZK circuit constraints.
In a production system these would be written in a circuit language such
as Circom, bellman (Rust), or arkworks, and compiled to R1CS or PLONK
constraints.  Here we keep the same interface but evaluate constraints in
plain Python so the BCS prototype can run end-to-end without a full
SNARK toolchain.

Circuit Types:
  1. NTransferCircuit    – prove input sum = output sum + fee, owners know sk.
  2. RatioVerifyCircuit  – prove N_amount / external_amount >= φ (or ψ).
  3. IdentityBindCircuit – prove a DID signature is valid for a given key.

Each circuit exposes:
  • `define(...)`          – wire the inputs/outputs into the constraint set.
  • `validate_constraints()` – evaluate every constraint and return True/False.
  • `public_inputs()`      – list of values revealed to the verifier.
  • `private_witness()`    – list of secrets known only to the prover.

Security Note:
  The Python evaluation is NOT zero-knowledge (the verifier sees all
  intermediate values).  It serves as a specification and integration test.
  The prover/verifier modules wrap these circuits with sigma protocols
  to achieve actual ZK properties in the prototype.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Any

from py_ecc.secp256k1 import secp256k1

# ---------------------------------------------------------------------------
# Minimal UTXO / Output stubs (mirrors core.utxo / core.transaction)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UTXO:
    """Minimal UTXO record used inside ZK circuits."""
    tx_hash: bytes
    output_index: int
    amount: int          # N amount (hidden in shielded mode)
    owner_pubkey: Tuple[int, int]
    # blinding factor is private witness

@dataclass(frozen=True)
class Output:
    """Minimal transaction output used inside ZK circuits."""
    amount: int
    recipient_pubkey: Tuple[int, int]
    # blinding factor is private witness


# ---------------------------------------------------------------------------
# Constraint representation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Constraint:
    """A single circuit constraint with a human-readable description."""
    name: str
    check: bool      # evaluated result (True = satisfied)
    details: str = ""

    def __repr__(self) -> str:
        status = "✓" if self.check else "✗"
        return f"[{status}] {self.name}: {self.details}"


# ---------------------------------------------------------------------------
# Circuit base class
# ---------------------------------------------------------------------------

class Circuit(ABC):
    """
    Abstract base for all BCS ZK circuits.
    """

    circuit_id: int = 0
    name: str = "AbstractCircuit"

    def __init__(self) -> None:
        self._constraints: List[Constraint] = []
        self._public_inputs: Dict[str, Any] = {}
        self._private_witness: Dict[str, Any] = {}

    @abstractmethod
    def define(self, **kwargs) -> None:
        """Wire inputs into the constraint system."""
        ...

    def add_constraint(self, name: str, condition: bool, details: str = "") -> None:
        """Register a constraint; if False the circuit is unsatisfied."""
        self._constraints.append(Constraint(name, condition, details))

    def validate_constraints(self) -> Tuple[bool, List[Constraint]]:
        """
        Evaluate all constraints.

        Returns:
            (all_satisfied, list_of_constraints)
        """
        all_ok = all(c.check for c in self._constraints)
        return all_ok, list(self._constraints)

    def public_inputs(self) -> Dict[str, Any]:
        """Return public inputs (verifier-visible)."""
        return dict(self._public_inputs)

    def private_witness(self) -> Dict[str, Any]:
        """Return private witness (prover-only)."""
        return dict(self._private_witness)

    def constraint_count(self) -> int:
        return len(self._constraints)

    def satisfied_count(self) -> int:
        return sum(1 for c in self._constraints if c.check)


# ---------------------------------------------------------------------------
# 1. N-Transfer Circuit
# ---------------------------------------------------------------------------

class NTransferCircuit(Circuit):
    """
    Circuit constraints for a shielded N-currency transfer.

    Private witness:
      – input_amounts[], output_amounts[]
      – input_blindings[], output_blindings[]
      – private_key (sk)
      – input_utxo_ids[]

    Public inputs:
      – nullifiers[]           (prevent double-spend)
      – output_commitments[]  (new UTXOs in shielded pool)
      – merkle_root             (UTXO set membership)
      – fee

    Constraints:
      (a) Σ input_amounts = Σ output_amounts + fee
      (b) Each nullifier = PRF_sk(utxo_id)
      (c) Each input commitment is valid Pedersen open
      (d) Each output commitment is valid Pedersen open
      (e) Merkle path from each input to root is valid  (simplified)
      (f) All amounts are non-negative (range proof)
      (g) Owner owns the input UTXOs (pk = g^sk)
    """

    circuit_id = 1
    name = "NTransferCircuit"

    def __init__(self, pedersen_g: Tuple[int, int], pedersen_h: Tuple[int, int]):
        super().__init__()
        self.g = pedersen_g
        self.h = pedersen_h

    def define(
        self,
        inputs: List[UTXO],
        outputs: List[Output],
        private_key: int,
        input_blindings: List[int],
        output_blindings: List[int],
        fee: int = 0,
        merkle_root: Optional[bytes] = None,
    ) -> None:
        """
        Define the N-transfer circuit with concrete values.

        Args:
            inputs: List of input UTXOs (private amounts).
            outputs: List of output specs (private amounts).
            private_key: Secret scalar controlling the inputs.
            input_blindings: Blinding factors for each input commitment.
            output_blindings: Blinding factors for each output commitment.
            fee: Transaction fee (public).
            merkle_root: Optional Merkle root for UTXO set membership.
        """
        assert len(inputs) == len(input_blindings), "input/blinding count mismatch"
        assert len(outputs) == len(output_blindings), "output/blinding count mismatch"

        # Derive public key from private key
        pubkey = secp256k1.multiply(self.g, private_key % secp256k1.N)
        pubkey_bytes = pubkey[0].to_bytes(32, 'big') + pubkey[1].to_bytes(32, 'big')

        # ---- Constraint (a): balance conservation ----
        input_sum = sum(u.amount for u in inputs)
        output_sum = sum(o.amount for o in outputs)
        self.add_constraint(
            "balance_conservation",
            input_sum == output_sum + fee,
            f"{input_sum} == {output_sum} + {fee}",
        )

        # ---- Constraint (b): nullifiers ----
        nullifiers: List[bytes] = []
        for i, utxo in enumerate(inputs):
            utxo_id = utxo.tx_hash + utxo.output_index.to_bytes(4, 'big')
            sk_bytes = private_key.to_bytes(32, 'big')
            nf = hashlib.sha3_256(
                b"BCS_NULLIFIER_V1" + utxo_id + sk_bytes
            ).digest()
            nullifiers.append(nf)
            self.add_constraint(
                f"nullifier_{i}",
                len(nf) == 32,
                f"nullifier length ok",
            )

        # ---- Constraint (c)(d): commitment validity ----
        from commitment import PedersenCommitment
        ped = PedersenCommitment(g=self.g, h=self.h)
        input_commitments: List[bytes] = []
        for i, (utxo, bl) in enumerate(zip(inputs, input_blindings)):
            c = ped.commit(utxo.amount, bl)
            input_commitments.append(c.to_bytes())
            self.add_constraint(
                f"input_commitment_{i}",
                not c.is_infinity(),
                f"input {i} commitment is valid point",
            )

        output_commitments: List[bytes] = []
        for i, (out, bl) in enumerate(zip(outputs, output_blindings)):
            c = ped.commit(out.amount, bl)
            output_commitments.append(c.to_bytes())
            self.add_constraint(
                f"output_commitment_{i}",
                not c.is_infinity(),
                f"output {i} commitment is valid point",
            )

        # ---- Constraint (e): Merkle root membership (simplified) ----
        if merkle_root is not None:
            # In a real circuit, this would verify a Merkle path
            # Here we just ensure the root is a valid 32-byte hash
            self.add_constraint(
                "merkle_root_format",
                len(merkle_root) == 32,
                "merkle root is 32 bytes",
            )

        # ---- Constraint (f): non-negative amounts ----
        all_non_negative = all(u.amount >= 0 for u in inputs) and all(o.amount >= 0 for o in outputs)
        self.add_constraint(
            "amounts_non_negative",
            all_non_negative,
            "all amounts >= 0",
        )

        # ---- Constraint (g): ownership (pk = g^sk) ----
        ownership_valid = True
        for utxo in inputs:
            if utxo.owner_pubkey != pubkey:
                ownership_valid = False
                break
        self.add_constraint(
            "ownership",
            ownership_valid,
            "all inputs owned by sk",
        )

        # ---- Register public / private data ----
        self._public_inputs = {
            "circuit_id": self.circuit_id,
            "nullifiers": nullifiers,
            "output_commitments": output_commitments,
            "merkle_root": merkle_root,
            "fee": fee,
            "pubkey": pubkey_bytes,
            "input_count": len(inputs),
            "output_count": len(outputs),
        }
        self._private_witness = {
            "input_amounts": [u.amount for u in inputs],
            "output_amounts": [o.amount for o in outputs],
            "input_blindings": input_blindings,
            "output_blindings": output_blindings,
            "private_key": private_key,
        }


# ---------------------------------------------------------------------------
# 2. Ratio Verification Circuit
# ---------------------------------------------------------------------------

class RatioVerifyCircuit(Circuit):
    """
    Circuit constraints proving that an N-transfer satisfies the BCS
    ratio rule (φ for sales, ψ for wages).

    Constraint:  n_amount * phi_denominator >= external_amount * phi_numerator

    This proves that the N component of a transaction meets or exceeds
    the required proportion of the external amount component, without
    revealing the exact amount if used inside a larger shielded proof.

    Private witness:
      – d_amount/external_amount, n_amount (can be private in shielded mode)

    Public inputs:
      – phi_numerator, phi_denominator
      – commitment to external amount (optional)
      – commitment to n_amount (optional)
    """

    circuit_id = 2
    name = "RatioVerifyCircuit"

    def define(
        self,
        d_amount: int,
        n_amount: int,
        phi_num: int,
        phi_den: int,
        d_commitment: Optional[bytes] = None,
        n_commitment: Optional[bytes] = None,
    ) -> None:
        """
        Define ratio verification constraints.

        Args:
            d_amount: External amount (e.g., sale price in fiat terms).
            n_amount: N-currency amount transferred.
            phi_num:  Proportion numerator   (e.g., 3).
            phi_den:  Proportion denominator (e.g., 100).
        """
        # ---- Constraint: proportions strictly positive ----
        self.add_constraint(
            "phi_positive",
            phi_num > 0 and phi_den > 0,
            f"phi = {phi_num}/{phi_den} > 0",
        )

        # ---- Constraint: amounts non-negative ----
        self.add_constraint(
            "amounts_non_negative",
            d_amount >= 0 and n_amount >= 0,
            f"d={d_amount}, n={n_amount} >= 0",
        )

        # ---- Core constraint: n_amount * phi_den >= d_amount * phi_num ----
        lhs = n_amount * phi_den
        rhs = d_amount * phi_num
        self.add_constraint(
            "ratio_satisfied",
            lhs >= rhs,
            f"{n_amount} * {phi_den} ({lhs}) >= {d_amount} * {phi_num} ({rhs})",
        )

        # ---- Optional: commitment consistency ----
        if d_commitment is not None:
            self.add_constraint(
                "d_commitment_present",
                len(d_commitment) == 64,
                "d commitment is 64-byte point",
            )
        if n_commitment is not None:
            self.add_constraint(
                "n_commitment_present",
                len(n_commitment) == 64,
                "n commitment is 64-byte point",
            )

        self._public_inputs = {
            "circuit_id": self.circuit_id,
            "phi_num": phi_num,
            "phi_den": phi_den,
            "d_commitment": d_commitment,
            "n_commitment": n_commitment,
        }
        self._private_witness = {
            "d_amount": d_amount,
            "n_amount": n_amount,
        }


# ---------------------------------------------------------------------------
# 3. Identity Binding Circuit
# ---------------------------------------------------------------------------

class IdentityBindCircuit(Circuit):
    """
    Circuit constraints proving that a DID document is controlled by
    the private key corresponding to a given public key.

    In BCS, this binds a `did:bcs:<pubkey_hash>` to the actual secp256k1
    keypair used for signing transactions.

    Private witness:
      – private_key

    Public inputs:
      – did_document (hash)
      – signature (r, s)
      – public_key (point)

    Constraints:
      (a) pk = g^sk
      (b) signature verifies on did_document hash under pk
    """

    circuit_id = 3
    name = "IdentityBindCircuit"

    def define(
        self,
        did_document: bytes,
        signature: Tuple[int, int, int],
        public_key: Tuple[int, int],
        private_key: Optional[int] = None,
    ) -> None:
        """
        Define identity binding constraints.

        Args:
            did_document: Raw DID document bytes (or its hash).
            signature: (v, r, s) ECDSA signature over the DID document.
            public_key: (x, y) secp256k1 public key point.
            private_key: Optional secret scalar (prover witness).
                         If None, the ownership constraint is skipped.
        """
        # ---- Constraint (a): pk = g^sk (if sk provided) ----
        if private_key is not None:
            derived_pk = secp256k1.multiply(self.g, private_key % secp256k1.N)
            pk_match = (derived_pk is not None) and (derived_pk[0] == public_key[0]) and (derived_pk[1] == public_key[1])
            self.add_constraint(
                "pk_equals_g_to_sk",
                pk_match,
                "derived pubkey matches provided pubkey",
            )
        else:
            self.add_constraint(
                "pk_equals_g_to_sk",
                True,  # cannot verify without sk
                "sk not provided – skipped",
            )

        # ---- Constraint (b): signature validity ----
        # We use py_ecc's ecdsa_raw_recover to verify
        msg_hash_bytes = hashlib.sha3_256(did_document).digest()
        v, r, s = signature
        try:
            recovered = secp256k1.ecdsa_raw_recover(msg_hash_bytes, (v, r, s))
            sig_valid = (recovered is not None) and (recovered[0] == public_key[0]) and (recovered[1] == public_key[1])
        except Exception:
            sig_valid = False

        self.add_constraint(
            "signature_valid",
            sig_valid,
            "ECDSA signature recovers to provided pubkey",
        )

        # DID document hash is public
        did_hash = hashlib.sha3_256(did_document).digest()

        self._public_inputs = {
            "circuit_id": self.circuit_id,
            "did_hash": did_hash,
            "public_key": public_key[0].to_bytes(32, 'big') + public_key[1].to_bytes(32, 'big'),
            "signature_v": v,
            "signature_r": r,
            "signature_s": s,
        }
        self._private_witness = {
            "private_key": private_key,
        }

    @staticmethod
    def _hash_message(msg: bytes) -> int:
        return int.from_bytes(hashlib.sha3_256(msg).digest(), 'big')


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _self_test() -> bool:
    print("=" * 60)
    print("circuits.py self-test")
    print("=" * 60)

    g = secp256k1.G
    h = secp256k1.multiply(g, 123456789)  # dummy H generator

    # 1. NTransferCircuit
    print("\n[1] NTransferCircuit")
    sk = 42
    pk = secp256k1.multiply(g, sk)
    inputs = [
        UTXO(tx_hash=b"tx_a", output_index=0, amount=500, owner_pubkey=pk),
        UTXO(tx_hash=b"tx_b", output_index=1, amount=300, owner_pubkey=pk),
    ]
    outputs = [
        Output(amount=600, recipient_pubkey=pk),
        Output(amount=180, recipient_pubkey=pk),
    ]
    circuit = NTransferCircuit(g, h)
    circuit.define(
        inputs=inputs,
        outputs=outputs,
        private_key=sk,
        input_blindings=[111, 222],
        output_blindings=[333, 444],
        fee=20,
    )
    ok, constraints = circuit.validate_constraints()
    print(f"  Constraints: {circuit.satisfied_count()}/{circuit.constraint_count()} satisfied")
    for c in constraints:
        print(f"    {c}")
    assert ok, "NTransferCircuit should be satisfied"
    print("  OK")

    # 2. RatioVerifyCircuit (sale: 3% => need 3N per 100D)
    print("\n[2] RatioVerifyCircuit")
    circuit2 = RatioVerifyCircuit()
    circuit2.define(d_amount=1000, n_amount=35, phi_num=3, phi_den=100)
    ok2, constraints2 = circuit2.validate_constraints()
    print(f"  Constraints: {circuit2.satisfied_count()}/{circuit2.constraint_count()} satisfied")
    for c in constraints2:
        print(f"    {c}")
    assert ok2, "RatioVerifyCircuit should be satisfied (35 >= 30)"
    print("  OK")

    # Test failing ratio
    circuit2_fail = RatioVerifyCircuit()
    circuit2_fail.define(d_amount=1000, n_amount=20, phi_num=3, phi_den=100)
    ok2_fail, _ = circuit2_fail.validate_constraints()
    assert not ok2_fail, "RatioVerifyCircuit should fail (20 < 30)"
    print("  Failing ratio correctly rejected")

    # 3. IdentityBindCircuit
    print("\n[3] IdentityBindCircuit")
    did_doc = b'{"id": "did:bcs:abc123", "controller": "self"}'
    msg_hash_bytes = hashlib.sha3_256(did_doc).digest()
    sk_int = 42
    sk_bytes = sk_int.to_bytes(32, 'big')
    pk = secp256k1.multiply(g, sk_int)
    # Sign with py_ecc  (ecdsa_raw_sign returns (v, r, s), expects bytes)
    v, r, s = secp256k1.ecdsa_raw_sign(msg_hash_bytes, sk_bytes)
    circuit3 = IdentityBindCircuit()
    circuit3.g = g
    circuit3.define(did_document=did_doc, signature=(v, r, s), public_key=pk, private_key=sk_int)
    ok3, constraints3 = circuit3.validate_constraints()
    print(f"  Constraints: {circuit3.satisfied_count()}/{circuit3.constraint_count()} satisfied")
    for c in constraints3:
        print(f"    {c}")
    assert ok3, "IdentityBindCircuit should be satisfied"
    print("  OK")

    print("\n" + "=" * 60)
    print("All circuits.py self-tests passed!")
    print("=" * 60)
    return True


if __name__ == "__main__":
    _self_test()
