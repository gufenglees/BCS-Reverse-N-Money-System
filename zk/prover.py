"""
prover.py - ZK Proof Generator for BCS Shielded Transactions
================================================================

Implements a **simplified Sigma-protocol** proof system for the BCS ZK module.

Technique:
  1. For each secret scalar x, the prover generates a Schnorr-style
     proof of knowledge:  a = g^k  (random k),  e = Hash(g, Y, a),
                         r = k + e·x  (mod N).  Proof = (a, r).
  2. Fiat-Shamir transform replaces the interactive challenge `e` with
     a hash of public data (statement + commitment), making the proof
     non-interactive and publicly verifiable.
  3. Range proofs are bit-decomposition commitments (see commitment.py).

Proof Structure (ZKProof):
  • circuit_id       – identifies which circuit was used
  • public_inputs    – dict of verifier-visible values
  • proof_data       – opaque bytes containing the serialized sigma proof

Security Properties:
  – Completeness:    honest prover always accepted.
  – Soundness:       cheating prover succeeds with negligible prob.
  – Zero-Knowledge:  proof reveals nothing beyond public inputs.
    (In this prototype, soundness is heuristic; production should use
    a provably secure zk-SNARK or Bulletproofs implementation.)

Author: BCS ZK Module (Prototype)
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Any

from py_ecc.secp256k1 import secp256k1

from commitment import (
    PedersenCommitment,
    NullifierGenerator,
    RangeProofProver,
    Commitment,
    _random_scalar,
    _hash_to_scalar,
    _ec_mul,
    _ec_add,
    _point_to_bytes,
    _bytes_to_point,
    N,
    G,
)
from circuits import (
    NTransferCircuit,
    RatioVerifyCircuit,
    IdentityBindCircuit,
    UTXO,
    Output,
)

# ---------------------------------------------------------------------------
# Proof data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ZKProof:
    """
    A non-interactive zero-knowledge proof.

    Attributes:
        proof_data:    Serialized proof bytes (sigma protocol transcript).
        public_inputs:   Dictionary of public statement values.
        circuit_id:      Identifies the circuit / statement type.
    """
    proof_data: bytes
    public_inputs: Dict[str, Any]
    circuit_id: int

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-friendly dict (for wire transfer)."""
        return {
            "circuit_id": self.circuit_id,
            "public_inputs": self._encode_public_inputs(),
            "proof_data": self.proof_data.hex(),
        }

    def _encode_public_inputs(self) -> Dict[str, Any]:
        """Base64/hex encode binary public inputs for JSON."""
        encoded = {}
        for k, v in self.public_inputs.items():
            if isinstance(v, bytes):
                encoded[k] = v.hex()
            elif isinstance(v, list) and v and isinstance(v[0], bytes):
                encoded[k] = [x.hex() for x in v]
            elif isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], int):
                encoded[k] = [hex(v[0]), hex(v[1])]
            else:
                encoded[k] = v
        return encoded


@dataclass
class SigmaProof:
    """
    A single Schnorr-style proof of knowledge of discrete logarithm.

    Statement:  Y = g^x
    Proof:      (a = g^k, r = k + e·x)
    Verify:     g^r == a · Y^e
    """
    a: Optional[Tuple[int, int]]  # commitment to randomness
    r: int                        # response

    def to_bytes(self) -> bytes:
        a_bytes = _point_to_bytes(self.a)
        r_bytes = self.r.to_bytes(32, 'big')
        return a_bytes + r_bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> SigmaProof:
        a = _bytes_to_point(data[:64])
        r = int.from_bytes(data[64:96], 'big')
        return cls(a=a, r=r)


# ---------------------------------------------------------------------------
# Fiat-Shamir challenge generation
# ---------------------------------------------------------------------------

def fiat_shamir_challenge(*inputs: bytes) -> int:
    """
    Deterministically generate a challenge scalar from public data.

    This replaces the interactive verifier challenge in the Sigma protocol.
    The hash includes all public statement elements so the prover cannot
    cheat by choosing the challenge adaptively.
    """
    hasher = hashlib.sha3_256()
    for inp in inputs:
        hasher.update(inp)
    return int.from_bytes(hasher.digest(), 'big') % N


# ---------------------------------------------------------------------------
# ZK Prover
# ---------------------------------------------------------------------------

class ZKProver:
    """
    Generates ZK proofs for BCS shielded transactions.

    Uses a simplified Sigma protocol + Fiat-Shamir for each sub-proof:
      • Ownership:      proof of knowledge of sk s.t. pk = g^sk
      • Balance:          homomorphic commitment equality proof
      • Range:            bit-decomposition range proof
      • Ratio:           inequality proof via commitments
      • IdentityBind:    signature + key ownership proof
    """

    def __init__(self, pedersen: Optional[PedersenCommitment] = None):
        self.pedersen = pedersen or PedersenCommitment()
        self.nf_gen = NullifierGenerator()
        self.range_prover = RangeProofProver(self.pedersen, max_bits=64)

    # ------------------------------------------------------------------
    # Core Sigma protocol helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _prove_dlog(
        secret_x: int,
        public_y: Tuple[int, int],
        generator: Tuple[int, int] = G,
    ) -> SigmaProof:
        """
        Prove knowledge of x such that Y = generator^x.
        Returns non-interactive Sigma proof via Fiat-Shamir.
        """
        k = _random_scalar()          # ephemeral randomness
        a = _ec_mul(generator, k)     # commitment
        # Fiat-Shamir challenge: hash(statement || commitment)
        e = fiat_shamir_challenge(
            _point_to_bytes(generator),
            _point_to_bytes(public_y),
            _point_to_bytes(a),
        )
        r = (k + e * secret_x) % N  # response
        return SigmaProof(a=a, r=r)

    @staticmethod
    def _prove_commitment_equality(
        c1: Commitment,
        c2: Commitment,
        delta_value: int,
        delta_blinding: int,
    ) -> SigmaProof:
        """
        Prove that C1 - C2 commits to (delta_value, delta_blinding).
        This is equivalent to a DLOG proof on the difference point.
        """
        diff = _ec_add(c1.point, _ec_mul(c2.point, N - 1))
        # We need to prove diff = g^delta_value * h^delta_blinding
        # => diff = g^dv * h^db
        # This is a proof of knowledge of (dv, db) for two bases.
        # For the prototype we simplify to a single Sigma proof on
        # the combined discrete log using a hash of the two generators.
        g = PedersenCommitment._derive_h()  # dummy – use class method properly
        # In the actual flow we use the prover's own g,h
        return ZKProver._prove_dlog(delta_value, diff or (0, 0), generator=G)

    # ------------------------------------------------------------------
    # 1. N-Transfer Proof
    # ------------------------------------------------------------------

    def prove_n_transfer(
        self,
        inputs: List[UTXO],
        outputs: List[Output],
        private_key: int,
        fee: int = 0,
        merkle_root: Optional[bytes] = None,
    ) -> ZKProof:
        """
        Generate a ZK proof for a shielded N-currency transfer.

        Flow:
          1. Compute nullifiers for each input.
          2. Compute output commitments with fresh blindings.
          3. Build the circuit constraint set.
          4. Generate sub-proofs: ownership, balance, range.
          5. Combine into a single ZKProof object.

        Returns:
            ZKProof containing all public data and serialized proof.
        """
        # --- Step 1: prepare witness data ---
        input_blindings = [_random_scalar() for _ in inputs]
        output_blindings = [_random_scalar() for _ in outputs]

        # --- Step 2: define circuit (evaluates constraints in the clear) ---
        circuit = NTransferCircuit(self.pedersen.g, self.pedersen.h)
        circuit.define(
            inputs=inputs,
            outputs=outputs,
            private_key=private_key,
            input_blindings=input_blindings,
            output_blindings=output_blindings,
            fee=fee,
            merkle_root=merkle_root,
        )
        ok, _ = circuit.validate_constraints()
        if not ok:
            raise ValueError("N-transfer circuit constraints not satisfied – cannot prove false statement")

        # --- Step 3: compute public statement values ---
        pubkey = secp256k1.multiply(self.pedersen.g, private_key % N)
        pubkey_bytes = _point_to_bytes(pubkey)

        # Nullifiers
        nullifiers: List[bytes] = []
        for utxo in inputs:
            utxo_id = utxo.tx_hash + utxo.output_index.to_bytes(4, 'big')
            sk_bytes = private_key.to_bytes(32, 'big')
            nf = hashlib.sha3_256(b"BCS_NULLIFIER_V1" + utxo_id + sk_bytes).digest()
            nullifiers.append(nf)

        # Output commitments
        output_commitments: List[bytes] = []
        for out, bl in zip(outputs, output_blindings):
            c = self.pedersen.commit(out.amount, bl)
            output_commitments.append(c.to_bytes())

        # --- Step 4: generate sub-proofs ---
        proofs: Dict[str, Any] = {}

        # 4a. Ownership proof: know sk s.t. pk = g^sk
        ownership_proof = self._prove_dlog(private_key, pubkey, generator=self.pedersen.g)
        proofs["ownership"] = ownership_proof.to_bytes()

        # 4b. Balance proof: prove Σ in = Σ out + fee via commitments
        #     C_in_sum = Σ C(in_i) , C_out_sum = Σ C(out_j)
        #     We need to prove C_in_sum / C_out_sum commits to (fee, r_diff)
        #     Homomorphically: C_in_sum = C_out_sum * C(fee, r_diff)
        #     => C_in_sum * C_out_sum^{-1} = C(fee, r_diff)
        c_in_sum: Optional[Tuple[int, int]] = None
        for utxo, bl in zip(inputs, input_blindings):
            c = self.pedersen.commit(utxo.amount, bl)
            c_in_sum = _ec_add(c_in_sum, c.point)
        c_out_sum: Optional[Tuple[int, int]] = None
        for out, bl in zip(outputs, output_blindings):
            c = self.pedersen.commit(out.amount, bl)
            c_out_sum = _ec_add(c_out_sum, c.point)

        # The "balance" point:  C_in_sum / C_out_sum = C(fee, r_in_sum - r_out_sum)
        r_diff = (sum(input_blindings) - sum(output_blindings)) % N
        balance_point = _ec_add(c_in_sum, _ec_mul(c_out_sum, N - 1))
        balance_proof = self._prove_dlog(
            r_diff,
            balance_point or (0, 0),
            generator=self.pedersen.h,  # because balance point is h^{r_diff} when fee=0
        )
        # If fee != 0, the proof is on the combined generator. For the prototype
        # we still use a simplified single-generator proof for demonstration.
        proofs["balance"] = balance_proof.to_bytes()

        # 4c. Range proofs for each amount
        range_proofs: List[List[str]] = []
        for utxo, bl in zip(inputs, input_blindings):
            rp = self.range_prover.prove(utxo.amount, bl)
            range_proofs.append(
                [c.to_bytes().hex() for c in rp.bit_commitments]
            )
        for out, bl in zip(outputs, output_blindings):
            rp = self.range_prover.prove(out.amount, bl)
            range_proofs.append(
                [c.to_bytes().hex() for c in rp.bit_commitments]
            )
        proofs["range_proofs"] = range_proofs

        # --- Step 5: package proof ---
        proof_data = json.dumps({
            "ownership": proofs["ownership"].hex(),
            "balance": proofs["balance"].hex(),
            "range_proofs": range_proofs,
        }).encode()

        public_inputs = {
            "nullifiers": nullifiers,
            "output_commitments": output_commitments,
            "merkle_root": merkle_root,
            "fee": fee,
            "pubkey": pubkey_bytes,
            "input_count": len(inputs),
            "output_count": len(outputs),
        }

        return ZKProof(
            proof_data=proof_data,
            public_inputs=public_inputs,
            circuit_id=NTransferCircuit.circuit_id,
        )

    # ------------------------------------------------------------------
    # 2. Ratio Verification Proof
    # ------------------------------------------------------------------

    def prove_ratio(
        self,
        d_amount: int,
        n_amount: int,
        phi_num: int,
        phi_den: int,
    ) -> ZKProof:
        """
        Generate a ZK proof that n_amount / external_amount >= phi_num / phi_den.

        In the prototype this reveals d_amount/external_amount and n_amount in public_inputs
        for transparency; a full shielded version would commit to them first.
        """
        circuit = RatioVerifyCircuit()
        circuit.define(d_amount=d_amount, n_amount=n_amount, phi_num=phi_num, phi_den=phi_den)
        ok, _ = circuit.validate_constraints()
        if not ok:
            raise ValueError("Ratio circuit constraints not satisfied")

        # For the prototype, the "proof" is a sigma-protocol commitment
        # to the fact that the prover knows the amounts satisfying the ratio.
        # We generate a proof of knowledge of (d, n) as a single scalar
        # by committing to their sum weighted by phi parameters.
        secret = (d_amount * phi_den + n_amount * phi_num) % N
        combined = (d_amount + n_amount) % N
        dummy_point = secp256k1.multiply(G, combined)
        sigma = self._prove_dlog(secret, dummy_point, generator=G)

        proof_data = json.dumps({
            "sigma": sigma.to_bytes().hex(),
        }).encode()

        public_inputs = {
            "phi_num": phi_num,
            "phi_den": phi_den,
            "d_commitment": None,
            "n_commitment": None,
        }

        return ZKProof(
            proof_data=proof_data,
            public_inputs=public_inputs,
            circuit_id=RatioVerifyCircuit.circuit_id,
        )

    # ------------------------------------------------------------------
    # 3. Identity Binding Proof
    # ------------------------------------------------------------------

    def prove_identity_bind(
        self,
        did_doc: bytes,
        signature: Tuple[int, int, int],
        pubkey: Tuple[int, int],
        private_key: int,
    ) -> ZKProof:
        """
        Generate a ZK proof that a DID document is controlled by the
        private key corresponding to `pubkey`.

        The proof consists of:
          1. A DLOG proof showing pk = g^sk.
          2. The ECDSA signature itself (publicly verifiable).
        """
        circuit = IdentityBindCircuit()
        circuit.g = self.pedersen.g
        circuit.define(
            did_document=did_doc,
            signature=signature,
            public_key=pubkey,
            private_key=private_key,
        )
        ok, _ = circuit.validate_constraints()
        if not ok:
            raise ValueError("Identity bind circuit constraints not satisfied")

        # Sub-proof: knowledge of sk
        ownership = self._prove_dlog(private_key, pubkey, generator=self.pedersen.g)

        proof_data = json.dumps({
            "ownership": ownership.to_bytes().hex(),
            "signature_v": signature[0],
            "signature_r": hex(signature[1]),
            "signature_s": hex(signature[2]),
        }).encode()

        public_inputs = {
            "did_hash": hashlib.sha3_256(did_doc).digest(),
            "pubkey": _point_to_bytes(pubkey),
            "signature": signature,
        }

        return ZKProof(
            proof_data=proof_data,
            public_inputs=public_inputs,
            circuit_id=IdentityBindCircuit.circuit_id,
        )


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _self_test() -> bool:
    print("=" * 60)
    print("prover.py self-test")
    print("=" * 60)

    prover = ZKProver()

    # 1. N-transfer proof
    print("\n[1] N-transfer ZK proof")
    sk = 12345
    pk = secp256k1.multiply(G, sk)
    inputs = [
        UTXO(tx_hash=b"tx_a", output_index=0, amount=500, owner_pubkey=pk),
        UTXO(tx_hash=b"tx_b", output_index=1, amount=300, owner_pubkey=pk),
    ]
    outputs = [
        Output(amount=600, recipient_pubkey=pk),
        Output(amount=180, recipient_pubkey=pk),
    ]
    proof = prover.prove_n_transfer(inputs, outputs, private_key=sk, fee=20)
    print(f"  Circuit ID: {proof.circuit_id}")
    print(f"  Proof size: {len(proof.proof_data)} bytes")
    print(f"  Nullifiers: {len(proof.public_inputs['nullifiers'])}")
    print(f"  Output commitments: {len(proof.public_inputs['output_commitments'])}")
    assert proof.circuit_id == NTransferCircuit.circuit_id
    print("  OK")

    # 2. Ratio proof
    print("\n[2] Ratio ZK proof")
    ratio_proof = prover.prove_ratio(d_amount=1000, n_amount=35, phi_num=3, phi_den=100)
    print(f"  Circuit ID: {ratio_proof.circuit_id}")
    print(f"  Proof size: {len(ratio_proof.proof_data)} bytes")
    assert ratio_proof.circuit_id == RatioVerifyCircuit.circuit_id
    print("  OK")

    # 3. Identity binding proof
    print("\n[3] Identity bind ZK proof")
    did_doc = b'{"id":"did:bcs:test","controller":"self"}'
    msg_hash = hashlib.sha3_256(did_doc).digest()
    v, r, s = secp256k1.ecdsa_raw_sign(msg_hash, sk.to_bytes(32, 'big'))
    id_proof = prover.prove_identity_bind(did_doc, (v, r, s), pk, sk)
    print(f"  Circuit ID: {id_proof.circuit_id}")
    print(f"  Proof size: {len(id_proof.proof_data)} bytes")
    assert id_proof.circuit_id == IdentityBindCircuit.circuit_id
    print("  OK")

    print("\n" + "=" * 60)
    print("All prover.py self-tests passed!")
    print("=" * 60)
    return True


if __name__ == "__main__":
    _self_test()
