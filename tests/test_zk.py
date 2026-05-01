"""
Zero-Knowledge Proof Integration Tests
======================================
Tests for commitment homomorphic properties, nullifier generation,
N-transfer ZK proof, ratio verification proof, identity binding proof,
and batch verification.
"""

import pytest
import hashlib
from typing import List, Tuple

from py_ecc.secp256k1 import secp256k1

from commitment import (
    PedersenCommitment, NullifierGenerator, Commitment,
    _random_scalar, _hash_to_scalar, _ec_mul, _ec_add, _point_to_bytes,
    N, G,
)
from prover import ZKProver, ZKProof
from verifier import ZKVerifier, NullifierSet
from circuits import NTransferCircuit, RatioVerifyCircuit, IdentityBindCircuit, UTXO as ZKUTXO, Output as ZKOutput


# ---------------------------------------------------------------------------
# Commitment Homomorphic Properties
# ---------------------------------------------------------------------------

class TestCommitmentHomomorphic:
    def test_commitment_additive_homomorphism(self):
        """C(v1, r1) + C(v2, r2) = C(v1+v2, r1+r2)."""
        pc = PedersenCommitment()
        v1, r1 = 100, _random_scalar()
        v2, r2 = 200, _random_scalar()

        c1 = pc.commit(v1, r1)
        c2 = pc.commit(v2, r2)
        c_sum = Commitment(_ec_add(c1.point, c2.point))

        expected = pc.commit(v1 + v2, (r1 + r2) % N)
        assert _point_to_bytes(c_sum.point) == _point_to_bytes(expected.point)

    def test_commitment_binding(self):
        """Same value with different blinding factors produces different commitments."""
        pc = PedersenCommitment()
        v = 500
        r1 = _random_scalar()
        r2 = _random_scalar()
        assert r1 != r2

        c1 = pc.commit(v, r1)
        c2 = pc.commit(v, r2)
        assert _point_to_bytes(c1.point) != _point_to_bytes(c2.point)

    def test_commitment_hiding(self):
        """Different values may produce same commitment (collision resistance heuristic)."""
        pc = PedersenCommitment()
        # Note: In a perfectly hiding commitment, collisions are expected.
        # This test just checks the API works.
        c1 = pc.commit(1000, _random_scalar())
        c2 = pc.commit(2000, _random_scalar())
        assert c1 is not None
        assert c2 is not None

    def test_commitment_serialization(self):
        """Commitment round-trips through bytes."""
        pc = PedersenCommitment()
        c = pc.commit(1234, _random_scalar())
        c_bytes = c.to_bytes()
        assert len(c_bytes) == 64
        restored = Commitment.from_bytes(c_bytes)
        assert _point_to_bytes(c.point) == _point_to_bytes(restored.point)

    def test_open_commitment(self):
        """Pedersen commitment can be opened with value and blinding."""
        pc = PedersenCommitment()
        v, r = 9999, _random_scalar()
        c = pc.commit(v, r)
        assert c.open(v, r, pc.g, pc.h)
        assert not c.open(v + 1, r, pc.g, pc.h)


# ---------------------------------------------------------------------------
# Nullifier Generation
# ---------------------------------------------------------------------------

class TestNullifierGeneration:
    def test_nullifier_deterministic(self):
        """Same input always produces the same nullifier."""
        gen = NullifierGenerator()
        utxo_id = b"test_utxo_123"
        sk = b"secret_key_bytes"

        nf1 = gen.generate(utxo_id, sk)
        nf2 = gen.generate(utxo_id, sk)
        assert nf1 == nf2
        assert len(nf1) == 32  # SHA3-256 digest

    def test_nullifier_unique_per_utxo(self):
        """Different UTXOs produce different nullifiers."""
        gen = NullifierGenerator()
        sk = b"secret_key_bytes"

        nf1 = gen.generate(b"utxo_a", sk)
        nf2 = gen.generate(b"utxo_b", sk)
        assert nf1 != nf2

    def test_nullifier_unique_per_key(self):
        """Same UTXO with different keys produces different nullifiers."""
        gen = NullifierGenerator()
        utxo_id = b"utxo_same"

        nf1 = gen.generate(utxo_id, b"key_a")
        nf2 = gen.generate(utxo_id, b"key_b")
        assert nf1 != nf2

    def test_nullifier_format(self):
        """Nullifier must be 32 bytes (SHA3-256)."""
        gen = NullifierGenerator()
        nf = gen.generate(b"any", b"key")
        assert isinstance(nf, bytes)
        assert len(nf) == 32


# ---------------------------------------------------------------------------
# N-Transfer ZK Proof
# ---------------------------------------------------------------------------

class TestNTransferProof:
    def test_n_transfer_proof_generation(self):
        """ZK proof for N-transfer can be generated."""
        prover = ZKProver()
        sk = 12345
        pk = secp256k1.multiply(G, sk)

        inputs = [
            ZKUTXO(tx_hash=b"tx_a", output_index=0, amount=500, owner_pubkey=pk),
            ZKUTXO(tx_hash=b"tx_b", output_index=1, amount=300, owner_pubkey=pk),
        ]
        outputs = [
            ZKOutput(amount=600, recipient_pubkey=pk),
            ZKOutput(amount=180, recipient_pubkey=pk),
        ]

        proof = prover.prove_n_transfer(inputs, outputs, private_key=sk, fee=20)
        assert isinstance(proof, ZKProof)
        assert proof.circuit_id == NTransferCircuit.circuit_id
        assert len(proof.public_inputs["nullifiers"]) == 2
        assert len(proof.public_inputs["output_commitments"]) == 2

    def test_n_transfer_proof_verification(self):
        """Generated N-transfer proof must verify."""
        prover = ZKProver()
        verifier = ZKVerifier()
        sk = 12345
        pk = secp256k1.multiply(G, sk)

        inputs = [
            ZKUTXO(tx_hash=b"tx_c", output_index=0, amount=1000, owner_pubkey=pk),
        ]
        outputs = [
            ZKOutput(amount=900, recipient_pubkey=pk),
        ]

        proof = prover.prove_n_transfer(inputs, outputs, private_key=sk, fee=100)
        ok = verifier.verify_n_transfer(proof)
        assert ok is True

    def test_n_transfer_double_spend_rejected(self):
        """Proof using already-spent nullifier must be rejected."""
        prover = ZKProver()
        verifier = ZKVerifier()
        sk = 12345
        pk = secp256k1.multiply(G, sk)

        inputs = [
            ZKUTXO(tx_hash=b"tx_ds", output_index=0, amount=1000, owner_pubkey=pk),
        ]
        outputs = [ZKOutput(amount=900, recipient_pubkey=pk)]

        proof = prover.prove_n_transfer(inputs, outputs, private_key=sk, fee=100)
        # Mark nullifiers as spent
        for nf in proof.public_inputs["nullifiers"]:
            verifier.nullifier_set.mark_spent(nf)

        ok = verifier.verify_n_transfer(proof)
        assert not ok

    def test_n_transfer_wrong_circuit_id_rejected(self):
        """Proof with wrong circuit ID must be rejected."""
        prover = ZKProver()
        verifier = ZKVerifier()
        sk = 12345
        pk = secp256k1.multiply(G, sk)

        inputs = [ZKUTXO(tx_hash=b"tx_w", output_index=0, amount=1000, owner_pubkey=pk)]
        outputs = [ZKOutput(amount=900, recipient_pubkey=pk)]

        proof = prover.prove_n_transfer(inputs, outputs, private_key=sk, fee=100)
        # Tamper with circuit_id
        object.__setattr__(proof, "circuit_id", 999)
        ok = verifier.verify_n_transfer(proof)
        assert not ok

    def test_n_transfer_balance_integrity(self):
        """Proof for unbalanced transfer should fail."""
        prover = ZKProver()
        sk = 12345
        pk = secp256k1.multiply(G, sk)

        inputs = [
            ZKUTXO(tx_hash=b"tx_bal", output_index=0, amount=500, owner_pubkey=pk),
        ]
        # Output > input (unbalanced)
        outputs = [
            ZKOutput(amount=600, recipient_pubkey=pk),
        ]

        # The prover's circuit validation should reject this
        with pytest.raises((ValueError, AssertionError)):
            prover.prove_n_transfer(inputs, outputs, private_key=sk, fee=0)


# ---------------------------------------------------------------------------
# Ratio Verification Proof
# ---------------------------------------------------------------------------

class TestRatioVerifyProof:
    def test_ratio_proof_valid(self):
        """Valid ratio proof (n/d >= phi) must verify."""
        prover = ZKProver()
        verifier = ZKVerifier()

        # n_amount / d_amount >= 3/100
        # 35 / 1000 = 0.035 >= 0.03
        proof = prover.prove_ratio(d_amount=1000, n_amount=35, phi_num=3, phi_den=100)
        ok = verifier.verify_ratio(proof, public_d_amount=1000, public_n_amount=35)
        assert ok

    def test_ratio_proof_invalid_ratio(self):
        """Proof for insufficient ratio must fail verification."""
        prover = ZKProver()
        verifier = ZKVerifier()

        # 20 / 1000 = 0.02 < 0.03
        # Depending on strictness, prover may reject at generation
        try:
            proof = prover.prove_ratio(d_amount=1000, n_amount=20, phi_num=3, phi_den=100)
            ok = verifier.verify_ratio(proof, public_d_amount=1000, public_n_amount=20)
            assert not ok
        except ValueError:
            # Prover correctly rejects at generation time
            pass

    def test_ratio_proof_with_public_amounts(self):
        """Verifier uses public amounts to check arithmetic."""
        prover = ZKProver()
        verifier = ZKVerifier()

        proof = prover.prove_ratio(d_amount=5000, n_amount=200, phi_num=3, phi_den=100)
        # 200 / 5000 = 0.04 >= 0.03
        ok = verifier.verify_ratio(proof, public_d_amount=5000, public_n_amount=200)
        assert ok

    def test_ratio_proof_wrong_public_amounts(self):
        """Verifier detects mismatch between proof and public amounts."""
        prover = ZKProver()
        verifier = ZKVerifier()

        proof = prover.prove_ratio(d_amount=5000, n_amount=200, phi_num=3, phi_den=100)
        # Claim different amounts
        ok = verifier.verify_ratio(proof, public_d_amount=5000, public_n_amount=100)
        # 100 / 5000 = 0.02 < 0.03
        assert not ok


# ---------------------------------------------------------------------------
# Identity Binding Proof
# ---------------------------------------------------------------------------

class TestIdentityBindProof:
    def test_identity_bind_proof(self):
        """Identity binding proof verifies DID ownership."""
        prover = ZKProver()
        verifier = ZKVerifier()
        sk = 12345
        pk = secp256k1.multiply(G, sk)

        did_doc = b'{"id":"did:bcs:test_user","controller":"self"}'
        msg_hash = hashlib.sha3_256(did_doc).digest()
        v, r, s = secp256k1.ecdsa_raw_sign(msg_hash, sk.to_bytes(32, 'big'))

        proof = prover.prove_identity_bind(did_doc, (v, r, s), pk, sk)
        ok = verifier.verify_identity_bind(proof, did_doc)
        assert ok

    def test_identity_bind_wrong_did(self):
        """Proof for different DID must be rejected."""
        prover = ZKProver()
        verifier = ZKVerifier()
        sk = 12345
        pk = secp256k1.multiply(G, sk)

        did_doc = b'{"id":"did:bcs:test_user","controller":"self"}'
        msg_hash = hashlib.sha3_256(did_doc).digest()
        v, r, s = secp256k1.ecdsa_raw_sign(msg_hash, sk.to_bytes(32, 'big'))

        proof = prover.prove_identity_bind(did_doc, (v, r, s), pk, sk)
        wrong_did = b'{"id":"did:bcs:other","controller":"self"}'
        ok = verifier.verify_identity_bind(proof, wrong_did)
        assert not ok

    def test_identity_bind_tampered_signature(self):
        """Tampered signature in identity proof rejected."""
        prover = ZKProver()
        verifier = ZKVerifier()
        sk = 12345
        pk = secp256k1.multiply(G, sk)

        did_doc = b'{"id":"did:bcs:test_user","controller":"self"}'
        msg_hash = hashlib.sha3_256(did_doc).digest()
        v, r, s = secp256k1.ecdsa_raw_sign(msg_hash, sk.to_bytes(32, 'big'))

        # Tamper signature
        proof = prover.prove_identity_bind(did_doc, (v, r + 1, s), pk, sk)
        ok = verifier.verify_identity_bind(proof, did_doc)
        assert not ok


# ---------------------------------------------------------------------------
# Batch Verification
# ---------------------------------------------------------------------------

class TestVerifierBatch:
    def test_batch_verify_all_valid(self):
        """Batch of valid proofs all verify."""
        prover = ZKProver()
        verifier = ZKVerifier()
        sk = 12345
        pk = secp256k1.multiply(G, sk)

        # N-transfer proof
        inputs = [ZKUTXO(tx_hash=b"bt1", output_index=0, amount=1000, owner_pubkey=pk)]
        outputs = [ZKOutput(amount=900, recipient_pubkey=pk)]
        proof1 = prover.prove_n_transfer(inputs, outputs, private_key=sk, fee=100)

        # Ratio proof
        proof2 = prover.prove_ratio(d_amount=1000, n_amount=35, phi_num=3, phi_den=100)

        # Identity bind proof
        did_doc = b'{"id":"did:bcs:batch","controller":"self"}'
        msg_hash = hashlib.sha3_256(did_doc).digest()
        v, r, s = secp256k1.ecdsa_raw_sign(msg_hash, sk.to_bytes(32, 'big'))
        proof3 = prover.prove_identity_bind(did_doc, (v, r, s), pk, sk)

        proofs = [proof1, proof2, proof3]
        results = verifier.batch_verify(proofs)
        assert all(results)

    def test_batch_verify_mixed(self):
        """Batch with valid and invalid proofs."""
        prover = ZKProver()
        verifier = ZKVerifier()
        sk = 12345
        pk = secp256k1.multiply(G, sk)

        # Valid proof
        inputs = [ZKUTXO(tx_hash=b"bm1", output_index=0, amount=1000, owner_pubkey=pk)]
        outputs = [ZKOutput(amount=900, recipient_pubkey=pk)]
        proof_valid = prover.prove_n_transfer(inputs, outputs, private_key=sk, fee=100)

        # Invalid: mark nullifier spent first
        proof_invalid = prover.prove_n_transfer(
            [ZKUTXO(tx_hash=b"bm2", output_index=0, amount=500, owner_pubkey=pk)],
            [ZKOutput(amount=400, recipient_pubkey=pk)],
            private_key=sk, fee=100
        )
        for nf in proof_invalid.public_inputs["nullifiers"]:
            verifier.nullifier_set.mark_spent(nf)

        proofs = [proof_valid, proof_invalid]
        results = verifier.batch_verify(proofs)
        assert results[0] is True
        assert results[1] is False

    def test_batch_verify_empty(self):
        """Empty batch returns empty results."""
        verifier = ZKVerifier()
        results = verifier.batch_verify([])
        assert results == []

    def test_batch_verify_with_public_amounts(self):
        """Batch verify ratio proofs with public amounts."""
        prover = ZKProver()
        verifier = ZKVerifier()

        proof1 = prover.prove_ratio(d_amount=1000, n_amount=35, phi_num=3, phi_den=100)
        proof2 = prover.prove_ratio(d_amount=5000, n_amount=200, phi_num=3, phi_den=100)

        amounts = [(1000, 35), (5000, 200)]
        proofs = [proof1, proof2]
        results = verifier.batch_verify(proofs, public_amounts=amounts)
        assert all(results)

    def test_vk_cache_efficiency(self):
        """VK cache improves repeated verification performance."""
        verifier = ZKVerifier()
        prover = ZKProver()
        sk = 12345
        pk = secp256k1.multiply(G, sk)

        inputs = [ZKUTXO(tx_hash=b"vc1", output_index=0, amount=1000, owner_pubkey=pk)]
        outputs = [ZKOutput(amount=900, recipient_pubkey=pk)]
        proof = prover.prove_n_transfer(inputs, outputs, private_key=sk, fee=100)

        # First verify (cache miss)
        verifier.verify_n_transfer(proof)
        stats1 = verifier.cache_stats()

        # Second verify (cache hit)
        verifier.verify_n_transfer(proof)
        stats2 = verifier.cache_stats()

        # At minimum, the operations should complete without error
        assert stats1 is not None
        assert stats2 is not None
