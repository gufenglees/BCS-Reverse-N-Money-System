"""
Identity & Authentication Integration Tests
=============================================
Tests for DID creation, VC issuance/verification, identity registration,
authentication flow, trust anchor management, and permission checks.
"""

import pytest
import time
from typing import Tuple

from ecdsa import SigningKey, VerifyingKey, SECP256k1

from did import DIDManager, DIDDocument, VerificationMethod
from vc import VCManager, VerifiableCredential, CredentialSubject, CredentialProof
from auth import AuthEngine, Permission
from registry import IdentityRegistry, IdentityStatus as RegIdentityStatus
from trust_anchor import TrustAnchorRegistry, TrustAnchor


# ---------------------------------------------------------------------------
# DID Creation
# ---------------------------------------------------------------------------

class TestDIDCreation:
    def test_did_creation_format(self):
        """DID must follow did:bcs:<pubkey_hash> format."""
        mgr = DIDManager()
        priv, pub = mgr.generate_keypair()
        did = mgr.create_did(priv)
        assert did.startswith("did:bcs:")
        assert len(did) > len("did:bcs:")

    def test_did_document_creation(self):
        """DID document must contain required fields."""
        mgr = DIDManager()
        priv, pub = mgr.generate_keypair()
        did = mgr.create_did(priv)
        doc = mgr.create_did_document(did, pub)
        assert doc.id == did
        assert doc.controller == did
        assert len(doc.verification_methods) > 0
        assert any(vm.controller == did for vm in doc.verification_methods)

    def test_did_document_serialization(self):
        """DID document round-trips through JSON."""
        mgr = DIDManager()
        priv, pub = mgr.generate_keypair()
        did = mgr.create_did(priv)
        doc = mgr.create_did_document(did, pub)
        json_str = DIDManager.to_json(doc)
        assert "id" in json_str
        restored = DIDManager.from_json(json_str)
        assert restored.id == did

    def test_did_uniqueness(self):
        """Different keypairs produce different DIDs."""
        mgr = DIDManager()
        dids = []
        for _ in range(5):
            priv, pub = mgr.generate_keypair()
            did = mgr.create_did(priv)
            dids.append(did)
        assert len(set(dids)) == 5


# ---------------------------------------------------------------------------
# VC Issuance
# ---------------------------------------------------------------------------

class TestVCIssuance:
    def test_vc_issuance(self, sample_dids):
        """VC can be issued for a DID with claims."""
        issuer_did = sample_dids[0]["did"]
        subject_did = sample_dids[1]["did"]
        vc_mgr = VCManager()

        vc = vc_mgr.issue(
            issuer_did=issuer_did,
            subject_did=subject_did,
            claims={"role": "consumer", "trust_level": 3},
            expiration_days=30,
        )
        assert isinstance(vc, VerifiableCredential)
        assert vc.issuer == issuer_did
        assert vc.subject == subject_did
        assert vc.subject_claims.role == "consumer"
        assert vc.proof is not None

    def test_vc_signature_valid(self, sample_dids):
        """VC signature must be verifiable."""
        issuer = sample_dids[0]
        subject = sample_dids[1]
        vc_mgr = VCManager()

        vc = vc_mgr.issue(
            issuer_did=issuer["did"],
            subject_did=subject["did"],
            claims={"role": "merchant", "trust_level": 2},
        )
        # Verify using issuer's public key
        ok = vc_mgr.verify(vc, issuer["pub"])
        assert ok is True

    def test_vc_expiration(self, sample_dids):
        """VC with past expiration must be rejected."""
        issuer = sample_dids[0]
        subject = sample_dids[1]
        vc_mgr = VCManager()

        vc = vc_mgr.issue(
            issuer_did=issuer["did"],
            subject_did=subject["did"],
            claims={"role": "worker"},
            expiration_days=-1,  # Already expired
        )
        ok = vc_mgr.verify(vc, issuer["pub"])
        assert not ok

    def test_vc_tampered_claims(self, sample_dids):
        """Tampered VC claims must fail verification."""
        issuer = sample_dids[0]
        subject = sample_dids[1]
        vc_mgr = VCManager()

        vc = vc_mgr.issue(
            issuer_did=issuer["did"],
            subject_did=subject["did"],
            claims={"role": "merchant"},
        )
        # Tamper with claims
        vc.subject_claims.role = "governance"
        ok = vc_mgr.verify(vc, issuer["pub"])
        assert not ok


# ---------------------------------------------------------------------------
# VC Verification
# ---------------------------------------------------------------------------

class TestVCVerification:
    def test_vc_chain_verification(self, sample_dids):
        """Verify chain of VCs: issuer -> subject -> nested."""
        anchor = sample_dids[0]
        intermediary = sample_dids[1]
        subject = sample_dids[2]
        vc_mgr = VCManager()

        # Anchor issues to intermediary
        vc1 = vc_mgr.issue(
            issuer_did=anchor["did"],
            subject_did=intermediary["did"],
            claims={"role": "trust_anchor_delegate", "can_issue": True},
        )
        # Intermediary issues to subject
        vc2 = vc_mgr.issue(
            issuer_did=intermediary["did"],
            subject_did=subject["did"],
            claims={"role": "authenticated_user"},
        )

        assert vc_mgr.verify(vc1, anchor["pub"])
        assert vc_mgr.verify(vc2, intermediary["pub"])

    def test_vc_revocation(self, sample_dids):
        """Revoked VC must fail verification."""
        issuer = sample_dids[0]
        subject = sample_dids[1]
        vc_mgr = VCManager()
        vc = vc_mgr.issue(
            issuer_did=issuer["did"],
            subject_did=subject["did"],
            claims={"role": "merchant"},
        )
        # Revoke
        vc_mgr.revoke(vc.id)
        ok = vc_mgr.verify(vc, issuer["pub"])
        assert not ok


# ---------------------------------------------------------------------------
# Identity Registration
# ---------------------------------------------------------------------------

class TestIdentityRegistration:
    def test_register_identity(self):
        """Identity can be registered with DID and status."""
        registry = IdentityRegistry()
        mgr = DIDManager()
        priv, pub = mgr.generate_keypair()
        did = mgr.create_did(priv)

        registry.register(did, status=RegIdentityStatus.PENDING)
        record = registry.resolve(did)
        assert record is not None
        assert record["status"] == RegIdentityStatus.PENDING

    def test_register_duplicate_rejected(self):
        """Duplicate registration must update or be rejected."""
        registry = IdentityRegistry()
        mgr = DIDManager()
        priv, pub = mgr.generate_keypair()
        did = mgr.create_did(priv)

        registry.register(did, status=RegIdentityStatus.PENDING)
        # Re-register with different status
        registry.register(did, status=RegIdentityStatus.AUTHENTICATED)
        record = registry.resolve(did)
        assert record["status"] == RegIdentityStatus.AUTHENTICATED

    def test_resolve_unknown_identity(self):
        """Resolving unknown DID returns None."""
        registry = IdentityRegistry()
        result = registry.resolve("did:bcs:unknown123")
        assert result is None

    def test_identity_status_transitions(self):
        """Valid status transitions enforced."""
        registry = IdentityRegistry()
        mgr = DIDManager()
        priv, pub = mgr.generate_keypair()
        did = mgr.create_did(priv)

        registry.register(did, status=RegIdentityStatus.PENDING)
        # Transition: PENDING -> AUTHENTICATED (valid)
        registry.update_status(did, RegIdentityStatus.AUTHENTICATED)
        assert registry.resolve(did)["status"] == RegIdentityStatus.AUTHENTICATED

        # Transition: AUTHENTICATED -> REVOKED (valid)
        registry.update_status(did, RegIdentityStatus.REVOKED)
        assert registry.resolve(did)["status"] == RegIdentityStatus.REVOKED


# ---------------------------------------------------------------------------
# Authentication Flow
# ---------------------------------------------------------------------------

class TestAuthenticationFlow:
    def test_full_auth_flow(self):
        """Complete authentication: create DID -> issue VC -> verify -> register."""
        did_mgr = DIDManager()
        vc_mgr = VCManager()
        registry = IdentityRegistry()
        auth = AuthEngine()

        # 1. User creates DID
        priv, pub = did_mgr.generate_keypair()
        did = did_mgr.create_did(priv)
        doc = did_mgr.create_did_document(did, pub)

        # 2. Trust anchor issues VC
        vc = vc_mgr.issue(
            issuer_did="did:bcs:trust_anchor",
            subject_did=did,
            claims={"role": "consumer", "verified": True},
        )

        # 3. Verify VC
        assert vc_mgr.verify(vc, pub)

        # 4. Register authenticated identity
        registry.register(did, status=RegIdentityStatus.AUTHENTICATED)
        record = registry.resolve(did)
        assert record["status"] == RegIdentityStatus.AUTHENTICATED

        # 5. Check permissions
        assert auth.check_permission(did, Permission.SEND_TRANSFER)
        assert auth.check_permission(did, Permission.RECEIVE_SALE_REBATE)

    def test_auth_flow_with_challenge(self):
        """Challenge-response authentication."""
        auth = AuthEngine()
        did_mgr = DIDManager()
        priv, pub = did_mgr.generate_keypair()
        did = did_mgr.create_did(priv)

        challenge = auth.generate_challenge(did)
        sk = SigningKey.from_string(priv, curve=SECP256k1)
        response = sk.sign_digest(
            challenge.encode(),
            sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order)
        )

        ok = auth.verify_challenge_response(did, challenge, response, pub)
        assert ok

    def test_failed_auth_wrong_signature(self):
        """Authentication fails with wrong signature."""
        auth = AuthEngine()
        did_mgr = DIDManager()
        priv, pub = did_mgr.generate_keypair()
        did = did_mgr.create_did(priv)

        challenge = auth.generate_challenge(did)
        # Sign with a different key
        wrong_sk = SigningKey.generate(curve=SECP256k1)
        response = wrong_sk.sign_digest(
            challenge.encode(),
            sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order)
        )

        ok = auth.verify_challenge_response(did, challenge, response, pub)
        assert not ok


# ---------------------------------------------------------------------------
# Trust Anchor Management
# ---------------------------------------------------------------------------

class TestTrustAnchorManagement:
    def test_add_trust_anchor(self):
        """Trust anchor can be added and retrieved."""
        ta_reg = TrustAnchorRegistry(governance_threshold=1)
        from ecdsa import SigningKey
        sk = SigningKey.generate(curve=SECP256k1)
        pub = sk.get_verifying_key().to_string("uncompressed").hex()

        anchor = ta_reg.add_anchor(
            anchor_id="ta-test-01",
            name="Test Anchor",
            public_key=pub,
            url="https://test.local",
            gov_signatures=["0xGOVSIG"],
        )
        assert anchor is not None
        assert anchor.id == "ta-test-01"
        assert anchor.status == "ACTIVE"

        retrieved = ta_reg.get_anchor("ta-test-01")
        assert retrieved is not None
        assert retrieved.id == "ta-test-01"
        assert retrieved.status == "ACTIVE"

    def test_trust_anchor_list_and_query(self):
        """Trust anchors can be listed and queried."""
        ta_reg = TrustAnchorRegistry(governance_threshold=1)
        from ecdsa import SigningKey
        sk1 = SigningKey.generate(curve=SECP256k1)
        pub1 = sk1.get_verifying_key().to_string("uncompressed").hex()
        sk2 = SigningKey.generate(curve=SECP256k1)
        pub2 = sk2.get_verifying_key().to_string("uncompressed").hex()

        ta_reg.add_anchor("ta-1", "Anchor One", pub1, "https://a1.local", ["0xSIG1"])
        ta_reg.add_anchor("ta-2", "Anchor Two", pub2, "https://a2.local", ["0xSIG2"])

        active = ta_reg.list_anchors(active_only=True)
        assert len(active) == 2

        assert ta_reg.is_trusted(pub1)
        assert ta_reg.is_trusted(pub2)

    def test_revoke_trust_anchor(self):
        """Revoked trust anchor cannot be trusted."""
        ta_reg = TrustAnchorRegistry(governance_threshold=1)
        from ecdsa import SigningKey
        sk = SigningKey.generate(curve=SECP256k1)
        pub = sk.get_verifying_key().to_string("uncompressed").hex()

        ta_reg.add_anchor("ta-revoke", "Revocable", pub, "https://r.local", ["0xSIG"])
        assert ta_reg.is_trusted(pub)

        ta_reg.remove_anchor("ta-revoke", gov_signatures=["0xSIG2"])
        assert not ta_reg.is_trusted(pub)

    def test_trust_anchor_signature_verification(self):
        """Verify anchor signatures over messages."""
        ta_reg = TrustAnchorRegistry(governance_threshold=1)
        from ecdsa import SigningKey
        import hashlib
        sk = SigningKey.generate(curve=SECP256k1)
        pub = sk.get_verifying_key().to_string("uncompressed").hex()

        ta_reg.add_anchor("ta-sig", "Signer", pub, "https://s.local", ["0xSIG"])

        msg = b"BCS trust anchor test"
        sig = sk.sign(msg, hashfunc=hashlib.sha3_256)
        ok = ta_reg.verify_anchor_signature("ta-sig", msg, sig)
        assert ok is True

        # Bad signature
        bad_sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])
        ok_bad = ta_reg.verify_anchor_signature("ta-sig", msg, bad_sig)
        assert not ok_bad

    def test_duplicate_add_rejected(self):
        """Adding duplicate anchor ID rejected."""
        ta_reg = TrustAnchorRegistry(governance_threshold=1)
        from ecdsa import SigningKey
        sk = SigningKey.generate(curve=SECP256k1)
        pub = sk.get_verifying_key().to_string("uncompressed").hex()

        ta_reg.add_anchor("ta-dup", "Dup", pub, "https://d.local", ["0xSIG"])
        with pytest.raises(ValueError):
            ta_reg.add_anchor("ta-dup", "Dup2", pub, "https://d2.local", ["0xSIG2"])

    def test_governance_threshold_enforced(self):
        """Governance threshold prevents unauthorized changes."""
        ta_reg = TrustAnchorRegistry(governance_threshold=2)
        from ecdsa import SigningKey
        sk = SigningKey.generate(curve=SECP256k1)
        pub = sk.get_verifying_key().to_string("uncompressed").hex()

        with pytest.raises(ValueError):
            ta_reg.add_anchor("ta-strict", "Strict", pub, "https://s.local", ["0xSIG"])


# ---------------------------------------------------------------------------
# Permission Checks
# ---------------------------------------------------------------------------

class TestPermissionCheck:
    def test_authenticated_permissions(self):
        """Authenticated user has expected permissions."""
        auth = AuthEngine()
        did_mgr = DIDManager()
        priv, pub = did_mgr.generate_keypair()
        did = did_mgr.create_did(priv)

        auth.register_identity(did, status=RegIdentityStatus.AUTHENTICATED)
        assert auth.check_permission(did, Permission.SEND_TRANSFER)
        assert auth.check_permission(did, Permission.RECEIVE_SALE_REBATE)
        assert auth.check_permission(did, Permission.RECEIVE_WAGE_N)
        assert auth.check_permission(did, Permission.MINT_N) is False  # Only governance

    def test_unauthenticated_permissions(self):
        """Unauthenticated user has minimal permissions."""
        auth = AuthEngine()
        did_mgr = DIDManager()
        priv, pub = did_mgr.generate_keypair()
        did = did_mgr.create_did(priv)

        auth.register_identity(did, status=RegIdentityStatus.UNAUTHENTICATED)
        assert auth.check_permission(did, Permission.SEND_TRANSFER) is False
        assert auth.check_permission(did, Permission.RECEIVE_SALE_REBATE) is False

    def test_suspended_permissions(self):
        """Suspended user loses most permissions."""
        auth = AuthEngine()
        did_mgr = DIDManager()
        priv, pub = did_mgr.generate_keypair()
        did = did_mgr.create_did(priv)

        auth.register_identity(did, status=RegIdentityStatus.AUTHENTICATED)
        auth.update_status(did, RegIdentityStatus.SUSPENDED)
        assert auth.check_permission(did, Permission.SEND_TRANSFER) is False
        assert auth.check_permission(did, Permission.RECEIVE_SALE_REBATE) is False

    def test_permission_hierarchy(self):
        """Higher trust levels get more permissions."""
        auth = AuthEngine()
        did_mgr = DIDManager()

        priv_user, pub_user = did_mgr.generate_keypair()
        did_user = did_mgr.create_did(priv_user)
        auth.register_identity(did_user, status=RegIdentityStatus.AUTHENTICATED, trust_level=1)

        priv_gov, pub_gov = did_mgr.generate_keypair()
        did_gov = did_mgr.create_did(priv_gov)
        auth.register_identity(did_gov, status=RegIdentityStatus.AUTHENTICATED, trust_level=5)

        assert auth.check_permission(did_user, Permission.GOVERNANCE_VOTE) is False
        assert auth.check_permission(did_gov, Permission.GOVERNANCE_VOTE) is True

    def test_role_based_permissions(self):
        """Role-based permission assignment."""
        auth = AuthEngine()
        did_mgr = DIDManager()

        priv_merchant, pub_merchant = did_mgr.generate_keypair()
        did_merchant = did_mgr.create_did(priv_merchant)
        auth.register_identity(did_merchant, status=RegIdentityStatus.AUTHENTICATED, roles=["merchant"])

        priv_employer, pub_employer = did_mgr.generate_keypair()
        did_employer = did_mgr.create_did(priv_employer)
        auth.register_identity(did_employer, status=RegIdentityStatus.AUTHENTICATED, roles=["employer"])

        assert auth.check_permission(did_merchant, Permission.CREATE_SALE)
        assert auth.check_permission(did_employer, Permission.CREATE_WAGE)
        assert auth.check_permission(did_merchant, Permission.CREATE_WAGE) is False
