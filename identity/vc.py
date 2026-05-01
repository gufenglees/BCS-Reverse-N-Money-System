"""
Verifiable Credential (VC) Module for BCS

Implements a simplified W3C Verifiable Credential Data Model 1.1
compatible with the ``did:bcs`` method.

Architecture reference: architecture_design.md §2.4 (Identity Module)

A VC in BCS has type ``BCSIdentityCredential`` and is issued by a
Trust Anchor to bind a real-world identity to a DID.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any

try:
    from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
except ImportError:  # pragma: no cover
    raise ImportError("Install `ecdsa` to use the BCS identity module: pip install ecdsa")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VC_TYPE_BASE: str = "VerifiableCredential"
VC_TYPE_BCS: str = "BCSIdentityCredential"
PROOF_TYPE_ECDSA: str = "EcdsaSecp256k1Signature2019"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CredentialSubject:
    """
    The entity about which claims are being made.

    Attributes:
        id: Subject DID.
        claims: Arbitrary key-value claims (e.g. ``{"name": "Alice"}``).
    """
    id: str
    claims: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CredentialProof:
    """
    Cryptographic proof that the issuer signed the credential.

    Attributes:
        type: Signature suite identifier.
        created: ISO-8601 timestamp when the proof was created.
        verification_method: DID URL of the issuer's signing key.
        proof_value: Base64-encoded DER ECDSA signature.
    """
    type: str
    created: str
    verification_method: str
    proof_value: str


@dataclass
class VerifiableCredential:
    """
    A W3C-compatible Verifiable Credential.

    Attributes:
        id: Unique VC identifier (UUID URI).
        type: List of credential types.
        issuer: DID of the issuing Trust Anchor.
        issuance_date: ISO-8601 issuance timestamp.
        expiration_date: ISO-8601 expiration timestamp (optional).
        credential_subject: The subject and its claims.
        proof: Embedded cryptographic proof (optional until issuance).
    """
    id: str
    type: List[str]
    issuer: str
    issuance_date: str
    expiration_date: Optional[str]
    credential_subject: CredentialSubject
    proof: Optional[CredentialProof] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Return current UTC time as ISO-8601 string with 'Z' suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _iso_offset_days(days: int) -> str:
    """Return UTC time *days* from now as ISO-8601 string."""
    dt = datetime.now(timezone.utc) + timedelta(days=days)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_dict(vc: VerifiableCredential) -> dict:
    """
    Build a canonical dict of the credential *excluding* the proof
    (the proof signs over everything else).
    """
    return {
        "id": vc.id,
        "type": vc.type,
        "issuer": vc.issuer,
        "issuanceDate": vc.issuance_date,
        "expirationDate": vc.expiration_date,
        "credentialSubject": {
            "id": vc.credential_subject.id,
            **vc.credential_subject.claims,
        },
    }


def _serialize_canonical(obj: dict) -> bytes:
    """Deterministic JSON serialization for signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# VC Manager
# ---------------------------------------------------------------------------

class VCManager:
    """
    Issue, verify, revoke and inspect Verifiable Credentials.

    Responsibilities:
        - Issue a ``BCSIdentityCredential`` signed by a Trust Anchor.
        - Verify VC signature and expiration.
        - Maintain a simple revocation list (in-memory; production would use
          a CRL or on-chain revocation Merkle tree).
    """

    def __init__(self) -> None:
        # In-memory revocation list: vc_id -> revocation_timestamp
        self._revocations: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Issuance
    # ------------------------------------------------------------------

    def issue_credential(
        self,
        issuer_did: str,
        issuer_key: bytes,
        subject_did: str,
        claims: Dict[str, Any],
        expiry_days: int = 365,
        verification_method: Optional[str] = None,
    ) -> VerifiableCredential:
        """
        Issue a new ``BCSIdentityCredential``.

        The credential is signed with the issuer's secp256k1 private key.
        The signature covers the canonical JSON serialization of the
        credential body (everything except ``proof``).

        Args:
            issuer_did: DID of the issuing Trust Anchor.
            issuer_key: 32-byte secp256k1 private key.
            subject_did: DID of the credential subject.
            claims: Subject claims dictionary.
            expiry_days: Days until expiration.
            verification_method: DID URL of the signing key (default
                                 ``{issuer_did}#keys-1``).

        Returns:
            A signed ``VerifiableCredential``.
        """
        if verification_method is None:
            verification_method = f"{issuer_did}#keys-1"

        vc_id = f"urn:uuid:{uuid.uuid4()}"
        issuance = _now_iso()
        expiration = _iso_offset_days(expiry_days)

        subject = CredentialSubject(id=subject_did, claims=claims)

        vc = VerifiableCredential(
            id=vc_id,
            type=[VC_TYPE_BASE, VC_TYPE_BCS],
            issuer=issuer_did,
            issuance_date=issuance,
            expiration_date=expiration,
            credential_subject=subject,
            proof=None,
        )

        # Sign the canonical body
        canonical = _canonical_dict(vc)
        payload = _serialize_canonical(canonical)

        sk = SigningKey.from_string(issuer_key, curve=SECP256k1)
        signature = sk.sign(payload, hashfunc=hashlib.sha3_256)
        sig_b64 = _b64encode(signature)

        vc.proof = CredentialProof(
            type=PROOF_TYPE_ECDSA,
            created=issuance,
            verification_method=verification_method,
            proof_value=sig_b64,
        )
        return vc

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_credential(
        self,
        vc: VerifiableCredential,
        issuer_public_key: bytes,
    ) -> bool:
        """
        Verify a Verifiable Credential.

        Checks performed:
            1. Signature is valid and was produced by *issuer_public_key*.
            2. The credential has not expired (UTC wall-clock time).
            3. The credential has not been revoked.

        Args:
            vc: The credential to verify.
            issuer_public_key: 65-byte uncompressed secp256k1 public key.

        Returns:
            ``True`` if the credential is valid and unexpired, else ``False``.
        """
        # --- 1. Check revocation ---
        if self.check_revoked(vc.id):
            return False

        # --- 2. Check expiration ---
        if vc.expiration_date:
            try:
                exp_dt = datetime.fromisoformat(vc.expiration_date.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) > exp_dt:
                    return False
            except ValueError:
                return False

        # --- 3. Verify signature ---
        if vc.proof is None:
            return False

        try:
            canonical = _canonical_dict(vc)
            payload = _serialize_canonical(canonical)
            signature = _b64decode(vc.proof.proof_value)
            vk = VerifyingKey.from_string(issuer_public_key, curve=SECP256k1)
            vk.verify(signature, payload, hashfunc=hashlib.sha3_256)
        except (BadSignatureError, ValueError, Exception):
            return False

        return True

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def revoke_credential(
        self,
        vc_id: str,
        revocation_list: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Revoke a credential by adding it to the revocation list.

        Args:
            vc_id: The credential UUID / URN.
            revocation_list: Optional external dict to write the revocation
                             into.  If ``None``, the manager's internal list
                             is used.
        """
        now = _now_iso()
        if revocation_list is not None:
            revocation_list[vc_id] = now
        self._revocations[vc_id] = now

    def check_revoked(
        self,
        vc_id: str,
        revocation_list: Optional[Dict[str, str]] = None,
    ) -> bool:
        """
        Check whether a credential has been revoked.

        Args:
            vc_id: The credential identifier.
            revocation_list: Optional external dict.  If ``None``, the
                             internal list is queried.

        Returns:
            ``True`` if the credential is revoked.
        """
        if revocation_list is not None:
            return vc_id in revocation_list
        return vc_id in self._revocations

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    @staticmethod
    def to_json(vc: VerifiableCredential) -> str:
        """Serialize a VerifiableCredential to JSON-LD string."""
        data = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "id": vc.id,
            "type": vc.type,
            "issuer": vc.issuer,
            "issuanceDate": vc.issuance_date,
            "expirationDate": vc.expiration_date,
            "credentialSubject": {
                "id": vc.credential_subject.id,
                **vc.credential_subject.claims,
            },
        }
        if vc.proof is not None:
            data["proof"] = {
                "type": vc.proof.type,
                "created": vc.proof.created,
                "verificationMethod": vc.proof.verification_method,
                "proofValue": vc.proof.proof_value,
            }
        return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False)

    @staticmethod
    def from_json(json_str: str) -> VerifiableCredential:
        """Deserialize a VerifiableCredential from JSON-LD string."""
        data = json.loads(json_str)
        proof_data = data.get("proof")
        proof = None
        if proof_data:
            proof = CredentialProof(
                type=proof_data["type"],
                created=proof_data["created"],
                verification_method=proof_data["verificationMethod"],
                proof_value=proof_data["proofValue"],
            )
        subject = data.get("credentialSubject", {})
        subject_id = subject.pop("id", "")
        return VerifiableCredential(
            id=data["id"],
            type=data.get("type", [VC_TYPE_BASE]),
            issuer=data["issuer"],
            issuance_date=data["issuanceDate"],
            expiration_date=data.get("expirationDate"),
            credential_subject=CredentialSubject(id=subject_id, claims=subject),
            proof=proof,
        )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def get_subject_claim(vc: VerifiableCredential, key: str, default: Any = None) -> Any:
        """Convenience accessor for a subject claim."""
        return vc.credential_subject.claims.get(key, default)


# ---------------------------------------------------------------------------
# Base64 helpers
# ---------------------------------------------------------------------------

def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data)


# Need base64 import for helpers above
import base64  # noqa: E402

# =============================================================================
# Self-test
# =============================================================================

def _self_test() -> None:
    print("=" * 60)
    print("BCS Identity — VC Module Self-Test")
    print("=" * 60)

    mgr = VCManager()

    # Generate issuer key pair
    issuer_sk = SigningKey.generate(curve=SECP256k1)
    issuer_vk = issuer_sk.get_verifying_key()
    issuer_pub = issuer_vk.to_string("uncompressed")
    issuer_did = f"did:bcs:{'00'*32}"  # dummy issuer DID

    subject_did = "did:bcs:{'11'*32}"
    claims = {"name": "Alice", "country": " Wonderland", "role": "validator"}

    # 1. Issue
    vc = mgr.issue_credential(
        issuer_did=issuer_did,
        issuer_key=issuer_sk.to_string(),
        subject_did=subject_did,
        claims=claims,
        expiry_days=365,
    )
    print(f"\n[1] VC issued")
    print(f"    ID    : {vc.id}")
    print(f"    Issuer: {vc.issuer}")
    print(f"    Subject: {vc.credential_subject.id}")
    print(f"    Claims: {vc.credential_subject.claims}")
    print(f"    Proof : type={vc.proof.type}, vm={vc.proof.verification_method}")
    assert vc.proof is not None

    # 2. Verify (good)
    ok = mgr.verify_credential(vc, issuer_pub)
    print(f"\n[2] Verification (valid): {ok}")
    assert ok is True

    # 3. Verify with wrong key
    bad_sk = SigningKey.generate(curve=SECP256k1)
    bad_pub = bad_sk.get_verifying_key().to_string("uncompressed")
    ok_bad = mgr.verify_credential(vc, bad_pub)
    print(f"[3] Verification (wrong key): {ok_bad}")
    assert ok_bad is False

    # 4. Revoke and check
    mgr.revoke_credential(vc.id)
    revoked = mgr.check_revoked(vc.id)
    print(f"[4] Revoked: {revoked}")
    assert revoked is True

    # 5. Verification should now fail (revoked)
    ok_revoked = mgr.verify_credential(vc, issuer_pub)
    print(f"[5] Verification after revocation: {ok_revoked}")
    assert ok_revoked is False

    # 6. JSON round-trip
    json_str = mgr.to_json(vc)
    vc2 = mgr.from_json(json_str)
    print(f"\n[6] JSON round-trip OK: {vc2.id == vc.id}")
    assert vc2.id == vc.id
    assert vc2.proof.proof_value == vc.proof.proof_value

    # 7. Expired credential
    expired_vc = mgr.issue_credential(
        issuer_did=issuer_did,
        issuer_key=issuer_sk.to_string(),
        subject_did=subject_did,
        claims={"name": "Bob"},
        expiry_days=-1,  # already expired
    )
    ok_expired = mgr.verify_credential(expired_vc, issuer_pub)
    print(f"[7] Expired credential rejected: {ok_expired is False}")
    assert ok_expired is False

    # 8. External revocation list
    external_rl: Dict[str, str] = {}
    external_vc = mgr.issue_credential(
        issuer_did=issuer_did,
        issuer_key=issuer_sk.to_string(),
        subject_did=subject_did,
        claims={"name": "Charlie"},
        expiry_days=1,
    )
    mgr.revoke_credential(external_vc.id, revocation_list=external_rl)
    assert external_vc.id in external_rl
    print(f"[8] External revocation list works: True")

    print("\n" + "=" * 60)
    print("All VC module self-tests PASSED ✓")
    print("=" * 60)


if __name__ == "__main__":
    _self_test()
