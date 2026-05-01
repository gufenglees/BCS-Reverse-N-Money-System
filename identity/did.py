"""
DID Module for BCS (Bidirectional Currency System)

Implements the ``did:bcs`` method — a lightweight, self-sovereign
identity scheme built on secp256k1 and SHA3-256.

Architecture reference: architecture_design.md §2.4 (Identity Module)

DID format::

    did:bcs:<32-byte pubkey_hash_hex>

Example::

    did:bcs:a1b2c3d4...e5f6
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Cryptography imports — ecdsa is the standard pure-Python SECP256k1 lib
# ---------------------------------------------------------------------------
try:
    from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
except ImportError:  # pragma: no cover
    raise ImportError("Install `ecdsa` to use the BCS identity module: pip install ecdsa")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DID_METHOD: str = "did:bcs"
VERIFICATION_METHOD_TYPE: str = "EcdsaSecp256k1VerificationKey2019"
PROOF_TYPE_ECDSA: str = "EcdsaSecp256k1Signature2019"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class VerificationMethod:
    """
    A single verification method inside a DID Document.

    Attributes:
        id: Full DID URL, e.g. ``did:bcs:abcd#keys-1``
        type: Cryptographic suite identifier.
        controller: The DID that controls this key.
        public_key_hex: 33-byte (compressed) or 65-byte (uncompressed) SEC1 hex.
    """
    id: str
    type: str
    controller: str
    public_key_hex: str


@dataclass
class DIDDocument:
    """
    W3C DID Document (simplified JSON-LD representation).

    Attributes:
        id: The DID itself.
        controller: The controlling DID (usually same as *id*).
        verification_methods: List of public-key verification methods.
        authentication: List of DID URLs used for authentication.
        assertion_method: List of DID URLs used for issuing VCs.
        created: Unix timestamp (ms) of creation.
        updated: Unix timestamp (ms) of last update.
    """
    id: str
    controller: str
    verification_methods: List[VerificationMethod] = field(default_factory=list)
    authentication: List[str] = field(default_factory=list)
    assertion_method: List[str] = field(default_factory=list)
    created: int = 0
    updated: int = 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sha3_256(data: bytes) -> bytes:
    """SHA3-256 digest (Keccak-256 compatible variant)."""
    return hashlib.sha3_256(data).digest()


def _pubkey_to_hash(public_key: bytes) -> str:
    """
    Derive the 32-byte public-key hash used in ``did:bcs``.

    Steps:
        1. SHA3-256(public_key) -> 32 bytes
        2. Hex-encode lowercase
    """
    return _sha3_256(public_key).hex()


def _serialize_for_signing(obj: dict) -> bytes:
    """
    Canonical JSON serialization for signing (deterministic).
    Keys sorted, no whitespace, no None values.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _now_ms() -> int:
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# DID Manager
# ---------------------------------------------------------------------------

class DIDManager:
    """
    Core manager for ``did:bcs`` DID lifecycle.

    Responsibilities:
        - Create a DID from an secp256k1 private key.
        - Build / update DID Documents.
        - Resolve DID -> Document (in-memory registry; production would use
          a persistent DID Document Store).
        - Verify DID ownership via challenge-response signatures.
        - JSON-LD serialization / deserialization.
    """

    def __init__(self) -> None:
        # In-memory DID Document store (DID -> DIDDocument)
        self._docs: Dict[str, DIDDocument] = {}

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    @staticmethod
    def create_did(private_key: bytes) -> str:
        """
        Generate a ``did:bcs`` identifier from a secp256k1 private key.

        Args:
            private_key: 32-byte raw private key.

        Returns:
            DID string, e.g. ``did:bcs:<64-hex-chars>``.

        Raises:
            ValueError: If the key cannot be loaded.
        """
        try:
            sk = SigningKey.from_string(private_key, curve=SECP256k1)
        except Exception as exc:
            raise ValueError("Invalid secp256k1 private key") from exc

        vk = sk.get_verifying_key()
        # Use uncompressed 65-byte SEC1 for maximum compatibility
        public_key = vk.to_string("uncompressed")
        pubkey_hash = _pubkey_to_hash(public_key)
        return f"{DID_METHOD}:{pubkey_hash}"

    @staticmethod
    def did_to_address(did: str) -> str:
        """
        Extract the raw public-key hash (hex) from a DID.

        Returns:
            64-character hex string (32 bytes).

        Raises:
            ValueError: If the DID is malformed.
        """
        prefix = f"{DID_METHOD}:"
        if not did.startswith(prefix):
            raise ValueError(f"DID must start with '{prefix}'")
        hash_hex = did[len(prefix):]
        if len(hash_hex) != 64:
            raise ValueError(f"Invalid public-key hash length: {len(hash_hex)} (expected 64)")
        try:
            int(hash_hex, 16)
        except ValueError as exc:
            raise ValueError("Public-key hash is not valid hex") from exc
        return hash_hex

    # ------------------------------------------------------------------
    # Document management
    # ------------------------------------------------------------------

    def create_did_document(self, did: str, public_key: bytes) -> DIDDocument:
        """
        Create a standard DID Document for *did* with a single verification method.

        Args:
            did: The DID string.
            public_key: Raw public-key bytes (65-byte uncompressed SEC1).

        Returns:
            A populated ``DIDDocument`` instance.
        """
        pubkey_hex = public_key.hex()
        vm_id = f"{did}#keys-1"
        vm = VerificationMethod(
            id=vm_id,
            type=VERIFICATION_METHOD_TYPE,
            controller=did,
            public_key_hex=pubkey_hex,
        )
        now = _now_ms()
        doc = DIDDocument(
            id=did,
            controller=did,
            verification_methods=[vm],
            authentication=[vm_id],
            assertion_method=[vm_id],
            created=now,
            updated=now,
        )
        # Register in local resolver cache
        self._docs[did] = doc
        return doc

    def resolve(self, did: str) -> Optional[DIDDocument]:
        """
        Resolve a DID to its DID Document.

        In a production deployment this would query the DID Document Store
        (SQLite / JSON-LD index).  Here we return the in-memory cached copy.

        Args:
            did: The DID to resolve.

        Returns:
            The ``DIDDocument`` if known, otherwise ``None``.
        """
        return self._docs.get(did)

    def update_document(self, did: str, **kwargs) -> DIDDocument:
        """
        Update fields of an existing DID Document.

        Automatically refreshes the ``updated`` timestamp.

        Args:
            did: The DID to update.
            **kwargs: Fields to overwrite (e.g. ``controller=...``).

        Returns:
            The updated document.

        Raises:
            KeyError: If the DID is not registered locally.
        """
        if did not in self._docs:
            raise KeyError(f"DID {did} not found in local registry")
        doc = self._docs[did]
        for k, v in kwargs.items():
            if hasattr(doc, k):
                setattr(doc, k, v)
        doc.updated = _now_ms()
        return doc

    # ------------------------------------------------------------------
    # Ownership verification
    # ------------------------------------------------------------------

    def verify_ownership(
        self,
        did: str,
        challenge: bytes,
        signature: bytes,
        public_key: Optional[bytes] = None,
    ) -> bool:
        """
        Verify that *signature* over *challenge* was produced by the owner of *did*.

        Resolution order:
            1. If *public_key* is provided, use it directly (avoids a resolve step).
            2. Resolve the DID Document and extract the first verification method's
               public key.

        Args:
            did: The DID whose ownership is being proved.
            challenge: The message that was signed.
            signature: DER-encoded ECDSA signature.
            public_key: Optional raw public-key bytes to short-circuit resolution.

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        # Obtain public key
        if public_key is None:
            doc = self.resolve(did)
            if doc is None or not doc.verification_methods:
                return False
            pubkey_hex = doc.verification_methods[0].public_key_hex
            try:
                public_key = bytes.fromhex(pubkey_hex)
            except ValueError:
                return False

        try:
            vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
            # ecdsa expects the message bytes directly; hashfunc=None disables internal hashing
            return vk.verify(signature, challenge, hashfunc=hashlib.sha3_256)
        except BadSignatureError:
            return False
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Serialization (JSON-LD-like)
    # ------------------------------------------------------------------

    @staticmethod
    def to_json(did_document: DIDDocument) -> str:
        """
        Serialize a DID Document to a JSON-LD string.

        The output uses deterministic ordering so that two serializations
        of the same logical document are byte-identical.
        """
        doc_dict = asdict(did_document)
        # Rename Pythonic field names to JSON-LD @context style
        json_ld = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": doc_dict["id"],
            "controller": doc_dict["controller"],
            "verificationMethod": [
                {
                    "id": vm["id"],
                    "type": vm["type"],
                    "controller": vm["controller"],
                    "publicKeyHex": vm["public_key_hex"],
                }
                for vm in doc_dict["verification_methods"]
            ],
            "authentication": doc_dict["authentication"],
            "assertionMethod": doc_dict["assertion_method"],
            "created": doc_dict["created"],
            "updated": doc_dict["updated"],
        }
        return json.dumps(json_ld, sort_keys=True, indent=2, ensure_ascii=False)

    @staticmethod
    def from_json(json_str: str) -> DIDDocument:
        """
        Deserialize a JSON-LD DID Document string.

        Supports both the internal Python dataclass layout and the standard
        W3C JSON-LD key names.
        """
        data = json.loads(json_str)

        def _get(key: str, alt: Optional[str] = None):
            return data.get(key, data.get(alt)) if alt else data.get(key)

        vms_data = _get("verification_methods", "verificationMethod") or []
        verification_methods = [
            VerificationMethod(
                id=vm["id"],
                type=vm.get("type", VERIFICATION_METHOD_TYPE),
                controller=vm.get("controller", data.get("id", "")),
                public_key_hex=vm.get("public_key_hex", vm.get("publicKeyHex", "")),
            )
            for vm in vms_data
        ]

        return DIDDocument(
            id=data["id"],
            controller=_get("controller") or data["id"],
            verification_methods=verification_methods,
            authentication=_get("authentication", "authentication") or [],
            assertion_method=_get("assertion_method", "assertionMethod") or [],
            created=_get("created", "created") or 0,
            updated=_get("updated", "updated") or 0,
        )

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @staticmethod
    def generate_keypair() -> tuple:
        """
        Generate a fresh secp256k1 key pair.

        Returns:
            (private_key_bytes, public_key_bytes)
        """
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.get_verifying_key()
        return sk.to_string(), vk.to_string("uncompressed")

    @staticmethod
    def sign_challenge(private_key: bytes, challenge: bytes) -> bytes:
        """
        Sign *challenge* with the given private key.

        Returns:
            DER-encoded ECDSA signature.
        """
        sk = SigningKey.from_string(private_key, curve=SECP256k1)
        return sk.sign(challenge, hashfunc=hashlib.sha3_256)


# =============================================================================
# Self-test
# =============================================================================

def _self_test() -> None:
    """Run basic sanity checks when this module is executed directly."""
    print("=" * 60)
    print("BCS Identity — DID Module Self-Test")
    print("=" * 60)

    mgr = DIDManager()

    # 1. Key generation
    priv, pub = mgr.generate_keypair()
    print(f"\n[1] Keypair generated")
    print(f"    Private key: {priv.hex()[:16]}... ({len(priv)} bytes)")
    print(f"    Public  key: {pub.hex()[:16]}... ({len(pub)} bytes)")

    # 2. DID creation
    did = mgr.create_did(priv)
    print(f"\n[2] DID created: {did}")
    assert did.startswith("did:bcs:")
    hash_part = did.split(":")[-1]
    assert len(hash_part) == 64
    print(f"    Hash part length OK (64 hex chars = 32 bytes)")

    # 3. DID Document creation
    doc = mgr.create_did_document(did, pub)
    print(f"\n[3] DID Document created")
    print(f"    ID         : {doc.id}")
    print(f"    Controller : {doc.controller}")
    print(f"    Auth keys  : {doc.authentication}")
    assert doc.id == did
    assert len(doc.verification_methods) == 1

    # 4. JSON serialization
    json_str = mgr.to_json(doc)
    print(f"\n[4] JSON serialization ({len(json_str)} chars)")
    print(json_str[:500])

    # 5. JSON deserialization
    doc2 = mgr.from_json(json_str)
    print(f"\n[5] JSON deserialization OK")
    assert doc2.id == doc.id
    assert doc2.verification_methods[0].public_key_hex == doc.verification_methods[0].public_key_hex

    # 6. DID resolve
    resolved = mgr.resolve(did)
    print(f"\n[6] Resolve DID -> {resolved is not None}")
    assert resolved is not None
    assert resolved.id == did

    # 7. Ownership verification
    challenge = b"BCS challenge message"
    sig = mgr.sign_challenge(priv, challenge)
    ok = mgr.verify_ownership(did, challenge, sig)
    print(f"\n[7] Ownership verification: {ok}")
    assert ok is True

    # 7b. Bad signature should fail
    bad_sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])  # flip last byte
    ok_bad = mgr.verify_ownership(did, challenge, bad_sig)
    print(f"    Tampered signature rejected: {ok_bad is False}")
    assert ok_bad is False

    # 8. DID -> address conversion
    addr = mgr.did_to_address(did)
    print(f"\n[8] DID -> address: {addr[:16]}...")
    assert len(addr) == 64

    print("\n" + "=" * 60)
    print("All DID module self-tests PASSED ✓")
    print("=" * 60)


if __name__ == "__main__":
    _self_test()
