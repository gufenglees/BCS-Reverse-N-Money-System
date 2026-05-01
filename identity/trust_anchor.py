"""
Trust Anchor Registry Module for BCS

Manages the set of authorised Trust Anchors — entities that are permitted
to issue Verifiable Credentials (e.g. KYC providers, government agencies).

Every addition or removal of a Trust Anchor requires governance-level
multi-signature approval.

Architecture reference: architecture_design.md §2.4 (Identity Module)
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
except ImportError:  # pragma: no cover
    raise ImportError("Install `ecdsa` to use the BCS identity module: pip install ecdsa")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TRUST_ANCHOR_ACTIVE: str = "ACTIVE"
TRUST_ANCHOR_REMOVED: str = "REMOVED"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class TrustAnchor:
    """
    A trusted entity authorised to issue VCs.

    Attributes:
        id: Unique anchor identifier (short code, e.g. ``ta-gov-01``).
        name: Human-readable name.
        public_key: 65-byte uncompressed secp256k1 public key (hex).
        url: Optional endpoint URL for the anchor's services.
        status: ``ACTIVE`` or ``REMOVED``.
        added_at: Unix timestamp (ms) when the anchor was added.
    """
    id: str
    name: str
    public_key: str
    url: str
    status: str = TRUST_ANCHOR_ACTIVE
    added_at: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)


def _check_governance_signatures(gov_signatures: List[str], threshold: int = 1) -> None:
    """
    Validate that enough governance signatures are present.

    In a real deployment each signature would be an ECDSA signature over a
    governance message and would be checked against the active validator set.
    Here we enforce a minimum count and non-empty strings.

    Args:
        gov_signatures: List of hex-encoded governance signatures.
        threshold: Minimum required signatures.

    Raises:
        ValueError: If the threshold is not met or any signature is empty.
    """
    if len(gov_signatures) < threshold:
        raise ValueError(
            f"Governance threshold not met: {len(gov_signatures)} < {threshold}"
        )
    for sig in gov_signatures:
        if not sig or not isinstance(sig, str):
            raise ValueError("All governance signatures must be non-empty strings")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TrustAnchorRegistry:
    """
    In-memory registry of authorised Trust Anchors.

    Production note: In a real deployment the anchor set would be stored
    on-chain or in a replicated SQLite / LevelDB so that all nodes agree on
    the same trust root.
    """

    def __init__(self, governance_threshold: int = 1) -> None:
        """
        Args:
            governance_threshold: Minimum number of governance signatures
                                  required for anchor mutations.
        """
        self._anchors: Dict[str, TrustAnchor] = {}
        self._threshold = governance_threshold

    # ------------------------------------------------------------------
    # Mutation (governance-gated)
    # ------------------------------------------------------------------

    def add_anchor(
        self,
        anchor_id: str,
        name: str,
        public_key: str,
        url: str,
        gov_signatures: List[str],
    ) -> TrustAnchor:
        """
        Register a new Trust Anchor.

        Args:
            anchor_id: Unique identifier for the anchor.
            name: Human-readable name.
            public_key: 65-byte uncompressed secp256k1 public key (hex).
            url: Service endpoint URL.
            gov_signatures: Governance multi-signatures authorising this addition.

        Returns:
            The newly created ``TrustAnchor``.

        Raises:
            ValueError: If the anchor already exists or governance threshold
                        is not met.
        """
        _check_governance_signatures(gov_signatures, self._threshold)

        if anchor_id in self._anchors:
            raise ValueError(f"Trust anchor '{anchor_id}' already exists")

        # Validate public key format
        try:
            VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
        except Exception as exc:
            raise ValueError(f"Invalid secp256k1 public key: {exc}") from exc

        anchor = TrustAnchor(
            id=anchor_id,
            name=name,
            public_key=public_key,
            url=url,
            status=TRUST_ANCHOR_ACTIVE,
            added_at=_now_ms(),
        )
        self._anchors[anchor_id] = anchor
        return anchor

    def remove_anchor(
        self,
        anchor_id: str,
        gov_signatures: List[str],
    ) -> TrustAnchor:
        """
        Remove (deactivate) a Trust Anchor.

        The anchor is marked ``REMOVED`` rather than deleted so that
        historical credentials issued by it remain auditable.

        Args:
            anchor_id: The anchor to remove.
            gov_signatures: Governance multi-signatures.

        Returns:
            The updated ``TrustAnchor``.

        Raises:
            ValueError: If the anchor does not exist or governance threshold
                        is not met.
        """
        _check_governance_signatures(gov_signatures, self._threshold)

        if anchor_id not in self._anchors:
            raise ValueError(f"Trust anchor '{anchor_id}' not found")

        anchor = self._anchors[anchor_id]
        anchor.status = TRUST_ANCHOR_REMOVED
        return anchor

    # ------------------------------------------------------------------
    # Signature verification
    # ------------------------------------------------------------------

    def verify_anchor_signature(
        self,
        anchor_id: str,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """
        Verify that *signature* over *message* was produced by the active
        Trust Anchor identified by *anchor_id*.

        Args:
            anchor_id: The anchor identifier.
            message: The signed payload.
            signature: DER-encoded ECDSA signature.

        Returns:
            ``True`` if the signature is valid and the anchor is ACTIVE.
        """
        anchor = self._anchors.get(anchor_id)
        if anchor is None:
            return False
        if anchor.status != TRUST_ANCHOR_ACTIVE:
            return False

        try:
            vk = VerifyingKey.from_string(bytes.fromhex(anchor.public_key), curve=SECP256k1)
            vk.verify(signature, message, hashfunc=hashlib.sha3_256)
            return True
        except (BadSignatureError, ValueError, Exception):
            return False

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def list_anchors(self, active_only: bool = True) -> List[TrustAnchor]:
        """
        List registered Trust Anchors.

        Args:
            active_only: If ``True``, filter to anchors with ``status=ACTIVE``.

        Returns:
            List of ``TrustAnchor`` objects.
        """
        anchors = list(self._anchors.values())
        if active_only:
            anchors = [a for a in anchors if a.status == TRUST_ANCHOR_ACTIVE]
        return anchors

    def is_trusted(self, public_key: str) -> bool:
        """
        Check whether a public key belongs to an active Trust Anchor.

        Args:
            public_key: 65-byte uncompressed secp256k1 public key (hex).

        Returns:
            ``True`` if the key is in the active trust set.
        """
        for anchor in self._anchors.values():
            if anchor.status == TRUST_ANCHOR_ACTIVE and anchor.public_key == public_key:
                return True
        return False

    def get_anchor(self, anchor_id: str) -> Optional[TrustAnchor]:
        """Retrieve a single anchor by ID."""
        return self._anchors.get(anchor_id)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        """Export the full registry as JSON."""
        return json.dumps(
            {aid: asdict(a) for aid, a in self._anchors.items()},
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )

    def from_json(self, json_str: str) -> None:
        """Import a registry from JSON (overwrites current state)."""
        data: Dict[str, dict] = json.loads(json_str)
        self._anchors.clear()
        for aid, d in data.items():
            self._anchors[aid] = TrustAnchor(**d)


# =============================================================================
# Self-test
# =============================================================================

def _self_test() -> None:
    print("=" * 60)
    print("BCS Identity — Trust Anchor Module Self-Test")
    print("=" * 60)

    from ecdsa import SigningKey

    # Generate a test anchor key pair
    anchor_sk = SigningKey.generate(curve=SECP256k1)
    anchor_vk = anchor_sk.get_verifying_key()
    anchor_pub = anchor_vk.to_string("uncompressed").hex()

    reg = TrustAnchorRegistry(governance_threshold=1)

    # 1. Add anchor
    ta = reg.add_anchor(
        anchor_id="ta-gov-01",
        name="Government KYC Office",
        public_key=anchor_pub,
        url="https://kyc.bcs.local",
        gov_signatures=["0xGOVSIG01"],
    )
    print(f"\n[1] Added trust anchor: {ta.id} ({ta.name})")
    assert ta.status == TRUST_ANCHOR_ACTIVE

    # 2. Duplicate add should fail
    try:
        reg.add_anchor(
            anchor_id="ta-gov-01",
            name="Duplicate",
            public_key=anchor_pub,
            url="https://dup.local",
            gov_signatures=["0xGOVSIG02"],
        )
        assert False, "Should have raised ValueError"
    except ValueError as exc:
        print(f"[2] Duplicate rejected: {exc}")

    # 3. List anchors
    active = reg.list_anchors(active_only=True)
    print(f"[3] Active anchors: {len(active)}")
    assert len(active) == 1

    # 4. is_trusted
    trusted = reg.is_trusted(anchor_pub)
    print(f"[4] is_trusted(pubkey) = {trusted}")
    assert trusted is True

    untrusted_pub = SigningKey.generate(curve=SECP256k1).get_verifying_key().to_string("uncompressed").hex()
    assert reg.is_trusted(untrusted_pub) is False
    print(f"    is_trusted(random_pubkey) = False")

    # 5. Verify anchor signature
    msg = b"BCS trust anchor test message"
    sig = anchor_sk.sign(msg, hashfunc=hashlib.sha3_256)
    ok = reg.verify_anchor_signature("ta-gov-01", msg, sig)
    print(f"[5] Anchor signature valid: {ok}")
    assert ok is True

    # 5b. Bad signature
    bad_sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])
    ok_bad = reg.verify_anchor_signature("ta-gov-01", msg, bad_sig)
    print(f"    Bad signature rejected: {ok_bad is False}")
    assert ok_bad is False

    # 6. Remove anchor (governance)
    removed = reg.remove_anchor("ta-gov-01", gov_signatures=["0xGOVSIG03"])
    print(f"[6] Removed anchor status: {removed.status}")
    assert removed.status == TRUST_ANCHOR_REMOVED

    # 7. After removal, is_trusted should be False
    trusted_after = reg.is_trusted(anchor_pub)
    print(f"[7] is_trusted after removal: {trusted_after}")
    assert trusted_after is False

    # 8. Governance threshold enforcement
    strict_reg = TrustAnchorRegistry(governance_threshold=2)
    try:
        strict_reg.add_anchor(
            anchor_id="ta-strict-01",
            name="Strict Anchor",
            public_key=anchor_pub,
            url="https://strict.local",
            gov_signatures=["0xSIG1"],  # only 1, threshold is 2
        )
        assert False, "Should have raised ValueError"
    except ValueError as exc:
        print(f"[8] Threshold enforcement works: {exc}")

    # 9. JSON round-trip
    reg2 = TrustAnchorRegistry(governance_threshold=1)
    reg2.add_anchor(
        anchor_id="ta-export-01",
        name="Exportable Anchor",
        public_key=anchor_pub,
        url="https://export.local",
        gov_signatures=["0xSIG"],
    )
    json_str = reg2.to_json()
    reg3 = TrustAnchorRegistry()
    reg3.from_json(json_str)
    assert reg3.get_anchor("ta-export-01") is not None
    print(f"[9] JSON round-trip OK")

    print("\n" + "=" * 60)
    print("All Trust Anchor module self-tests PASSED ✓")
    print("=" * 60)


if __name__ == "__main__":
    _self_test()
