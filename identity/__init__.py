"""
BCS Identity Module

Provides DID, Verifiable Credentials, Identity Registry, Trust Anchor
management, and Authentication / Permission control for the BCS chain.

Sub-modules:
    did          — DID generation, resolution, document management
    vc           — Verifiable Credential issuance, verification, revocation
    registry     — SQLite-backed identity lifecycle registry
    trust_anchor — Trust anchor governance and signature verification
    auth         — Permission engine for MINT, REPLENISH, SALE, WAGE, etc.
"""

from .did import (
    DID_METHOD,
    DIDDocument,
    DIDManager,
    VerificationMethod,
)

from .vc import (
    CredentialProof,
    CredentialSubject,
    VCManager,
    VerifiableCredential,
)

from .registry import (
    IdentityRecord,
    IdentityRegistry,
    IdentityStatus,
)

from .trust_anchor import (
    TrustAnchor,
    TrustAnchorRegistry,
)

from .auth import (
    AuthEngine,
    Permission,
)

__all__ = [
    "DID_METHOD",
    "DIDDocument",
    "DIDManager",
    "VerificationMethod",
    "CredentialProof",
    "CredentialSubject",
    "VCManager",
    "VerifiableCredential",
    "IdentityRecord",
    "IdentityRegistry",
    "IdentityStatus",
    "TrustAnchor",
    "TrustAnchorRegistry",
    "AuthEngine",
    "Permission",
]
