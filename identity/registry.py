"""
Identity Registry Module for BCS

SQLite-backed registry for DID identity lifecycle management.

Supports states:
    PENDING        — registration submitted, awaiting governance verification
    AUTHENTICATED  — approved, may receive MINT / REPLENISH
    SUSPENDED      — temporarily frozen
    REVOKED        — permanently revoked

Architecture reference: architecture_design.md §2.4, §3.4
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import IntEnum
from typing import Dict, List, Optional, Any

# ---------------------------------------------------------------------------
# Enums & constants
# ---------------------------------------------------------------------------

class IdentityStatus(IntEnum):
    """
    Lifecycle states of a BCS identity.

    Values mirror the protobuf enum in architecture_design.md §3.4.
    """
    UNAUTHENTICATED = 0   # Legacy / pre-registration
    PENDING = 1           # Submitted, awaiting gov verification
    AUTHENTICATED = 2     # Approved, may receive MINT
    SUSPENDED = 3         # Temporarily frozen
    REVOKED = 4           # Permanently revoked


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class IdentityRecord:
    """
    Full identity record stored in the registry.

    Attributes:
        did: The DID string (primary key).
        address: Public-key hash (hex) derived from the DID.
        status: Current lifecycle state.
        first_auth_height: Block height when first authenticated (0 if never).
        last_replenish_height: Block height of last REPLENISH (0 if never).
        credentials: List of VC IDs bound to this identity.
        metadata: Free-form metadata dict.
        created_at: ISO-8601 timestamp of first registration.
        updated_at: ISO-8601 timestamp of last mutation.
    """
    did: str
    address: str
    status: IdentityStatus = IdentityStatus.PENDING
    first_auth_height: int = 0
    last_replenish_height: int = 0
    credentials: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""


# ---------------------------------------------------------------------------
# SQL schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS identities (
    did                   TEXT PRIMARY KEY,
    address               TEXT NOT NULL,
    status                INTEGER NOT NULL DEFAULT 1,
    first_auth_height     INTEGER NOT NULL DEFAULT 0,
    last_replenish_height INTEGER NOT NULL DEFAULT 0,
    credentials_json      TEXT NOT NULL DEFAULT '[]',
    metadata              TEXT NOT NULL DEFAULT '{}',
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_status ON identities(status);
CREATE INDEX IF NOT EXISTS idx_address ON identities(address);
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _record_from_row(row: sqlite3.Row) -> IdentityRecord:
    return IdentityRecord(
        did=row["did"],
        address=row["address"],
        status=IdentityStatus(row["status"]),
        first_auth_height=row["first_auth_height"],
        last_replenish_height=row["last_replenish_height"],
        credentials=json.loads(row["credentials_json"]),
        metadata=json.loads(row["metadata"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _did_to_address(did: str) -> str:
    """Extract the pubkey_hash portion from ``did:bcs:<hash>``."""
    prefix = "did:bcs:"
    if not did.startswith(prefix):
        raise ValueError(f"Malformed BCS DID: {did}")
    return did[len(prefix):]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class IdentityRegistry:
    """
    SQLite-backed identity registry.

    Manages the full lifecycle of a DID identity from initial registration
    through governance approval, suspension and revocation.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        """
        Args:
            db_path: SQLite database file path.  ``:memory:`` for tests.
        """
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._conn:
            self._conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    # Core lifecycle
    # ------------------------------------------------------------------

    def register(
        self,
        did_document: Any,
        vc: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> IdentityRecord:
        """
        Register a new identity (status = PENDING).

        Args:
            did_document: The DID Document object (must expose ``.id``).
            vc: The VerifiableCredential object (must expose ``.id``).
            metadata: Optional free-form metadata dict.

        Returns:
            The created ``IdentityRecord``.

        Raises:
            ValueError: If the DID already exists.
        """
        did = getattr(did_document, "id", did_document)
        vc_id = getattr(vc, "id", vc)
        address = _did_to_address(did)
        now = _now_iso()
        meta = metadata or {}

        try:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO identities
                    (did, address, status, first_auth_height, last_replenish_height,
                     credentials_json, metadata, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        did,
                        address,
                        IdentityStatus.PENDING.value,
                        0,
                        0,
                        json.dumps([vc_id]),
                        json.dumps(meta),
                        now,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"DID {did} already registered") from exc

        return IdentityRecord(
            did=did,
            address=address,
            status=IdentityStatus.PENDING,
            first_auth_height=0,
            last_replenish_height=0,
            credentials=[vc_id],
            metadata=meta,
            created_at=now,
            updated_at=now,
        )

    def verify_and_activate(
        self,
        did: str,
        gov_signature: str,
        auth_height: int = 0,
    ) -> IdentityRecord:
        """
        Governance verification: promote a PENDING identity to AUTHENTICATED.

        In production the *gov_signature* would be checked against the
        active governance validator set; here we accept any non-empty string.

        Args:
            did: The DID to activate.
            gov_signature: Multi-sig governance proof (hex).
            auth_height: Block height at which activation occurs.

        Returns:
            The updated ``IdentityRecord``.

        Raises:
            ValueError: If the DID is not found or not in PENDING state.
        """
        if not gov_signature:
            raise ValueError("Governance signature required")

        record = self.get_record(did)
        if record is None:
            raise ValueError(f"DID {did} not found")
        if record.status != IdentityStatus.PENDING:
            raise ValueError(f"DID {did} is not in PENDING state (current={record.status.name})")

        now = _now_iso()
        with self._conn:
            self._conn.execute(
                """
                UPDATE identities
                SET status = ?, first_auth_height = ?, updated_at = ?
                WHERE did = ?
                """,
                (IdentityStatus.AUTHENTICATED.value, auth_height, now, did),
            )

        return self.get_record(did)

    def suspend(self, did: str, reason: str = "") -> IdentityRecord:
        """
        Suspend an identity (SUSPENDED).

        Args:
            did: The DID to suspend.
            reason: Optional human-readable reason (stored in metadata).

        Returns:
            The updated ``IdentityRecord``.

        Raises:
            ValueError: If the DID is not found or already REVOKED.
        """
        record = self.get_record(did)
        if record is None:
            raise ValueError(f"DID {did} not found")
        if record.status == IdentityStatus.REVOKED:
            raise ValueError(f"DID {did} is already REVOKED and cannot be suspended")

        now = _now_iso()
        meta = dict(record.metadata)
        meta["suspend_reason"] = reason
        meta["suspended_at"] = now

        with self._conn:
            self._conn.execute(
                """
                UPDATE identities
                SET status = ?, metadata = ?, updated_at = ?
                WHERE did = ?
                """,
                (IdentityStatus.SUSPENDED.value, json.dumps(meta), now, did),
            )

        return self.get_record(did)

    def revoke(self, did: str, reason: str = "") -> IdentityRecord:
        """
        Permanently revoke an identity (REVOKED).

        Args:
            did: The DID to revoke.
            reason: Optional human-readable reason.

        Returns:
            The updated ``IdentityRecord``.

        Raises:
            ValueError: If the DID is not found.
        """
        record = self.get_record(did)
        if record is None:
            raise ValueError(f"DID {did} not found")

        now = _now_iso()
        meta = dict(record.metadata)
        meta["revoke_reason"] = reason
        meta["revoked_at"] = now

        with self._conn:
            self._conn.execute(
                """
                UPDATE identities
                SET status = ?, metadata = ?, updated_at = ?
                WHERE did = ?
                """,
                (IdentityStatus.REVOKED.value, json.dumps(meta), now, did),
            )

        return self.get_record(did)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_status(self, did: str) -> Optional[IdentityStatus]:
        """
        Query the current status of a DID.

        Returns:
            The ``IdentityStatus`` enum value, or ``None`` if not found.
        """
        cur = self._conn.execute("SELECT status FROM identities WHERE did = ?", (did,))
        row = cur.fetchone()
        return IdentityStatus(row["status"]) if row else None

    def get_record(self, did: str) -> Optional[IdentityRecord]:
        """
        Retrieve the full ``IdentityRecord`` for a DID.

        Returns:
            The record, or ``None`` if not found.
        """
        cur = self._conn.execute("SELECT * FROM identities WHERE did = ?", (did,))
        row = cur.fetchone()
        return _record_from_row(row) if row else None

    def get_record_by_address(self, address: str) -> Optional[IdentityRecord]:
        """Lookup by raw public-key hash address."""
        cur = self._conn.execute("SELECT * FROM identities WHERE address = ?", (address,))
        row = cur.fetchone()
        return _record_from_row(row) if row else None

    def list_by_status(self, status: IdentityStatus) -> List[IdentityRecord]:
        """
        List all identities with the given status.

        Args:
            status: Filter by this status.

        Returns:
            List of matching ``IdentityRecord`` objects.
        """
        cur = self._conn.execute(
            "SELECT * FROM identities WHERE status = ? ORDER BY created_at",
            (status.value,),
        )
        return [_record_from_row(row) for row in cur.fetchall()]

    def list_all(self, limit: int = 100, offset: int = 0) -> List[IdentityRecord]:
        """
        List all identities with pagination.

        Args:
            limit: Max rows to return.
            offset: Skip this many rows.

        Returns:
            List of ``IdentityRecord`` objects.
        """
        cur = self._conn.execute(
            "SELECT * FROM identities ORDER BY created_at LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [_record_from_row(row) for row in cur.fetchall()]

    def count_by_status(self) -> Dict[str, int]:
        """Return a breakdown of identity counts per status."""
        cur = self._conn.execute("SELECT status, COUNT(*) AS cnt FROM identities GROUP BY status")
        return {IdentityStatus(row["status"]).name: row["cnt"] for row in cur.fetchall()}

    # ------------------------------------------------------------------
    # Credential management
    # ------------------------------------------------------------------

    def add_credential(self, did: str, vc_id: str) -> None:
        """
        Append a new Verifiable Credential ID to an existing identity.

        Args:
            did: The target DID.
            vc_id: The VC identifier to append.

        Raises:
            ValueError: If the DID is not found.
        """
        record = self.get_record(did)
        if record is None:
            raise ValueError(f"DID {did} not found")

        creds = list(record.credentials)
        if vc_id not in creds:
            creds.append(vc_id)

        now = _now_iso()
        with self._conn:
            self._conn.execute(
                "UPDATE identities SET credentials_json = ?, updated_at = ? WHERE did = ?",
                (json.dumps(creds), now, did),
            )

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    def __del__(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


# =============================================================================
# Self-test
# =============================================================================

def _self_test() -> None:
    print("=" * 60)
    print("BCS Identity — Registry Module Self-Test")
    print("=" * 60)

    # Dummy DID / VC objects with .id attributes
    class _FakeDoc:
        def __init__(self, did: str):
            self.id = did

    class _FakeVC:
        def __init__(self, vc_id: str):
            self.id = vc_id

    reg = IdentityRegistry(db_path=":memory:")

    did = "did:bcs:" + "a" * 64
    doc = _FakeDoc(did)
    vc = _FakeVC("urn:uuid:vc-001")

    # 1. Register
    record = reg.register(doc, vc, metadata={"source": "test"})
    print(f"\n[1] Registered DID: {record.did}")
    print(f"    Status   : {record.status.name}")
    print(f"    Address  : {record.address[:16]}...")
    assert record.status == IdentityStatus.PENDING

    # 2. Get status
    st = reg.get_status(did)
    print(f"[2] get_status -> {st.name}")
    assert st == IdentityStatus.PENDING

    # 3. Verify and activate
    activated = reg.verify_and_activate(did, gov_signature="0xDEADBEEF", auth_height=42)
    print(f"[3] Activated at height {activated.first_auth_height}")
    assert activated.status == IdentityStatus.AUTHENTICATED
    assert activated.first_auth_height == 42

    # 4. Add credential
    reg.add_credential(did, "urn:uuid:vc-002")
    rec = reg.get_record(did)
    print(f"[4] Credentials count: {len(rec.credentials)}")
    assert len(rec.credentials) == 2

    # 5. Suspend
    suspended = reg.suspend(did, reason="suspicious_activity")
    print(f"[5] Suspended: {suspended.status.name}")
    assert suspended.status == IdentityStatus.SUSPENDED
    assert suspended.metadata.get("suspend_reason") == "suspicious_activity"

    # 6. Revoke
    revoked = reg.revoke(did, reason="kyc_failed")
    print(f"[6] Revoked: {revoked.status.name}")
    assert revoked.status == IdentityStatus.REVOKED

    # 7. Query by status
    pending_list = reg.list_by_status(IdentityStatus.PENDING)
    auth_list = reg.list_by_status(IdentityStatus.AUTHENTICATED)
    revoked_list = reg.list_by_status(IdentityStatus.REVOKED)
    print(f"[7] Counts — PENDING={len(pending_list)}, AUTHENTICATED={len(auth_list)}, REVOKED={len(revoked_list)}")
    assert len(revoked_list) == 1

    # 8. Count breakdown
    counts = reg.count_by_status()
    print(f"[8] Status breakdown: {counts}")
    assert counts.get("REVOKED") == 1

    # 9. Duplicate registration should fail
    try:
        reg.register(doc, vc)
        assert False, "Should have raised ValueError"
    except ValueError as exc:
        print(f"[9] Duplicate registration rejected: {exc}")

    # 10. Address lookup
    by_addr = reg.get_record_by_address(record.address)
    print(f"[10] Lookup by address OK: {by_addr is not None and by_addr.did == did}")
    assert by_addr is not None
    assert by_addr.did == did

    reg.close()

    print("\n" + "=" * 60)
    print("All Registry module self-tests PASSED ✓")
    print("=" * 60)


if __name__ == "__main__":
    _self_test()
