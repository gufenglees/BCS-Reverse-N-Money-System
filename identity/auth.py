"""
Authentication & Permission Engine for BCS

Determines whether a given DID is authorised to perform high-value
operations such as MINT, REPLENISH, BURN, GOVERN, or day-to-day
operations like TRANSFER_SALE and TRANSFER_WAGE.

The engine queries the ``IdentityRegistry`` to inspect the DID's
``IdentityStatus`` and derives the effective permission set.

Architecture reference: architecture_design.md §2.4, §3.4

Permission model::

    ┌─────────────────────────────────────────────┐
    │  AUTHENTICATED + gov_flag=True  → MINT       │
    │  AUTHENTICATED                  → REPLENISH  │
    │  AUTHENTICATED                  → SALE/WAGE  │
    │  PENDING                        → (none)     │
    │  SUSPENDED                      → (none)     │
    │  REVOKED                        → (none)     │
    └─────────────────────────────────────────────┘
"""
from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, Optional, Set

# Local imports
try:
    from .registry import IdentityStatus, IdentityRegistry
except ImportError:
    from registry import IdentityStatus, IdentityRegistry

if TYPE_CHECKING:
    from .registry import IdentityRecord


# ---------------------------------------------------------------------------
# Permission enum
# ---------------------------------------------------------------------------

class Permission(IntEnum):
    """
    Atomic permissions in the BCS system.

    The numeric values are stable and may be used in bitmasking
    (e.g. protobuf uint32 permission_bits).
    """
    MINT = 0          # Initial N currency issuance (gov only)
    REPLENISH = 1     # Top-up existing N balance (gov or authorised)
    BURN = 2          # Destroy N currency (gov only)
    GOVERN = 3        # Parameter changes, validator set mutations
    VALIDATE = 4      # Block proposal / validation right
    SALE = 5          # Participate in TRANSFER_SALE transactions
    WAGE = 6          # Participate in TRANSFER_WAGE transactions


# ---------------------------------------------------------------------------
# Auth Engine
# ---------------------------------------------------------------------------

class AuthEngine:
    """
    Permission evaluation engine.

    Checks a DID against the on-chain (or local) identity registry and
    returns whether a specific operation is permitted.

    In production this would also enforce:
        - Multi-signature governance proofs for MINT / BURN / GOVERN
        - Rate-limiting (e.g. max REPLENISH per epoch)
        - VC re-validation before high-value operations
    """

    def __init__(self, governance_dids: Optional[Set[str]] = None) -> None:
        """
        Args:
            governance_dids: Optional set of DIDs that are members of the
                             governance committee.  These DIDs gain
                             ``MINT``, ``BURN`` and ``GOVERN`` permissions
                             once they are ``AUTHENTICATED``.
        """
        self._gov_dids: Set[str] = set(governance_dids or {})

    # ------------------------------------------------------------------
    # Individual permission checks
    # ------------------------------------------------------------------

    def check_mint_permission(self, did: str, registry: IdentityRegistry) -> bool:
        """
        Check whether *did* may authorise a ``MINT`` transaction.

        Requirements:
            1. Identity status == ``AUTHENTICATED``
            2. DID is in the governance committee set.
        """
        record = registry.get_record(did)
        if record is None:
            return False
        if record.status != IdentityStatus.AUTHENTICATED:
            return False
        return did in self._gov_dids

    def check_replenish_permission(self, did: str, registry: IdentityRegistry) -> bool:
        """
        Check whether *did* may authorise a ``REPLENISH`` transaction.

        Requirements:
            1. Identity status == ``AUTHENTICATED``
            2. DID has been authenticated at least once
               (``first_auth_height > 0``).
        """
        record = registry.get_record(did)
        if record is None:
            return False
        if record.status != IdentityStatus.AUTHENTICATED:
            return False
        # Replenish requires a prior successful authentication
        return record.first_auth_height > 0

    def check_sale_permission(self, did: str, registry: IdentityRegistry) -> bool:
        """
        Check whether *did* may participate in a ``TRANSFER_SALE`` transaction.

        Requirements:
            1. Identity status == ``AUTHENTICATED``
        """
        record = registry.get_record(did)
        if record is None:
            return False
        return record.status == IdentityStatus.AUTHENTICATED

    def check_wage_permission(self, did: str, registry: IdentityRegistry) -> bool:
        """
        Check whether *did* may participate in a ``TRANSFER_WAGE`` transaction.

        Requirements:
            1. Identity status == ``AUTHENTICATED`` or ``PENDING``
               (wage payments are allowed earlier in the lifecycle because
               workers may need to receive wages before full KYC is complete).
        """
        record = registry.get_record(did)
        if record is None:
            return False
        return record.status in (IdentityStatus.AUTHENTICATED, IdentityStatus.PENDING)

    def check_burn_permission(self, did: str, registry: IdentityRegistry) -> bool:
        """
        Check whether *did* may authorise a ``BURN`` transaction.

        Requirements:
            1. Identity status == ``AUTHENTICATED``
            2. DID is in the governance committee set.
        """
        record = registry.get_record(did)
        if record is None:
            return False
        if record.status != IdentityStatus.AUTHENTICATED:
            return False
        return did in self._gov_dids

    def check_govern_permission(self, did: str, registry: IdentityRegistry) -> bool:
        """
        Check whether *did* may propose or vote on governance actions.

        Requirements:
            1. Identity status == ``AUTHENTICATED``
            2. DID is in the governance committee set.
        """
        record = registry.get_record(did)
        if record is None:
            return False
        if record.status != IdentityStatus.AUTHENTICATED:
            return False
        return did in self._gov_dids

    def check_validate_permission(self, did: str, registry: IdentityRegistry) -> bool:
        """
        Check whether *did* is authorised to validate (propose) blocks.

        Requirements:
            1. Identity status == ``AUTHENTICATED``
            2. DID is in the governance committee set (validator set).
        """
        record = registry.get_record(did)
        if record is None:
            return False
        if record.status != IdentityStatus.AUTHENTICATED:
            return False
        return did in self._gov_dids

    # ------------------------------------------------------------------
    # Bulk evaluation
    # ------------------------------------------------------------------

    def get_effective_permissions(
        self,
        did: str,
        registry: IdentityRegistry,
    ) -> Set[Permission]:
        """
        Compute the complete effective permission set for *did*.

        Args:
            did: The DID to evaluate.
            registry: The identity registry backing the query.

        Returns:
            A set of ``Permission`` enum values.
        """
        perms: Set[Permission] = set()
        record = registry.get_record(did)
        if record is None:
            return perms

        # No permissions for SUSPENDED or REVOKED
        if record.status in (IdentityStatus.SUSPENDED, IdentityStatus.REVOKED):
            return perms

        # PENDING: only wage permission (early worker onboarding)
        if record.status == IdentityStatus.PENDING:
            perms.add(Permission.WAGE)
            return perms

        # AUTHENTICATED
        if record.status == IdentityStatus.AUTHENTICATED:
            perms.add(Permission.REPLENISH)
            perms.add(Permission.SALE)
            perms.add(Permission.WAGE)

            if did in self._gov_dids:
                perms.add(Permission.MINT)
                perms.add(Permission.BURN)
                perms.add(Permission.GOVERN)
                perms.add(Permission.VALIDATE)

        return perms

    # ------------------------------------------------------------------
    # Helpers for rule enforcement
    # ------------------------------------------------------------------

    @staticmethod
    def assert_permission(
        did: str,
        registry: IdentityRegistry,
        permission: Permission,
        engine: Optional["AuthEngine"] = None,
    ) -> None:
        """
        Raise ``PermissionError`` if *did* lacks *permission*.

        This is a convenience wrapper for use inside transaction validators.
        """
        eng = engine or AuthEngine()
        checkers = {
            Permission.MINT: eng.check_mint_permission,
            Permission.REPLENISH: eng.check_replenish_permission,
            Permission.BURN: eng.check_burn_permission,
            Permission.GOVERN: eng.check_govern_permission,
            Permission.VALIDATE: eng.check_validate_permission,
            Permission.SALE: eng.check_sale_permission,
            Permission.WAGE: eng.check_wage_permission,
        }
        fn = checkers.get(permission)
        if fn is None:
            raise PermissionError(f"Unknown permission: {permission}")
        if not fn(did, registry):
            raise PermissionError(
                f"DID {did} lacks permission {permission.name}"
            )


# ---------------------------------------------------------------------------
# Convenience: map Permission to transaction types (documentation)
# ---------------------------------------------------------------------------

PERMISSION_TO_TX_TYPE: dict = {
    Permission.MINT: "MINT",
    Permission.REPLENISH: "REPLENISH",
    Permission.BURN: "BURN",
    Permission.GOVERN: "GOV_PARAMETER_CHANGE / GOV_VALIDATOR_CHANGE",
    Permission.VALIDATE: "BLOCK_PROPOSAL",
    Permission.SALE: "TRANSFER_SALE",
    Permission.WAGE: "TRANSFER_WAGE",
}


# =============================================================================
# Self-test
# =============================================================================

def _self_test() -> None:
    print("=" * 60)
    print("BCS Identity — Auth Engine Self-Test")
    print("=" * 60)

    try:
        from .registry import IdentityRegistry, IdentityStatus
    except ImportError:
        from registry import IdentityRegistry, IdentityStatus

    # Helper: create a fake DID Document and VC proxy
    class _FakeDoc:
        def __init__(self, did: str):
            self.id = did

    class _FakeVC:
        def __init__(self, vc_id: str):
            self.id = vc_id

    reg = IdentityRegistry(db_path=":memory:")

    gov_did = "did:bcs:" + "g" * 64
    normal_did = "did:bcs:" + "n" * 64
    pending_did = "did:bcs:" + "p" * 64
    suspended_did = "did:bcs:" + "s" * 64
    revoked_did = "did:bcs:" + "r" * 64

    # Register all
    for did in [gov_did, normal_did, pending_did, suspended_did, revoked_did]:
        reg.register(_FakeDoc(did), _FakeVC(f"urn:uuid:vc-{did[-4:]}"))

    # Activate gov + normal
    reg.verify_and_activate(gov_did, "0xGOV", auth_height=10)
    reg.verify_and_activate(normal_did, "0xGOV", auth_height=11)
    reg.suspend(suspended_did, reason="test")
    reg.revoke(revoked_did, reason="test")

    # Leave pending_did in PENDING

    engine = AuthEngine(governance_dids={gov_did})

    # 1. MINT permission
    print(f"\n[1] MINT permission checks")
    print(f"    gov_did      : {engine.check_mint_permission(gov_did, reg)} (expect True)")
    print(f"    normal_did   : {engine.check_mint_permission(normal_did, reg)} (expect False)")
    print(f"    pending_did  : {engine.check_mint_permission(pending_did, reg)} (expect False)")
    assert engine.check_mint_permission(gov_did, reg) is True
    assert engine.check_mint_permission(normal_did, reg) is False
    assert engine.check_mint_permission(pending_did, reg) is False

    # 2. REPLENISH permission
    print(f"\n[2] REPLENISH permission checks")
    print(f"    gov_did      : {engine.check_replenish_permission(gov_did, reg)}")
    print(f"    normal_did   : {engine.check_replenish_permission(normal_did, reg)}")
    print(f"    pending_did  : {engine.check_replenish_permission(pending_did, reg)}")
    assert engine.check_replenish_permission(gov_did, reg) is True
    assert engine.check_replenish_permission(normal_did, reg) is True
    assert engine.check_replenish_permission(pending_did, reg) is False

    # 3. SALE permission
    print(f"\n[3] SALE permission checks")
    print(f"    gov_did      : {engine.check_sale_permission(gov_did, reg)}")
    print(f"    normal_did   : {engine.check_sale_permission(normal_did, reg)}")
    print(f"    pending_did  : {engine.check_sale_permission(pending_did, reg)}")
    print(f"    suspended_did: {engine.check_sale_permission(suspended_did, reg)}")
    print(f"    revoked_did  : {engine.check_sale_permission(revoked_did, reg)}")
    assert engine.check_sale_permission(gov_did, reg) is True
    assert engine.check_sale_permission(normal_did, reg) is True
    assert engine.check_sale_permission(pending_did, reg) is False
    assert engine.check_sale_permission(suspended_did, reg) is False
    assert engine.check_sale_permission(revoked_did, reg) is False

    # 4. WAGE permission (PENDING allowed)
    print(f"\n[4] WAGE permission checks")
    print(f"    gov_did      : {engine.check_wage_permission(gov_did, reg)}")
    print(f"    normal_did   : {engine.check_wage_permission(normal_did, reg)}")
    print(f"    pending_did  : {engine.check_wage_permission(pending_did, reg)} (expect True)")
    print(f"    suspended_did: {engine.check_wage_permission(suspended_did, reg)}")
    assert engine.check_wage_permission(gov_did, reg) is True
    assert engine.check_wage_permission(normal_did, reg) is True
    assert engine.check_wage_permission(pending_did, reg) is True
    assert engine.check_wage_permission(suspended_did, reg) is False

    # 5. GOVERN permission
    print(f"\n[5] GOVERN permission checks")
    assert engine.check_govern_permission(gov_did, reg) is True
    assert engine.check_govern_permission(normal_did, reg) is False
    print(f"    gov_did    : True")
    print(f"    normal_did : False")

    # 6. Effective permissions (gov)
    perms_gov = engine.get_effective_permissions(gov_did, reg)
    print(f"\n[6] Effective permissions (gov):  {[p.name for p in perms_gov]}")
    assert Permission.MINT in perms_gov
    assert Permission.BURN in perms_gov
    assert Permission.GOVERN in perms_gov
    assert Permission.VALIDATE in perms_gov
    assert Permission.REPLENISH in perms_gov
    assert Permission.SALE in perms_gov
    assert Permission.WAGE in perms_gov

    # 7. Effective permissions (normal)
    perms_norm = engine.get_effective_permissions(normal_did, reg)
    print(f"[7] Effective permissions (normal): {[p.name for p in perms_norm]}")
    assert Permission.MINT not in perms_norm
    assert Permission.BURN not in perms_norm
    assert Permission.REPLENISH in perms_norm
    assert Permission.SALE in perms_norm
    assert Permission.WAGE in perms_norm

    # 8. Effective permissions (pending)
    perms_pending = engine.get_effective_permissions(pending_did, reg)
    print(f"[8] Effective permissions (pending): {[p.name for p in perms_pending]}")
    assert perms_pending == {Permission.WAGE}

    # 9. Effective permissions (suspended / revoked)
    perms_sus = engine.get_effective_permissions(suspended_did, reg)
    perms_rev = engine.get_effective_permissions(revoked_did, reg)
    print(f"[9] Effective permissions (suspended): {perms_sus} (expect set())")
    print(f"    Effective permissions (revoked)  : {perms_rev} (expect set())")
    assert perms_sus == set()
    assert perms_rev == set()

    # 10. assert_permission raises
    try:
        AuthEngine.assert_permission(normal_did, reg, Permission.MINT, engine)
        assert False, "Should have raised PermissionError"
    except PermissionError as exc:
        print(f"\n[10] assert_permission correctly raised: {exc}")

    reg.close()

    print("\n" + "=" * 60)
    print("All Auth Engine self-tests PASSED ✓")
    print("=" * 60)


if __name__ == "__main__":
    _self_test()
