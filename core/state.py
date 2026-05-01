"""
BCS Blockchain Core — Account Derived State
===========================================
While BCS uses a UTXO model at the protocol level, a derived account
state is maintained for convenient querying of balances, N feasibility,
and identity status.

Components:
  • IdentityStatus     – enum of authentication states
  • AccountState       – per-address derived state snapshot
  • StateManager       – in-memory address→AccountState map with batch ops

All monetary amounts use int (nanoN units, 1 N = 10^9 nanoN).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# IdentityStatus
# ---------------------------------------------------------------------------

class IdentityStatus(IntEnum):
    """
    Lifecycle states of a BCS identity.

    Only AUTHENTICATED accounts may receive MINT/REPLENISH transactions.
    """
    UNAUTHENTICATED = 0   # No identity registered
    PENDING = 1           # Registration submitted, awaiting verification
    AUTHENTICATED = 2     # Verified; eligible for N issuance
    SUSPENDED = 3         # Temporarily frozen by governance
    REVOKED = 4           # Permanently revoked


# ---------------------------------------------------------------------------
# AccountState
# ---------------------------------------------------------------------------

@dataclass
class AccountState:
    """
    Derived account state for a BCS address.

    Fields:
        address: Base58Check address string.
        did: Bound DID string, or empty if none.
        n_balance: Total N balance across all UTXOs.
        n_locked: N value locked by timelocks or other conditions.
        n_available: n_balance - n_locked (spendable).
        max_sale_capacity: Maximum D-denominated sale capacity = n_available / φ.
        current_sale_volume: D sales already consumed in current sliding window.
        identity_status: Current identity lifecycle state.
        first_auth_height: Block height of first authentication (0 if never).
        last_replenish_height: Block height of last REPLENISH/MINT (0 if never).
        nonce: Replay-protection nonce for account-model-like operations.
        last_activity: Most recent block height where this address was active.
    """
    address: str = ""
    did: str = ""
    n_balance: int = 0
    n_locked: int = 0
    n_available: int = 0
    max_sale_capacity: int = 0
    current_sale_volume: int = 0
    identity_status: IdentityStatus = IdentityStatus.UNAUTHENTICATED
    first_auth_height: int = 0
    last_replenish_height: int = 0
    nonce: int = 0
    last_activity: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.identity_status, int):
            object.__setattr__(self, "identity_status", IdentityStatus(self.identity_status))
        # Derive n_available if not explicitly set
        if self.n_available == 0 and (self.n_balance or self.n_locked):
            object.__setattr__(
                self, "n_available", max(0, self.n_balance - self.n_locked)
            )

    def is_authenticated(self) -> bool:
        return self.identity_status == IdentityStatus.AUTHENTICATED

    def can_receive_mint(self) -> bool:
        return self.identity_status in (IdentityStatus.AUTHENTICATED, IdentityStatus.PENDING)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "did": self.did,
            "n_balance": self.n_balance,
            "n_locked": self.n_locked,
            "n_available": self.n_available,
            "max_sale_capacity": self.max_sale_capacity,
            "current_sale_volume": self.current_sale_volume,
            "identity_status": int(self.identity_status),
            "first_auth_height": self.first_auth_height,
            "last_replenish_height": self.last_replenish_height,
            "nonce": self.nonce,
            "last_activity": self.last_activity,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AccountState":
        return cls(
            address=d["address"],
            did=d.get("did", ""),
            n_balance=d["n_balance"],
            n_locked=d["n_locked"],
            n_available=d.get("n_available", 0),
            max_sale_capacity=d.get("max_sale_capacity", 0),
            current_sale_volume=d.get("current_sale_volume", 0),
            identity_status=IdentityStatus(d["identity_status"]),
            first_auth_height=d.get("first_auth_height", 0),
            last_replenish_height=d.get("last_replenish_height", 0),
            nonce=d["nonce"],
            last_activity=d["last_activity"],
        )


# ---------------------------------------------------------------------------
# StateManager
# ---------------------------------------------------------------------------

class StateManager:
    """
    Maintains the derived address→AccountState mapping.

    Supports single updates, batch updates (atomic), and snapshot/restore
    for reorganization handling.
    """

    def __init__(self) -> None:
        self._states: dict[str, AccountState] = {}

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def get(self, address: str) -> AccountState:
        """
        Retrieve the AccountState for an address.
        Returns a default (zero) AccountState if unknown.
        """
        return self._states.get(address, AccountState(address=address))

    def update(self, address: str, **kwargs: Any) -> AccountState:
        """
        Update specific fields of an AccountState.
        Missing fields are carried over from the existing record.
        """
        existing = self._states.get(address, AccountState(address=address))
        data = existing.to_dict()
        data.update(kwargs)
        new_state = AccountState.from_dict(data)
        self._states[address] = new_state
        return new_state

    def set(self, state: AccountState) -> None:
        """Overwrite the state for an address."""
        self._states[state.address] = state

    def remove(self, address: str) -> Optional[AccountState]:
        """Remove an address from the manager."""
        return self._states.pop(address, None)

    def exists(self, address: str) -> bool:
        return address in self._states

    def all_addresses(self) -> list[str]:
        return list(self._states.keys())

    def all_states(self) -> list[AccountState]:
        return list(self._states.values())

    # ------------------------------------------------------------------
    # Batch operations
    # ------------------------------------------------------------------

    def batch_update(self, updates: dict[str, dict[str, Any]]) -> list[AccountState]:
        """
        Atomically apply a batch of field updates.

        Args:
            updates: Mapping address -> {field: new_value, ...}

        Returns:
            List of updated AccountState objects.
        """
        result: list[AccountState] = []
        for address, fields in updates.items():
            result.append(self.update(address, **fields))
        return result

    def batch_set(self, states: list[AccountState]) -> None:
        """Atomically overwrite multiple AccountState records."""
        for st in states:
            self._states[st.address] = st

    # ------------------------------------------------------------------
    # Snapshot / restore
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """JSON-serializable snapshot of the full state map."""
        return {
            "states": {addr: st.to_dict() for addr, st in self._states.items()},
        }

    def restore(self, snapshot: dict[str, Any]) -> None:
        """Restore from a snapshot."""
        self._states = {}
        for addr, sd in snapshot.get("states", {}).items():
            self._states[addr] = AccountState.from_dict(sd)

    def clone(self) -> "StateManager":
        """Return a deep copy of the state manager."""
        sm = StateManager()
        sm.restore(self.snapshot())
        return sm


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # 1. Default state
    sm = StateManager()
    st = sm.get("addr1")
    assert st.address == "addr1"
    assert st.n_balance == 0
    assert st.identity_status == IdentityStatus.UNAUTHENTICATED
    print("Default state OK")

    # 2. Update fields
    updated = sm.update("addr1", n_balance=5_000_000_000, n_locked=1_000_000_000)
    assert updated.n_balance == 5_000_000_000
    assert updated.n_available == 4_000_000_000  # derived
    print("Update OK, available:", updated.n_available)

    # 3. Batch update
    sm.batch_update({
        "addr2": {"n_balance": 1_000_000_000, "identity_status": IdentityStatus.AUTHENTICATED},
        "addr3": {"n_balance": 2_000_000_000, "identity_status": IdentityStatus.PENDING},
    })
    assert sm.get("addr2").is_authenticated()
    assert sm.get("addr3").identity_status == IdentityStatus.PENDING
    print("Batch update OK")

    # 4. Snapshot round-trip
    snap = sm.snapshot()
    sm2 = StateManager()
    sm2.restore(snap)
    assert sm2.get("addr1").n_balance == 5_000_000_000
    assert sm2.get("addr2").is_authenticated()
    print("Snapshot round-trip OK")

    # 5. Full AccountState serialization
    full = AccountState(
        address="addrX",
        did="did:bcs:abc123",
        n_balance=10_000_000_000,
        n_locked=2_000_000_000,
        max_sale_capacity=8_000_000_000,
        current_sale_volume=1_000_000_000,
        identity_status=IdentityStatus.AUTHENTICATED,
        first_auth_height=100,
        last_replenish_height=500,
        nonce=42,
        last_activity=1000,
    )
    rt = AccountState.from_dict(full.to_dict())
    assert rt.did == full.did
    assert rt.identity_status == full.identity_status
    assert rt.first_auth_height == 100
    print("AccountState serialization OK")

    # 6. Clone
    sm3 = sm.clone()
    assert sm3.get("addr1").n_balance == sm.get("addr1").n_balance
    print("Clone OK")

    print("state.py self-test PASSED")
