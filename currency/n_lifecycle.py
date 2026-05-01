"""N-Currency Lifecycle Manager

Manages the full lifecycle of N-money: mint, replenish, burn, and transfer.
Implements the "N corridor" concept — the total circulating supply of N is
expected to remain within a bounded range [N_lower, N_upper], creating a
controlled monetary base that expands or contracts via governance actions.

Economic Rationale:
    N is not created by market activity; it is allocated by the governance
    committee to authenticated participants. This mirrors the BCS paper's
    insight that "being-needed" is a social property, not a commodity to be
    bought. The corridor ensures:
      • N_lower — Minimum supply to keep the economy liquid.
      • N_upper — Maximum supply to prevent dilution of the "being-needed" signal.

Lifecycle State Machine:
    [NonExistent] --MINT (gov + AUTHENTICATED)--> [Active]
    [Active] --TRANSFER--> [Active]          (peer-to-peer流转)
    [Active] --REPLENISH (gov)--> [Active]   (balance increases)
    [Active] --BURN (gov)--> [Revoked]       (balance destroyed)

All amounts are integer nanoN (10^-9 N).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

try:
    from .params import SystemParameters, GovernanceParams
except ImportError:  # pragma: no cover
    from params import SystemParameters, GovernanceParams

# --------------------------------------------------------------------------- #
#  Data Structures
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class CorridorStatus:
    """Snapshot of the N-supply corridor state.

    Attributes:
        within_corridor: True iff N_lower <= circulating_supply <= N_upper.
        circulating_supply: Total N in circulation (nanoN).
        n_lower: Lower corridor bound (nanoN).
        n_upper: Upper corridor bound (nanoN).
        distance_to_lower: nanoN gap to the lower bound (negative if below).
        distance_to_upper: nanoN gap to the upper bound (negative if above).
    """
    within_corridor: bool
    circulating_supply: int
    n_lower: int
    n_upper: int
    distance_to_lower: int
    distance_to_upper: int


@dataclass(frozen=True)
class LifecycleResult:
    """Result of a lifecycle operation.

    Attributes:
        success: Whether the operation was accepted.
        reason: Human-readable explanation on failure.
        new_balance: The account's N balance after the operation (if applicable).
    """
    success: bool
    reason: Optional[str] = None
    new_balance: Optional[int] = None


# --------------------------------------------------------------------------- #
#  Lifecycle Manager
# --------------------------------------------------------------------------- #

class NLifecycleManager:
    """Manages N-currency balances, issuance, and supply corridor monitoring.

    In a production deployment this class wraps the UTXO set manager;
    balances are derived from unspent outputs. For the MVP implementation
    we maintain an in-memory balance table with deterministic audit logging.

    Governance Authorization:
        Mint, replenish, and burn operations require a minimum threshold of
        governance signatures. The threshold is defined by
        `SystemParameters.required_gov_signatures`.
    """

    def __init__(
        self,
        governance: Optional[GovernanceParams] = None,
        n_lower: int = 0,
        n_upper: int = 10_000_000_000_000_000,  # 10 billion N in nanoN
    ) -> None:
        """Initialize the lifecycle manager.

        Args:
            governance: GovernanceParams for parameter lookup and history.
            n_lower: Lower bound of the N-supply corridor (nanoN).
            n_upper: Upper bound of the N-supply corridor (nanoN).
        """
        self.governance = governance or GovernanceParams()
        self.n_lower = n_lower
        self.n_upper = n_upper

        # In-memory balance ledger (address -> nanoN balance)
        self._balances: dict[str, int] = {}
        # Transaction log for audit (simplified)
        self._audit_log: list[dict[str, Any]] = []

    # --------------------------------------------------------------------- #
    #  Governance helpers
    # --------------------------------------------------------------------- #

    def _check_governance_signatures(
        self, gov_signatures: list[Any], reason: str = ""
    ) -> Optional[str]:
        """Validate that governance signatures meet the required threshold.

        Returns:
            Error string if insufficient, or None if sufficient.
        """
        params = self.governance.latest()
        if len(gov_signatures) < params.required_gov_signatures:
            return (
                f"Governance signatures insufficient for {reason}: "
                f"required {params.required_gov_signatures}, got {len(gov_signatures)}"
            )
        return None

    def _record(
        self,
        operation: str,
        address: str,
        amount: int,
        detail: str = "",
    ) -> None:
        """Append an entry to the in-memory audit log."""
        self._audit_log.append(
            {
                "op": operation,
                "address": address,
                "amount": amount,
                "circulating": self.get_circulating_supply(),
                "detail": detail,
            }
        )

    # --------------------------------------------------------------------- #
    #  Mint — Initial issuance
    # --------------------------------------------------------------------- #

    def mint(
        self,
        address: str,
        amount: int,
        gov_signatures: list[Any],
    ) -> LifecycleResult:
        """Issue new N-money to an authenticated address.

        Economic rationale:
            Minting is the entry point for authenticated participants into the
            N economy. It is strictly governance-controlled to prevent arbitrary
            inflation and to ensure N allocation reflects the committee's
            assessment of genuine economic need.

        Validation:
            1. Governance signatures >= required threshold.
            2. Amount >= min_n_mint (from SystemParameters).
            3. Post-mint supply must not exceed n_upper (corridor ceiling).

        Args:
            address: Recipient address (hex string).
            amount: N amount to mint (nanoN).
            gov_signatures: List of governance signatures authorizing the mint.

        Returns:
            LifecycleResult indicating success or failure.
        """
        # Governance check
        err = self._check_governance_signatures(gov_signatures, reason="MINT")
        if err:
            return LifecycleResult(success=False, reason=err)

        # Amount check
        params = self.governance.latest()
        if amount < params.min_n_mint:
            return LifecycleResult(
                success=False,
                reason=f"MINT amount {amount} below minimum {params.min_n_mint} nanoN",
            )
        if amount <= 0:
            return LifecycleResult(success=False, reason="MINT amount must be positive")

        # Corridor ceiling check
        post_supply = self.get_circulating_supply() + amount
        if post_supply > self.n_upper:
            return LifecycleResult(
                success=False,
                reason=(
                    f"MINT would exceed N corridor upper bound: "
                    f"post-mint supply {post_supply} > n_upper {self.n_upper}"
                ),
            )

        # Execute
        old_balance = self._balances.get(address, 0)
        self._balances[address] = old_balance + amount
        self._record("MINT", address, amount, detail=f"old_balance={old_balance}")

        return LifecycleResult(
            success=True,
            new_balance=self._balances[address],
        )

    # --------------------------------------------------------------------- #
    #  Replenish — Additional issuance
    # --------------------------------------------------------------------- #

    def replenish(
        self,
        address: str,
        amount: int,
        gov_signatures: list[Any],
    ) -> LifecycleResult:
        """Add N-money to an existing active account.

        Economic rationale:
            Replenishment allows the governance committee to inject additional
            N into the economy when the corridor is below target or when
            specific participants have exhausted their feasibility capacity
            through productive activity. Unlike minting, replenishment
            requires the account to already exist.

        Validation:
            1. Governance signatures >= required threshold.
            2. Account must already have a non-zero balance.
            3. Post-replenish supply must not exceed n_upper.

        Args:
            address: Existing account address.
            amount: N amount to add (nanoN).
            gov_signatures: Governance signatures.

        Returns:
            LifecycleResult.
        """
        err = self._check_governance_signatures(gov_signatures, reason="REPLENISH")
        if err:
            return LifecycleResult(success=False, reason=err)

        if amount <= 0:
            return LifecycleResult(success=False, reason="REPLENISH amount must be positive")

        if address not in self._balances or self._balances[address] == 0:
            return LifecycleResult(
                success=False,
                reason=f"REPLENISH target {address} does not exist or has zero balance; use MINT",
            )

        post_supply = self.get_circulating_supply() + amount
        if post_supply > self.n_upper:
            return LifecycleResult(
                success=False,
                reason=(
                    f"REPLENISH would exceed N corridor upper bound: "
                    f"post-supply {post_supply} > n_upper {self.n_upper}"
                ),
            )

        old_balance = self._balances[address]
        self._balances[address] = old_balance + amount
        self._record("REPLENISH", address, amount, detail=f"old_balance={old_balance}")

        return LifecycleResult(success=True, new_balance=self._balances[address])

    # --------------------------------------------------------------------- #
    #  Burn — Destruction
    # --------------------------------------------------------------------- #

    def burn(
        self,
        address: str,
        amount: int,
        gov_signatures: list[Any],
    ) -> LifecycleResult:
        """Permanently destroy N-money at an address.

        Economic rationale:
            Burning is the deflationary counterpart to minting. It removes N
            from circulation permanently, tightening the corridor and
            strengthening the "being-needed" signal for remaining holders.
            Governance-only execution prevents malicious destruction of
            participant balances.

        Validation:
            1. Governance signatures >= required threshold.
            2. Address must have sufficient balance.
            3. Post-burn supply must remain >= n_lower (corridor floor).

        Args:
            address: Target account address.
            amount: N amount to destroy (nanoN).
            gov_signatures: Governance signatures.

        Returns:
            LifecycleResult.
        """
        err = self._check_governance_signatures(gov_signatures, reason="BURN")
        if err:
            return LifecycleResult(success=False, reason=err)

        if amount <= 0:
            return LifecycleResult(success=False, reason="BURN amount must be positive")

        current_balance = self._balances.get(address, 0)
        if current_balance < amount:
            return LifecycleResult(
                success=False,
                reason=(
                    f"BURN insufficient balance: "
                    f"address has {current_balance}, requested burn {amount}"
                ),
            )

        post_supply = self.get_circulating_supply() - amount
        if post_supply < self.n_lower:
            return LifecycleResult(
                success=False,
                reason=(
                    f"BURN would breach N corridor lower bound: "
                    f"post-burn supply {post_supply} < n_lower {self.n_lower}"
                ),
            )

        self._balances[address] = current_balance - amount
        if self._balances[address] == 0:
            del self._balances[address]
        self._record("BURN", address, amount, detail=f"old_balance={current_balance}")

        return LifecycleResult(success=True, new_balance=self._balances.get(address, 0))

    # --------------------------------------------------------------------- #
    #  Transfer — Peer-to-peer N flow
    # --------------------------------------------------------------------- #

    def transfer(
        self,
        sender: str,
        recipient: str,
        amount: int,
        signature: Any,
    ) -> LifecycleResult:
        """Transfer N-money from sender to recipient.

        Economic rationale:
            Unlike external payment amounts, N-money transfers are unconditional and do not
            require a counter-flow. This models the pure "being-needed"
            relationship: if Alice values Bob's presence/need, she can
            directly send N to Bob without a corresponding D payment.

        Validation:
            1. Signature must be present (non-None / non-empty).
            2. Amount > 0.
            3. Sender must have sufficient balance.

        Args:
            sender: Source address.
            recipient: Destination address.
            amount: N amount to transfer (nanoN).
            signature: Sender's digital signature authorizing the transfer.

        Returns:
            LifecycleResult.
        """
        if not signature:
            return LifecycleResult(success=False, reason="TRANSFER: signature required")
        if amount <= 0:
            return LifecycleResult(success=False, reason="TRANSFER: amount must be positive")

        sender_balance = self._balances.get(sender, 0)
        if sender_balance < amount:
            return LifecycleResult(
                success=False,
                reason=(
                    f"TRANSFER insufficient balance: "
                    f"sender has {sender_balance}, requested {amount}"
                ),
            )

        # Execute
        self._balances[sender] = sender_balance - amount
        old_recipient = self._balances.get(recipient, 0)
        self._balances[recipient] = old_recipient + amount

        self._record(
            "TRANSFER",
            sender,
            amount,
            detail=f"recipient={recipient}, sender_old={sender_balance}",
        )

        return LifecycleResult(
            success=True,
            new_balance=self._balances[sender],
        )

    # --------------------------------------------------------------------- #
    #  Supply queries
    # --------------------------------------------------------------------- #

    def get_circulating_supply(self) -> int:
        """Return total N-money currently in circulation (nanoN).

        In a UTXO model this would be the sum of all unspent outputs.
        Here we sum the in-memory balance ledger.
        """
        return sum(self._balances.values())

    def get_balance(self, address: str) -> int:
        """Return the N balance of a single address (nanoN)."""
        return self._balances.get(address, 0)

    def get_corridor_status(self) -> CorridorStatus:
        """Return the current N-supply corridor status.

        The corridor [N_lower, N_upper] is a governance-defined band that
        constrains total circulating supply. Staying within the corridor is
        a health indicator for the monetary system.
        """
        supply = self.get_circulating_supply()
        dist_lower = supply - self.n_lower
        dist_upper = self.n_upper - supply
        return CorridorStatus(
            within_corridor=self.n_lower <= supply <= self.n_upper,
            circulating_supply=supply,
            n_lower=self.n_lower,
            n_upper=self.n_upper,
            distance_to_lower=dist_lower,
            distance_to_upper=dist_upper,
        )

    def get_audit_log(self) -> list[dict[str, Any]]:
        """Return a copy of the audit log for inspection."""
        return list(self._audit_log)


# =========================================================================== #
#  Self-Test
# =========================================================================== #

def _self_test() -> None:
    print("=== n_lifecycle.py self-test ===")

    gov = GovernanceParams(
        genesis_params=SystemParameters(
            min_n_mint=1_000_000_000,          # 1 N
            required_gov_signatures=2,
        )
    )
    mgr = NLifecycleManager(governance=gov, n_lower=0, n_upper=10_000_000_000_000)

    addr_a = "addr_a"
    addr_b = "addr_b"
    gov_sigs = [b"gov_sig_1", b"gov_sig_2"]
    bad_sigs = [b"gov_sig_1"]

    # 1. Mint — valid
    r = mgr.mint(addr_a, 5_000_000_000, gov_sigs)  # 5 N
    assert r.success and r.new_balance == 5_000_000_000
    assert mgr.get_circulating_supply() == 5_000_000_000
    print("[PASS] MINT valid")

    # 2. Mint — insufficient gov signatures
    r = mgr.mint(addr_a, 1_000_000_000, bad_sigs)
    assert not r.success and "insufficient" in (r.reason or "").lower()
    print("[PASS] MINT rejected with insufficient gov signatures")

    # 3. Mint — below minimum
    r = mgr.mint(addr_a, 500_000_000, gov_sigs)  # 0.5 N < 1 N min
    assert not r.success and "below minimum" in (r.reason or "")
    print("[PASS] MINT rejected below minimum")

    # 4. Mint — would exceed corridor
    tiny_mgr = NLifecycleManager(
        governance=gov, n_lower=0, n_upper=6_000_000_000  # 6 N ceiling
    )
    tiny_mgr.mint(addr_a, 5_000_000_000, gov_sigs)
    r = tiny_mgr.mint(addr_b, 2_000_000_000, gov_sigs)  # would hit 7 N
    assert not r.success and "corridor upper bound" in (r.reason or "")
    print("[PASS] MINT rejected when exceeding corridor")

    # 5. Replenish — valid
    r = mgr.replenish(addr_a, 1_000_000_000, gov_sigs)  # +1 N
    assert r.success and r.new_balance == 6_000_000_000
    print("[PASS] REPLENISH valid")

    # 6. Replenish — target does not exist
    r = mgr.replenish("nonexistent", 1_000_000_000, gov_sigs)
    assert not r.success and "does not exist" in (r.reason or "")
    print("[PASS] REPLENISH rejected for non-existent account")

    # 7. Transfer — valid
    r = mgr.transfer(addr_a, addr_b, 2_000_000_000, b"sender_sig")
    assert r.success and r.new_balance == 4_000_000_000
    assert mgr.get_balance(addr_b) == 2_000_000_000
    assert mgr.get_circulating_supply() == 6_000_000_000  # unchanged
    print("[PASS] TRANSFER valid")

    # 8. Transfer — insufficient balance
    r = mgr.transfer(addr_a, addr_b, 10_000_000_000, b"sender_sig")
    assert not r.success and "insufficient balance" in (r.reason or "")
    print("[PASS] TRANSFER rejected for insufficient balance")

    # 9. Transfer — missing signature
    r = mgr.transfer(addr_a, addr_b, 1_000_000_000, "")
    assert not r.success and "signature required" in (r.reason or "")
    print("[PASS] TRANSFER rejected for missing signature")

    # 10. Burn — valid
    r = mgr.burn(addr_a, 1_000_000_000, gov_sigs)
    assert r.success and r.new_balance == 3_000_000_000
    assert mgr.get_circulating_supply() == 5_000_000_000
    print("[PASS] BURN valid")

    # 11. Burn — insufficient balance
    r = mgr.burn(addr_a, 10_000_000_000, gov_sigs)
    assert not r.success and "insufficient balance" in (r.reason or "")
    print("[PASS] BURN rejected for insufficient balance")

    # 12. Burn — would breach lower bound
    floor_mgr = NLifecycleManager(
        governance=gov, n_lower=5_000_000_000, n_upper=100_000_000_000
    )
    floor_mgr.mint(addr_a, 6_000_000_000, gov_sigs)
    r = floor_mgr.burn(addr_a, 2_000_000_000, gov_sigs)  # would leave 4 N < 5 N floor
    assert not r.success and "corridor lower bound" in (r.reason or "")
    print("[PASS] BURN rejected when breaching corridor floor")

    # 13. Corridor status
    status = mgr.get_corridor_status()
    assert status.within_corridor
    assert status.circulating_supply == 5_000_000_000
    assert status.n_lower == 0
    assert status.n_upper == 10_000_000_000_000
    print("[PASS] Corridor status correct")

    # 14. Audit log
    log = mgr.get_audit_log()
    assert len(log) >= 4  # mint + replenish + transfer + burn
    assert log[0]["op"] == "MINT"
    print("[PASS] Audit log recorded")

    print("=== all n_lifecycle.py tests passed ===")


if __name__ == "__main__":
    _self_test()
