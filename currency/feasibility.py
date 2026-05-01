"""N-Feasibility Constraint Engine

Implements the BCS "N feasibility constraint" — the economic rule that an
entity's scale of sales (measured by external payment amount) is bounded by
its holdings of N-money.

Economic Rationale:
    In BCS, N is the scarce resource that limits how much externally paid
    business an agent can conduct. This scarcity is intentional: it forces economic participants
to maintain genuine "being-needed" relationships rather than engaging in
    speculative or empty transactions. The constraint acts as a natural
    macro-prudential limit, analogous to a reserve requirement in traditional
    banking but applied at the micro level of every sale.

Key formulas (all integer arithmetic):
    • max_sale_capacity = available_n / φ
    • auth_bonus = 1 + min(0.1 × months_active, 1.0)
    • adjusted_capacity = max_sale_capacity × auth_bonus
    • feasibility check: current_period_usage + proposed_sale ≤ adjusted_capacity

To avoid floating-point errors, the auth_bonus is stored as a scaled integer
with a fixed precision (BONUS_SCALE = 1000).  Thus:
    bonus_scaled = 1000 + min(100 × months_active, 1000)
    adjusted_capacity = (max_sale_capacity × bonus_scaled) // 1000
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

try:
    from .params import SystemParameters
except ImportError:  # pragma: no cover
    from params import SystemParameters

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #

# ~12-hour sliding window at 5-second block intervals
SALE_WINDOW_BLOCKS: int = 8640

# Approximate blocks per month (30 days * 24h * 3600s / 5s per block)
BLOCKS_PER_MONTH: int = 518_400

# Fixed-point scale for auth_bonus calculations (3 decimal places)
BONUS_SCALE: int = 1000

# Maximum bonus multiplier: 2.0× (i.e. bonus_scaled = 2000)
MAX_BONUS_SCALED: int = 2000


# --------------------------------------------------------------------------- #
#  Data Structures
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class SaleUsageRecord:
    """A single entry in the per-address sliding-window usage log.

    Attributes:
        address: The account address (hex string).
        amount: External payment amount consumed by this sale (smallest unit, e.g. cents).
        height: Block height at which the sale was recorded.
    """
    address: str
    amount: int
    height: int


@dataclass(frozen=True)
class FeasibilityResult:
    """Outcome of a feasibility check.

    Attributes:
        feasible: True if the proposed sale is within capacity.
        remaining_capacity: Unused external-sale capacity after the proposed sale.
        shortfall: If infeasible, the amount by which the proposal exceeds capacity.
    """
    feasible: bool
    remaining_capacity: int
    shortfall: int


# --------------------------------------------------------------------------- #
#  Mock / stub types for AccountState (core module may not yet exist)
# --------------------------------------------------------------------------- #

try:
    from core.state import AccountState, IdentityStatus
except ImportError:  # pragma: no cover
    AccountState = Any  # type: ignore
    IdentityStatus = Any  # type: ignore


# --------------------------------------------------------------------------- #
#  Feasibility Engine
# --------------------------------------------------------------------------- #

class NFeasibilityEngine:
    """Calculates N feasibility constraints and tracks per-address sale usage.

    The engine maintains a sliding-window log of external sale consumption for each
    address. When a new sale is proposed, it checks whether the cumulative
    usage in the current window plus the proposed amount fits within the
    adjusted capacity derived from the account's N balance.

    Usage in block validation:
        1. Before accepting a TRANSFER_SALE tx, call check_sale_feasibility().
        2. If feasible, proceed to CurrencyRulesEngine validation (φ rule).
        3. After tx is confirmed in a block, call record_sale_usage().
    """

    def __init__(self, current_height: int = 0) -> None:
        """Initialize the feasibility engine.

        Args:
            current_height: The chain tip block height for window calculations.
        """
        self._current_height: int = current_height
        # address -> list of SaleUsageRecord (unsorted; cleaned on access)
        self._usage_log: dict[str, list[SaleUsageRecord]] = {}

    # --------------------------------------------------------------------- #
    #  Core capacity calculation
    # --------------------------------------------------------------------- #

    def calculate_max_sale_capacity(
        self,
        address: str,
        account_state: Optional[AccountState],
        params: SystemParameters,
    ) -> int:
        """Calculate the maximum D-sale capacity for an account.

        Formula (integer arithmetic):
            theoretical_max = (available_n × phi_denominator) // phi_numerator
            bonus_scaled = calculate_auth_bonus_scaled(state)
            adjusted_capacity = (theoretical_max × bonus_scaled) // BONUS_SCALE

        Economic interpretation:
            The more N an entity holds, the larger the D-sales it can support,
            because each sale requires a φ-proportion N rebate. The
            authentication bonus rewards long-standing participants with up to
            2× capacity, reflecting accumulated trust and economic history.

        Args:
            address: Account address (for logging / correlation).
            account_state: The account's derived state (must expose n_available,
                           identity_status, first_auth_height).
            params: SystemParameters for the φ ratio.

        Returns:
            Maximum allowable external sale volume in the configured smallest unit.
        """
        available_n = self._extract_n_available(account_state)
        if available_n <= 0:
            return 0

        # Integer division: available_n / φ
        theoretical_max = (available_n * params.phi_denominator) // params.phi_numerator
        if theoretical_max <= 0:
            return 0

        # Apply authentication duration bonus
        bonus_scaled = self.calculate_auth_bonus_scaled(account_state)
        adjusted_capacity = (theoretical_max * bonus_scaled) // BONUS_SCALE

        return int(adjusted_capacity)

    # --------------------------------------------------------------------- #
    #  Feasibility check
    # --------------------------------------------------------------------- #

    def check_sale_feasibility(
        self,
        address: str,
        proposed_sale_amount_d: int,
        account_state: Optional[AccountState],
        params: SystemParameters,
    ) -> FeasibilityResult:
        """Check whether a proposed sale is within the account's feasibility corridor.

        Logic:
            capacity = calculate_max_sale_capacity(...)
            current_usage = sum of recorded sales in the sliding window
            if current_usage + proposed_sale ≤ capacity:
                feasible = True
            else:
                feasible = False, shortfall = current_usage + proposed - capacity

        Args:
            address: The seller's account address.
            proposed_sale_amount_d: External payment amount of the proposed sale.
            account_state: AccountState for N balance and auth info.
            params: SystemParameters for φ and corridor constants.

        Returns:
            FeasibilityResult with feasibility flag and capacity details.
        """
        if proposed_sale_amount_d <= 0:
            return FeasibilityResult(
                feasible=False,
                remaining_capacity=0,
                shortfall=0,
            )

        capacity = self.calculate_max_sale_capacity(address, account_state, params)
        current_usage = self._get_period_usage(address)

        total_after = current_usage + proposed_sale_amount_d
        if total_after <= capacity:
            return FeasibilityResult(
                feasible=True,
                remaining_capacity=capacity - total_after,
                shortfall=0,
            )
        else:
            return FeasibilityResult(
                feasible=False,
                remaining_capacity=max(0, capacity - current_usage),
                shortfall=total_after - capacity,
            )

    # --------------------------------------------------------------------- #
    #  Usage recording (sliding window)
    # --------------------------------------------------------------------- #

    def record_sale_usage(
        self,
        address: str,
        sale_amount_d: int,
        at_height: int,
    ) -> None:
        """Record a confirmed sale in the sliding-window usage log.

        This method should be called after a TRANSFER_SALE transaction is
        confirmed in a block. It appends the sale to the log and prunes
        entries that have fallen outside the window.

        Args:
            address: Seller's account address.
            sale_amount_d: External payment amount of the confirmed sale.
            at_height: Block height at which the sale was confirmed.
        """
        record = SaleUsageRecord(address=address, amount=sale_amount_d, height=at_height)
        self._usage_log.setdefault(address, []).append(record)
        self._prune_expired(address, at_height)
        # Update internal height tracker
        self._current_height = max(self._current_height, at_height)

    def _get_period_usage(self, address: str) -> int:
        """Sum D-sale amounts within the sliding window for an address."""
        records = self._usage_log.get(address, [])
        if not records:
            return 0
        window_start = max(0, self._current_height - SALE_WINDOW_BLOCKS)
        return sum(r.amount for r in records if r.height > window_start)

    def _prune_expired(self, address: str, at_height: int) -> None:
        """Remove usage records that have fallen outside the sliding window."""
        window_start = max(0, at_height - SALE_WINDOW_BLOCKS)
        records = self._usage_log.get(address, [])
        self._usage_log[address] = [r for r in records if r.height > window_start]

    def get_usage_records(self, address: str) -> list[SaleUsageRecord]:
        """Return a copy of the usage records for an address."""
        return list(self._usage_log.get(address, []))

    # --------------------------------------------------------------------- #
    #  Authentication bonus
    # --------------------------------------------------------------------- #

    def calculate_auth_bonus_scaled(self, state: Optional[AccountState]) -> int:
        """Compute the authentication duration bonus as a scaled integer.

        Formula:
            bonus_scaled = 1000 + min(100 × months_active, 1000)

        Where:
            months_active = blocks_since_auth / BLOCKS_PER_MONTH

        Constraints:
            • If not AUTHENTICATED → return 0 (no sales allowed).
            • months_active ≥ 0.
            • Maximum bonus = 2000 (i.e. 2.0× capacity).

        Economic rationale:
            Longer-authenticated accounts have demonstrated sustained economic
            presence. The bonus (up to 2×) rewards this stability while still
            keeping the N feasibility binding.

        Args:
            state: AccountState with identity_status and first_auth_height.

        Returns:
            Scaled bonus integer (1000 = 1.0×, 2000 = 2.0×).
        """
        if state is None:
            return 0

        status = getattr(state, "identity_status", None)
        # Accept either enum value or integer 2 (AUTHENTICATED)
        if status is None or (
            (isinstance(status, int) and status != 2)
            and (not hasattr(status, "value") or status.value != 2)
        ):
            return 0

        first_auth_height = getattr(state, "first_auth_height", 0)
        if first_auth_height == 0:
            return BONUS_SCALE  # no bonus, but allow sales

        blocks_since_auth = max(0, self._current_height - first_auth_height)
        months_active = blocks_since_auth // BLOCKS_PER_MONTH

        # bonus_scaled = 1000 + min(100 * months_active, 1000)
        extra_scaled = min(100 * months_active, BONUS_SCALE)
        bonus_scaled = BONUS_SCALE + extra_scaled

        # Clamp at maximum 2.0×
        return min(bonus_scaled, MAX_BONUS_SCALED)

    def calculate_auth_bonus(self, state: Optional[AccountState]) -> float:
        """Return the authentication bonus as a float (for display only).

        WARNING: Do NOT use this value in consensus-critical calculations.
        Always use calculate_auth_bonus_scaled() for exact arithmetic.
        """
        scaled = self.calculate_auth_bonus_scaled(state)
        return scaled / BONUS_SCALE

    # --------------------------------------------------------------------- #
    #  Internal helpers
    # --------------------------------------------------------------------- #

    @staticmethod
    def _extract_n_available(account_state: Optional[AccountState]) -> int:
        """Safely extract n_available from an AccountState-like object."""
        if account_state is None:
            return 0
        return int(getattr(account_state, "n_available", 0))

    @property
    def current_height(self) -> int:
        return self._current_height

    def set_current_height(self, height: int) -> None:
        """Update the reference block height (e.g. on new block import)."""
        self._current_height = height


# =========================================================================== #
#  Self-Test
# =========================================================================== #

def _self_test() -> None:
    print("=== feasibility.py self-test ===")

    params = SystemParameters(phi_numerator=3, phi_denominator=100)  # φ = 3%

    # Mock AccountState
    class MockState:
        def __init__(self, n_available: int, identity_status: int = 2, first_auth_height: int = 0):
            self.n_available = n_available
            self.identity_status = identity_status  # 2 = AUTHENTICATED
            self.first_auth_height = first_auth_height

    # 1. Basic capacity: 300 nanoN, φ=3% → capacity = 300 / 0.03 = 10_000
    state = MockState(n_available=300)
    engine = NFeasibilityEngine(current_height=0)
    cap = engine.calculate_max_sale_capacity("addr1", state, params)
    assert cap == 10_000, f"Expected 10_000, got {cap}"
    print("[PASS] Basic capacity 300 nanoN / 3% = 10_000")

    # 2. Zero balance → zero capacity
    state_zero = MockState(n_available=0)
    cap_zero = engine.calculate_max_sale_capacity("addr1", state_zero, params)
    assert cap_zero == 0
    print("[PASS] Zero balance gives zero capacity")

    # 3. Feasibility check — within capacity
    result = engine.check_sale_feasibility("addr1", 5_000, state, params)
    assert result.feasible
    assert result.remaining_capacity == 5_000
    assert result.shortfall == 0
    print("[PASS] Feasibility check within capacity")

    # 4. Feasibility check — exceeds capacity
    result2 = engine.check_sale_feasibility("addr1", 15_000, state, params)
    assert not result2.feasible
    assert result2.shortfall == 5_000
    print("[PASS] Feasibility check exceeds capacity")

    # 5. Sliding window usage recording
    engine.record_sale_usage("addr1", 3_000, at_height=100)
    engine.record_sale_usage("addr1", 2_000, at_height=200)
    usage = engine._get_period_usage("addr1")
    assert usage == 5_000
    # After pruning at height 9000, record at 100 should still be in window
    engine.set_current_height(8_000)
    engine.record_sale_usage("addr1", 1_000, at_height=8_000)
    # At height 9000, window_start = 9000 - 8640 = 360, so records at 100 and 200 are OUT
    engine.set_current_height(9_000)
    engine._prune_expired("addr1", 9_000)
    usage_after = engine._get_period_usage("addr1")
    assert usage_after == 1_000, f"Expected 1000 (only 8000 record), got {usage_after}"
    print("[PASS] Sliding window pruning")

    # 6. Auth bonus — unauthenticated
    state_unauth = MockState(n_available=300, identity_status=0)
    bonus_unauth = engine.calculate_auth_bonus_scaled(state_unauth)
    assert bonus_unauth == 0
    cap_unauth = engine.calculate_max_sale_capacity("addr1", state_unauth, params)
    assert cap_unauth == 0  # bonus=0 → capacity=0
    print("[PASS] Unauthenticated account has zero capacity")

    # 7. Auth bonus — 0 months (newly authenticated)
    state_new = MockState(n_available=300, first_auth_height=1_000_000)
    engine.set_current_height(1_000_000)
    bonus_new = engine.calculate_auth_bonus_scaled(state_new)
    assert bonus_new == 1000  # 1.0×
    cap_new = engine.calculate_max_sale_capacity("addr1", state_new, params)
    assert cap_new == 10_000
    print("[PASS] Auth bonus 1.0× for newly authenticated")

    # 8. Auth bonus — 5 months active
    engine.set_current_height(1_000_000 + 5 * BLOCKS_PER_MONTH)
    bonus_5mo = engine.calculate_auth_bonus_scaled(state_new)
    assert bonus_5mo == 1500  # 1.0 + 0.5 = 1.5×
    cap_5mo = engine.calculate_max_sale_capacity("addr1", state_new, params)
    assert cap_5mo == 15_000, f"Expected 15_000, got {cap_5mo}"
    print("[PASS] Auth bonus 1.5× after 5 months")

    # 9. Auth bonus — 12 months active (capped at 2.0×)
    engine.set_current_height(1_000_000 + 12 * BLOCKS_PER_MONTH)
    bonus_12mo = engine.calculate_auth_bonus_scaled(state_new)
    assert bonus_12mo == 2000  # 2.0× capped
    cap_12mo = engine.calculate_max_sale_capacity("addr1", state_new, params)
    assert cap_12mo == 20_000, f"Expected 20_000, got {cap_12mo}"
    print("[PASS] Auth bonus capped at 2.0× after 12 months")

    # 10. Float bonus display
    assert engine.calculate_auth_bonus(state_new) == 2.0
    print("[PASS] Float bonus display")

    # 11. Record then check — cumulative usage respects capacity
    engine_fresh = NFeasibilityEngine(current_height=100)
    state_300 = MockState(n_available=300, first_auth_height=0)
    # capacity = 10_000
    engine_fresh.record_sale_usage("seller", 4_000, at_height=50)
    engine_fresh.record_sale_usage("seller", 3_000, at_height=80)
    # current_usage = 7_000, remaining = 3_000
    res = engine_fresh.check_sale_feasibility("seller", 2_500, state_300, params)
    assert res.feasible, f"Expected feasible, got shortfall {res.shortfall}"
    assert res.remaining_capacity == 500
    # Record the 2_500 sale, making current_usage = 9_500
    engine_fresh.record_sale_usage("seller", 2_500, at_height=90)
    # Now request 1_000 more → total 10_500 > 10_000 capacity
    res2 = engine_fresh.check_sale_feasibility("seller", 1_000, state_300, params)
    assert not res2.feasible
    assert res2.shortfall == 500
    print("[PASS] Cumulative usage respects capacity")

    # 12. Edge: very small N balance with large φ denominator
    params_small = SystemParameters(phi_numerator=1, phi_denominator=1000)  # φ=0.1%
    state_small = MockState(n_available=1)
    cap_small = engine.calculate_max_sale_capacity("addr1", state_small, params_small)
    assert cap_small == 1000  # 1 / 0.001 = 1000
    print("[PASS] Small balance with tiny φ")

    print("=== all feasibility.py tests passed ===")


if __name__ == "__main__":
    _self_test()
