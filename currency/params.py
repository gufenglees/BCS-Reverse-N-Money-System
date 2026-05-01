"""BCS System Parameter Management

Implements governance-controlled system parameters with historical tracking.
All monetary ratios (φ, ψ) are stored as rational numbers (numerator/denominator)
to avoid floating-point precision issues in financial calculations.

Economic Rationale:
    φ (phi) — Seller rebate ratio: When a seller receives an external payment
              for goods, they must simultaneously transfer φ×external_amount
              of N-money to the buyer.
              This creates a mutual-obligation mechanism that enforces the
              "being-needed" relationship in commerce.

    ψ (psi) — Wage rebate ratio: When a worker receives externally paid wages,
              they must simultaneously transfer ψ×external_amount of N-money
              to the employer.
              This ensures labor relationships are backed by N-currency commitment.

The chain only mints, spends, burns and accounts for N. The external payment
amount is metadata used to calculate the required N obligation. Optional
references can point to cash, bank transfer, invoice, card payment, stablecoin
gateway, payroll record or another later-integrated payment rail.

Parameter changes are recorded by block height to enable deterministic replay
and support offline nodes that need to validate transactions against historical rules.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Any, Optional, Union
from copy import deepcopy


# --------------------------------------------------------------------------- #
#  Data Structures
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ParameterRecord:
    """Immutable snapshot of a parameter change at a specific block height.

    Attributes:
        height: Block height at which this parameter set became active.
        params: The SystemParameters instance valid from this height onward.
        change_reason: Optional human-readable description of the change.
    """
    height: int
    params: "SystemParameters"
    change_reason: str = ""


@dataclass(frozen=True)
class SystemParameters:
    """Immutable system parameters governing BCS monetary policy.

    All monetary amounts use nanoN (10^-9 N) as the base integer unit.
    φ and ψ are represented as rational numbers (numerator/denominator)
    to guarantee exact arithmetic and avoid floating-point rounding errors.

    Attributes:
        phi_numerator: Numerator of the φ ratio (e.g. 3 for 3%).
        phi_denominator: Denominator of the φ ratio (e.g. 100).
        psi_numerator: Numerator of the ψ ratio (e.g. 5 for 5%).
        psi_denominator: Denominator of the ψ ratio (e.g. 100).
        block_interval_ms: Target block interval in milliseconds (e.g. 5000).
        max_block_size: Maximum block body size in bytes.
        max_tx_per_block: Maximum number of transactions per block.
        min_n_mint: Minimum N amount that can be minted (nanoN).
        replenish_threshold: N balance threshold triggering auto-replenish (nanoN).
        validators: List of validator public keys (hex strings or bytes).
        required_gov_signatures: Minimum governance signatures for privileged ops.
    """
    phi_numerator: int = 3
    phi_denominator: int = 100
    psi_numerator: int = 5
    psi_denominator: int = 100
    block_interval_ms: int = 5000
    max_block_size: int = 1_048_576        # 1 MB
    max_tx_per_block: int = 2000
    min_n_mint: int = 1_000_000_000        # 1 N in nanoN
    replenish_threshold: int = 100_000_000_000  # 100 N in nanoN
    validators: tuple[str, ...] = field(default_factory=tuple)
    required_gov_signatures: int = 2

    # Derived cached values (not part of equality / hash)
    _phi_ratio: Optional[int] = field(default=None, repr=False, compare=False)
    _psi_ratio: Optional[int] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        # Validate invariants
        if self.phi_denominator == 0 or self.psi_denominator == 0:
            raise ValueError("Denominator cannot be zero.")
        if self.phi_numerator < 0 or self.psi_numerator < 0:
            raise ValueError("Ratio numerators must be non-negative.")
        if self.required_gov_signatures < 1:
            raise ValueError("required_gov_signatures must be at least 1.")
        if self.block_interval_ms < 1:
            raise ValueError("block_interval_ms must be positive.")

    # -- Rational number helpers (exact integer arithmetic) -------------------

    @property
    def phi_ratio_nano(self) -> int:
        """Return φ as a scaled integer: φ * 1_000_000_000 (nanoN per D unit).

        This property is useful for quick comparisons while still avoiding floats.
        """
        return (self.phi_numerator * 1_000_000_000) // self.phi_denominator

    @property
    def psi_ratio_nano(self) -> int:
        """Return ψ as a scaled integer: ψ * 1_000_000_000 (nanoN per D unit)."""
        return (self.psi_numerator * 1_000_000_000) // self.psi_denominator

    def required_n_for_sale(self, d_amount: int) -> int:
        """Calculate minimum N the seller must transfer to buyer for a sale.

        Formula: required_n = ceil(φ * external_amount)
        Using integer arithmetic: required_n = (phi_num * external_amount + phi_den - 1) // phi_den

        Args:
            d_amount: External payment amount in its smallest configured unit.
                The parameter name is kept for backward compatibility.

        Returns:
            Minimum N amount in nanoN.
        """
        num = self.phi_numerator * d_amount
        return (num + self.phi_denominator - 1) // self.phi_denominator

    def required_n_for_wage(self, d_amount: int) -> int:
        """Calculate minimum N the worker must transfer to employer for wages.

        Formula: required_n = ceil(ψ * external_amount)
        """
        num = self.psi_numerator * d_amount
        return (num + self.psi_denominator - 1) // self.psi_denominator

    def max_sale_capacity(self, available_n: int) -> int:
        """Maximum external sale volume an account can support given its N balance.

        Formula: capacity = available_n / φ (integer division).
        Economic meaning: With N available, one can only sell goods/services
        up to the point where the required φ-rebate N is fully consumed.
        """
        return (available_n * self.phi_denominator) // self.phi_numerator

    def max_wage_capacity(self, available_n: int) -> int:
        """Maximum external wage volume a worker can receive given their N balance.

        Formula: capacity = available_n / ψ (integer division).
        """
        return (available_n * self.psi_denominator) // self.psi_numerator

    # -- Serialization helpers -----------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize parameters to a plain dictionary."""
        return {
            "phi_numerator": self.phi_numerator,
            "phi_denominator": self.phi_denominator,
            "psi_numerator": self.psi_numerator,
            "psi_denominator": self.psi_denominator,
            "block_interval_ms": self.block_interval_ms,
            "max_block_size": self.max_block_size,
            "max_tx_per_block": self.max_tx_per_block,
            "min_n_mint": self.min_n_mint,
            "replenish_threshold": self.replenish_threshold,
            "validators": list(self.validators),
            "required_gov_signatures": self.required_gov_signatures,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SystemParameters":
        """Deserialize from a plain dictionary."""
        vals = data.get("validators", [])
        if isinstance(vals, (list, tuple)):
            vals = tuple(str(v) for v in vals)
        return cls(
            phi_numerator=int(data["phi_numerator"]),
            phi_denominator=int(data["phi_denominator"]),
            psi_numerator=int(data["psi_numerator"]),
            psi_denominator=int(data["psi_denominator"]),
            block_interval_ms=int(data["block_interval_ms"]),
            max_block_size=int(data["max_block_size"]),
            max_tx_per_block=int(data["max_tx_per_block"]),
            min_n_mint=int(data["min_n_mint"]),
            replenish_threshold=int(data["replenish_threshold"]),
            validators=vals,
            required_gov_signatures=int(data["required_gov_signatures"]),
        )


# --------------------------------------------------------------------------- #
#  Governance Parameter History
# --------------------------------------------------------------------------- #

class GovernanceParams:
    """Maintains a history of SystemParameters indexed by activation height.

    This class provides deterministic access to the parameter set that was
    active at any given block height — critical for:
      1. Offline nodes replaying historical transactions with correct rules.
      2. Conflict resolution when rules changed during a node's offline period.
      3. Fork resolution: two branches may have divergent parameter histories.

    The history is stored as an ordered list of ParameterRecord entries.
    Each entry records the block height at which a new parameter set took effect.
    """

    def __init__(
        self,
        genesis_params: Optional[SystemParameters] = None,
        history: Optional[list[ParameterRecord]] = None,
    ) -> None:
        self._history: list[ParameterRecord] = []
        if history:
            self._history = sorted(history, key=lambda r: r.height)
        else:
            gp = genesis_params or SystemParameters()
            self._history.append(ParameterRecord(height=0, params=gp, change_reason="genesis"))

    # -- Persistence ---------------------------------------------------------

    def save(self, filepath: str) -> None:
        """Serialize parameter history to JSON on disk.

        Args:
            filepath: Absolute or relative path to the JSON file.
        """
        serializable = [
            {
                "height": rec.height,
                "params": rec.params.to_dict(),
                "change_reason": rec.change_reason,
            }
            for rec in self._history
        ]
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)

    @classmethod
    def load(cls, filepath: str) -> "GovernanceParams":
        """Load parameter history from a JSON file.

        Args:
            filepath: Path to the JSON file.

        Returns:
            A GovernanceParams instance with the loaded history.
        """
        if not os.path.exists(filepath):
            # Return fresh instance with default genesis parameters
            return cls()
        with open(filepath, "r", encoding="utf-8") as f:
            raw = json.load(f)
        history = [
            ParameterRecord(
                height=int(item["height"]),
                params=SystemParameters.from_dict(item["params"]),
                change_reason=item.get("change_reason", ""),
            )
            for item in raw
        ]
        return cls(history=history)

    # -- Mutation ------------------------------------------------------------

    def update(
        self,
        new_params: SystemParameters,
        at_height: int,
        reason: str = "",
    ) -> None:
        """Record a parameter change that takes effect at a given block height.

        The new parameter set becomes the active set at `at_height` and remains
        valid until superseded by a later record.

        Args:
            new_params: The new SystemParameters to activate.
            at_height: Block height at which the change takes effect.
            reason: Optional description for audit trails.

        Raises:
            ValueError: If at_height is not strictly greater than the latest
                        recorded height.
        """
        if self._history and at_height <= self._history[-1].height:
            raise ValueError(
                f"Parameter update height ({at_height}) must exceed "
                f"latest recorded height ({self._history[-1].height})."
            )
        record = ParameterRecord(height=at_height, params=new_params, change_reason=reason)
        self._history.append(record)

    # -- Historical Query ----------------------------------------------------

    def get_params_at_height(self, height: int) -> SystemParameters:
        """Return the SystemParameters active at the given block height.

        Uses binary search (O(log n)) over the history list.

        Args:
            height: Block height to query.

        Returns:
            The parameter set that was active at `height`.
        """
        lo, hi = 0, len(self._history) - 1
        best = self._history[0].params
        while lo <= hi:
            mid = (lo + hi) // 2
            rec = self._history[mid]
            if rec.height <= height:
                best = rec.params
                lo = mid + 1
            else:
                hi = mid - 1
        return best

    def get_parameter_at_height(self, param_name: str, height: int) -> Union[int, tuple, str]:
        """Query a single parameter value by name at a specific height.

        Args:
            param_name: Name of the parameter attribute on SystemParameters.
            height: Block height to query.

        Returns:
            The parameter value (type depends on the attribute).

        Raises:
            AttributeError: If param_name does not exist on SystemParameters.
        """
        params = self.get_params_at_height(height)
        if not hasattr(params, param_name):
            raise AttributeError(
                f"SystemParameters has no attribute '{param_name}'"
            )
        return getattr(params, param_name)

    def latest(self) -> SystemParameters:
        """Return the most recently active parameter set."""
        return self._history[-1].params

    def latest_height(self) -> int:
        """Return the block height of the latest parameter record."""
        return self._history[-1].height

    def history(self) -> list[ParameterRecord]:
        """Return a shallow copy of the full parameter history."""
        return list(self._history)

    def __len__(self) -> int:
        return len(self._history)


# =========================================================================== #
#  Self-Test
# =========================================================================== #

def _self_test() -> None:
    import tempfile

    print("=== params.py self-test ===")

    # 1. Default parameters
    p = SystemParameters()
    assert p.phi_numerator == 3 and p.phi_denominator == 100
    assert p.psi_numerator == 5 and p.psi_denominator == 100
    assert p.required_n_for_sale(1000) == 30          # ceil(3% * 1000) = 30
    assert p.required_n_for_sale(1) == 1              # ceil(3% * 1) = 1
    assert p.required_n_for_wage(1000) == 50          # ceil(5% * 1000) = 50
    assert p.max_sale_capacity(300) == 10_000          # 300 / 0.03 = 10_000
    print("[PASS] Default parameters & rational math")

    # 2. Custom parameters
    custom = SystemParameters(
        phi_numerator=1,
        phi_denominator=20,   # 5%
        psi_numerator=1,
        psi_denominator=10,   # 10%
        validators=("0xabc", "0xdef"),
        required_gov_signatures=2,
    )
    assert custom.required_n_for_sale(100) == 5       # ceil(5% * 100)
    assert custom.required_n_for_wage(100) == 10      # ceil(10% * 100)
    print("[PASS] Custom parameters")

    # 3. Governance history
    gov = GovernanceParams(genesis_params=p)
    assert gov.latest().phi_numerator == 3
    assert gov.get_params_at_height(0).phi_numerator == 3
    assert gov.get_params_at_height(999).phi_numerator == 3

    # Update at height 1000
    p2 = SystemParameters(phi_numerator=4, phi_denominator=100)
    gov.update(p2, at_height=1000, reason="increase phi to 4%")
    assert gov.latest().phi_numerator == 4
    assert gov.get_params_at_height(999).phi_numerator == 3
    assert gov.get_params_at_height(1000).phi_numerator == 4
    assert gov.get_params_at_height(5000).phi_numerator == 4
    print("[PASS] Governance history & height-based lookup")

    # 4. get_parameter_at_height
    assert gov.get_parameter_at_height("phi_numerator", 500) == 3
    assert gov.get_parameter_at_height("phi_numerator", 1000) == 4
    assert gov.get_parameter_at_height("max_tx_per_block", 1000) == 2000
    print("[PASS] get_parameter_at_height")

    # 5. Save / load roundtrip
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
        tmp_path = tmp.name
    gov.save(tmp_path)
    gov2 = GovernanceParams.load(tmp_path)
    assert len(gov2) == 2
    assert gov2.get_params_at_height(0).phi_numerator == 3
    assert gov2.get_params_at_height(1000).phi_numerator == 4
    os.remove(tmp_path)
    print("[PASS] Save / load roundtrip")

    # 6. Bad update height
    try:
        gov.update(p2, at_height=500)
        assert False, "Expected ValueError"
    except ValueError:
        pass
    print("[PASS] Bad update height rejected")

    print("=== all params.py tests passed ===")


if __name__ == "__main__":
    _self_test()
