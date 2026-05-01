"""
BCS Currency Module

Implements the Bidirectional Currency System (BCS) monetary policy rules,
N-currency lifecycle management, and feasibility constraints.

Submodules:
    params        — System parameter governance and historical tracking
    rules_engine  — φ/ψ ratio enforcement for SALE and WAGE transactions
    n_lifecycle   — Mint, replenish, burn, and transfer of N currency
    feasibility   — N feasibility corridor and capacity calculations
"""

from .params import SystemParameters, GovernanceParams, ParameterRecord
from .rules_engine import CurrencyRulesEngine, ValidationResult
from .n_lifecycle import NLifecycleManager, CorridorStatus
from .feasibility import NFeasibilityEngine, FeasibilityResult, SaleUsageRecord

__all__ = [
    # params
    "SystemParameters",
    "GovernanceParams",
    "ParameterRecord",
    # rules_engine
    "CurrencyRulesEngine",
    "ValidationResult",
    # n_lifecycle
    "NLifecycleManager",
    "CorridorStatus",
    # feasibility
    "NFeasibilityEngine",
    "FeasibilityResult",
    "SaleUsageRecord",
]
