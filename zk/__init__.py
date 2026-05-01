"""
BCS Zero-Knowledge Package
============================
Zero-knowledge proof primitives for shielded transactions.

Modules:
    commitment  – Pedersen-like commitments for value hiding
    circuits    – ZK circuit definitions (range, membership, sum)
    prover      – Proof generation interface
    verifier    – Proof verification interface
"""

from __future__ import annotations

__all__ = [
    "commitment",
    "circuits",
    "prover",
    "verifier",
]
