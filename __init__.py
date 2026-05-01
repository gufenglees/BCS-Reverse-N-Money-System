"""
BCS Chain — Bidirectional Currency System Blockchain
====================================================
A complete blockchain implementation for the BCS economic model.

Modules:
    core        – Blockchain primitives (blocks, transactions, UTXO, consensus, storage)
    currency    – Monetary policy engine (φ/ψ rules, parameter governance)
    offline     – Offline transaction support, sync engine, light client
    identity    – DID / VC registry, trust anchors, authentication
    zk          – Zero-knowledge proofs for privacy-preserving transactions
    api         – REST and gRPC API servers
    network     – P2P gossip and sync layer
    wallet      – Key management, address derivation, offline signing
    cli         – Command-line interface for node and wallet operations

Entry Points:
    node        – BCSNode (main node runtime)
    scripts     – Genesis generator, key generator

Quick Start:
    >>> from bcs_chain.node import BCSNode
    >>> node = BCSNode("config.toml")
    >>> node.start()
"""

from __future__ import annotations

import sys
from pathlib import Path

__version__ = "0.1.0"
__all__ = [
    "core",
    "currency",
    "offline",
    "identity",
    "zk",
    "api",
    "network",
    "wallet",
    "cli",
    "node",
    "scripts",
]


def _install_legacy_import_paths() -> None:
    """
    Keep both supported import styles working during the package migration.

    Several modules still use script-era imports such as ``from core.transaction``
    or ``from _core_stubs``.  Adding these package-local directories to
    ``sys.path`` lets ``python -m bcs_chain...`` and external package imports
    resolve the same modules without each caller having to patch paths.
    """
    package_root = Path(__file__).resolve().parent
    search_paths = [package_root]
    search_paths.extend(
        package_root / name
        for name in (
            "core",
            "currency",
            "offline",
            "identity",
            "zk",
            "api",
            "network",
            "wallet",
            "cli",
        )
    )
    for path in reversed(search_paths):
        path_str = str(path)
        if path_str not in sys.path:
            sys.path.insert(0, path_str)


_install_legacy_import_paths()
