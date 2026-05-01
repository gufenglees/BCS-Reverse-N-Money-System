"""
BCS Chain — Offline Module Package
====================================

Provides offline-first transaction handling for the Bidirectional Currency System.

Modules:
    tx_builder        — OfflineTxBuilder (unsigned tx construction + signing)
    cache             — TxCache (SQLite-backed persistent tx pool with TTL)
    utxo_view         — UTXOSyncView (optimistic local UTXO replica)
    sync              — SyncEngine (6-phase reconnection synchronisation)
    conflict_resolver — ConflictResolver (automated & semi-automated conflict resolution)
    light_client      — LightClient (Merkle / state / header verification)
"""

__all__ = [
    "OfflineTxBuilder",
    "TxCache",
    "TxStatus",
    "UTXOSyncView",
    "SyncEngine",
    "SyncResult",
    "ConflictResolver",
    "Conflict",
    "Resolution",
    "LightClient",
]
