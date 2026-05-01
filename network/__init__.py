"""
BCS Network Package
===================
P2P networking layer for the BCS blockchain.

Modules:
    messages  – Wire protocol message types and serializer
    p2p       – Async P2P node with gossip, peer management, and callbacks
"""

from __future__ import annotations

__all__ = [
    "messages",
    "p2p",
]
