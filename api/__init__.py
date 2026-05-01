"""
BCS Chain API Package
=====================
FastAPI REST and gRPC server modules for the BCS node.

Modules:
    rest_server   – FastAPI REST endpoints (Node, Offline, Identity, Governance, ZK)
    grpc_server   – gRPC service wrapper with streaming sync
    schemas       – Pydantic request/response models bridging core types
    middleware    – ASGI middleware stack (auth, rate-limit, logging, errors)
"""

from __future__ import annotations

__all__ = [
    "rest_server",
    "grpc_server",
    "schemas",
    "middleware",
]
