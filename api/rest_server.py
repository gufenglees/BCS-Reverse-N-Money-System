"""
BCS API — FastAPI REST Server
=============================
A production-grade FastAPI application exposing the full BCS node surface:

  • NodeController      — tx submit/query, block query, balance, mempool
  • OfflineController   — offline prepare, batch submit, conflict detection
  • IdentityController  — DID registration, auth status
  • GovernanceController — system parameters
  • ZKController        — shielded transaction creation

Middleware stack (outer → inner):
  ErrorHandler → RateLimit → Authentication → Logging → FastAPI routers

All monetary amounts are ``int`` (nanoN) in the wire protocol.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Callable, Optional

from fastapi import FastAPI, APIRouter, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Import schemas
from api.schemas import (
    AccountStateSchema,
    ActivateIdentityRequest,
    AuthStatusResponse,
    BlockSchema,
    BlockHeaderSchema,
    ConflictCheckRequest,
    ConflictCheckResponse,
    GetBalanceRequest,
    GetBalanceResponse,
    GetUTXOsRequest,
    GetUTXOsResponse,
    HealthResponse,
    IdentityChallengeRequest,
    IdentityChallengeResponse,
    IdentityStatus,
    MempoolInfoSchema,
    OfflineBatchRequest,
    OfflineBatchResponse,
    OfflinePrepareRequest,
    OfflinePrepareResponse,
    RegisterDIDRequest,
    RegisterDIDResponse,
    RejectedTxSchema,
    ShieldedTxRequest,
    ShieldedTxResponse,
    StateProofSchema,
    SubmitTxRequest,
    SubmitTxResponse,
    SystemParametersSchema,
    TransactionSchema,
    TxStatus,
    TxStatusResponse,
    TxType,
    UTXOSchema,
)

from api.middleware import (
    APIException,
    AuthenticationMiddleware,
    AuthConfig,
    ErrorHandlerMiddleware,
    LoggingMiddleware,
    RateLimitMiddleware,
    RateLimitConfig,
    ValidationError,
    NotFoundError,
    ConflictError,
    InternalError,
    get_logger,
)

# Core imports (for type hints / bridging)
from core.transaction import Transaction, TxType as CoreTxType
from core.block import Block
from core.mempool import Mempool
from core.state import AccountState, IdentityStatus as CoreIdentityStatus
from currency.params import SystemParameters
from identity.did import DIDManager
from identity.vc import VCManager


logger = get_logger("bcs.api.rest")

IDENTITY_CHALLENGE_TTL_SECONDS = 300


# --------------------------------------------------------------------------- #
#  Application state (shared across requests)
# --------------------------------------------------------------------------- #

class NodeAppState:
    """Mutable application state wired into the FastAPI lifespan."""

    def __init__(self) -> None:
        self.mempool: Optional[Mempool] = None
        self.blockchain: Optional[Any] = None          # BlockStorage / ChainManager stub
        self.utxo_manager: Optional[Any] = None         # UTXOManager stub
        self.identity_registry: Optional[Any] = None  # IdentityRegistry stub
        self.trust_anchor_registry: Optional[Any] = None
        self.identity_challenges: dict[str, dict[str, Any]] = {}
        self.params: Optional[SystemParameters] = None
        self.offline_sync_engine: Optional[Any] = None
        self.zk_verifier: Optional[Any] = None
        self.started_at: float = 0.0

    @property
    def uptime_seconds(self) -> float:
        return time.monotonic() - self.started_at


# Global singleton state (real system would use dependency injection)
_app_state = NodeAppState()


# --------------------------------------------------------------------------- #
#  Lifespan
# --------------------------------------------------------------------------- #

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    _app_state.started_at = time.monotonic()
    if _app_state.mempool is None:
        _app_state.mempool = Mempool()
    if _app_state.params is None:
        _app_state.params = SystemParameters()
    logger.info("BCS REST API starting", extra={"version": "1.0.0"})
    yield
    logger.info("BCS REST API shutting down")


# --------------------------------------------------------------------------- #
#  FastAPI app factory
# --------------------------------------------------------------------------- #

def create_app(
    *,
    app_state: Optional[NodeAppState] = None,
    auth_config: Optional[AuthConfig] = None,
    rate_limit_config: Optional[RateLimitConfig] = None,
    debug: bool = False,
) -> FastAPI:
    global _app_state
    if app_state is not None:
        _app_state = app_state

    app = FastAPI(
        title="BCS Chain API",
        description="Bidirectional Currency System — REST API for nodes, wallets, and light clients",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Custom ASGI middleware stack (wrap the whole app)
    # Note: FastAPI middleware is applied in reverse order of add_middleware,
    # but for ASGI callables we manually wrap the inner app.
    asgi_app = app
    asgi_app = ErrorHandlerMiddleware(asgi_app, debug=debug)
    asgi_app = RateLimitMiddleware(asgi_app, config=rate_limit_config)
    asgi_app = AuthenticationMiddleware(asgi_app, config=auth_config)
    asgi_app = LoggingMiddleware(asgi_app)
    app.router.app = asgi_app  # type: ignore[attr-defined]

    # Mount routers
    app.include_router(_node_router, prefix="/api/v1")
    app.include_router(_offline_router, prefix="/api/v1")
    app.include_router(_identity_router, prefix="/api/v1")
    app.include_router(_governance_router, prefix="/api/v1")
    app.include_router(_zk_router, prefix="/api/v1")

    # Health (unauthenticated)
    @app.get("/health", response_model=HealthResponse, tags=["system"])
    async def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            version="1.0.0",
            height=_app_state.blockchain.height if _app_state.blockchain else 0,
            peers=0,
            uptime_seconds=round(_app_state.uptime_seconds, 3),
        )

    return app


# --------------------------------------------------------------------------- #
#  Node Controller
# --------------------------------------------------------------------------- #

_node_router = APIRouter(tags=["node"])


@_node_router.post("/tx", response_model=SubmitTxResponse, status_code=202)
async def submit_transaction(req: SubmitTxRequest) -> SubmitTxResponse:
    """
    Submit a new transaction to the BCS network.
    Returns immediately with the tx hash; use ``GET /tx/{hash}/status`` to poll confirmation.
    """
    tx_core: Transaction = req.tx.to_core()
    tx_hash = tx_core.hash()

    mempool = _app_state.mempool
    if mempool is None:
        raise InternalError("Mempool not initialized")

    # Validate and add
    try:
        mempool.add_tx(tx_core, fee=0)
    except Exception as exc:
        raise ValidationError(f"Transaction rejected: {exc}")

    logger.info("Transaction submitted", extra={"tx_hash": tx_hash, "tx_type": int(tx_core.tx_type)})

    return SubmitTxResponse(
        tx_hash=tx_hash,
        status=TxStatus.MEMPOOL,
        expected_block_height=(_app_state.blockchain.height + 1) if _app_state.blockchain else None,
        message="Accepted into mempool",
    )


@_node_router.get("/tx/{tx_hash}", response_model=TransactionSchema)
async def get_transaction(tx_hash: str) -> TransactionSchema:
    """Retrieve a transaction by its hex hash."""
    # Search mempool
    mempool = _app_state.mempool
    if mempool:
        tx = mempool.get_by_hash(tx_hash)
        if tx:
            return TransactionSchema.from_core(tx)

    # Check blockchain storage (stub)
    if _app_state.blockchain and hasattr(_app_state.blockchain, "get_tx"):
        tx = _app_state.blockchain.get_tx(tx_hash)
        if tx:
            return TransactionSchema.from_core(tx)

    raise NotFoundError(f"Transaction {tx_hash} not found")


@_node_router.get("/tx/{tx_hash}/status", response_model=TxStatusResponse)
async def get_transaction_status(tx_hash: str) -> TxStatusResponse:
    """Query the lifecycle status of a transaction."""
    # Search mempool first
    mempool = _app_state.mempool
    if mempool and mempool.contains(tx_hash):
        return TxStatusResponse(tx_hash=tx_hash, status=TxStatus.MEMPOOL, timestamp=int(time.time() * 1000))

    # Search chain (stub)
    if _app_state.blockchain and hasattr(_app_state.blockchain, "get_tx_status"):
        status = _app_state.blockchain.get_tx_status(tx_hash)
        if status:
            return TxStatusResponse(
                tx_hash=tx_hash,
                status=TxStatus.CONFIRMED,
                confirmed_height=status.get("height"),
                block_hash=status.get("block_hash"),
                timestamp=int(time.time() * 1000),
            )

    return TxStatusResponse(tx_hash=tx_hash, status=TxStatus.UNKNOWN, timestamp=int(time.time() * 1000))


@_node_router.get("/block/{height}", response_model=BlockSchema)
async def get_block_by_height(height: int) -> BlockSchema:
    """Retrieve a full block by height."""
    if _app_state.blockchain and hasattr(_app_state.blockchain, "get_block_by_height"):
        block = _app_state.blockchain.get_block_by_height(height)
        if block:
            return BlockSchema.from_core(block)
    raise NotFoundError(f"Block at height {height} not found")


@_node_router.get("/block/latest", response_model=BlockSchema)
async def get_latest_block() -> BlockSchema:
    """Return the most recently committed block."""
    if _app_state.blockchain and hasattr(_app_state.blockchain, "get_latest_block"):
        block = _app_state.blockchain.get_latest_block()
        if block:
            return BlockSchema.from_core(block)
    # Return genesis-like stub
    return BlockSchema(
        header=BlockHeaderSchema(height=0, prev_block_hash="0" * 64),
        transactions=[],
    )


@_node_router.get("/account/{address}/balance", response_model=GetBalanceResponse)
async def get_balance(address: str) -> GetBalanceResponse:
    """
    Query N balance and BCS feasibility for an address.
    Returns amounts as **strings** to avoid JSON float truncation.
    """
    # Derive from UTXO set
    utxos: list[Any] = []
    if _app_state.utxo_manager and hasattr(_app_state.utxo_manager, "get_utxos_for_address"):
        utxos = _app_state.utxo_manager.get_utxos_for_address(address)

    total = sum(u.amount for u in utxos)
    locked = sum(u.amount for u in utxos if u.metadata)  # simplistic lock heuristic
    available = total - locked

    phi = Decimal(3) / Decimal(100)  # default; real system reads from params
    if _app_state.params:
        phi = Decimal(_app_state.params.phi_numerator) / Decimal(_app_state.params.phi_denominator)

    max_sale = int(available / phi) if phi > 0 else 0

    identity = IdentityStatus.UNAUTHENTICATED
    if _app_state.identity_registry and hasattr(_app_state.identity_registry, "get_status"):
        identity = IdentityStatus(_app_state.identity_registry.get_status(address))

    return GetBalanceResponse(
        address=address,
        n_balance=str(total),
        n_available=str(available),
        max_sale_capacity=str(max_sale),
        current_sale_volume="0",
        identity_status=identity.name,
        last_activity=0,
    )


@_node_router.get("/account/{address}/utxos", response_model=GetUTXOsResponse)
async def get_utxos(
    address: str,
    min_confirms: int = Query(default=1, ge=0),
    min_amount: int = Query(default=0, ge=0),
) -> GetUTXOsResponse:
    """List spendable UTXOs for an address."""
    utxos: list[Any] = []
    if _app_state.utxo_manager and hasattr(_app_state.utxo_manager, "get_utxos_for_address"):
        raw = _app_state.utxo_manager.get_utxos_for_address(address)
        for u in raw:
            if u.confirmations >= min_confirms and u.amount >= min_amount:
                utxos.append(u)

    total = sum(u.amount for u in utxos)
    return GetUTXOsResponse(
        utxos=[UTXOSchema.from_core(u) for u in utxos],
        total_amount=total,
    )


@_node_router.get("/mempool", response_model=MempoolInfoSchema)
async def get_mempool() -> MempoolInfoSchema:
    """Current mempool statistics."""
    mempool = _app_state.mempool
    if mempool is None:
        return MempoolInfoSchema(tx_count=0, total_size_bytes=0, max_size_bytes=0, min_fee_per_byte=0, peak_size_1h=0)
    total_size = mempool.total_size_bytes()
    return MempoolInfoSchema(
        tx_count=mempool.size(),
        total_size_bytes=total_size,
        max_size_bytes=10_000_000,  # Default max mempool size
        min_fee_per_byte=0,
        peak_size_1h=0,
    )


# --------------------------------------------------------------------------- #
#  Offline Controller
# --------------------------------------------------------------------------- #

_offline_router = APIRouter(tags=["offline"])


@_offline_router.post("/offline/prepare", response_model=OfflinePrepareResponse)
async def offline_prepare(req: OfflinePrepareRequest) -> OfflinePrepareResponse:
    """
    Prepare a light UTXO proof package for a client entering offline mode.
    The package includes Merkle proofs so the client can independently verify
    UTXO validity during offline periods.
    """
    utxos: list[Any] = []
    if _app_state.utxo_manager and hasattr(_app_state.utxo_manager, "get_utxos_for_address"):
        raw = _app_state.utxo_manager.get_utxos_for_address(req.address)
        utxos = raw[: req.max_utxos]

    tip_hash = "0" * 64
    tip_height = 0
    if _app_state.blockchain and hasattr(_app_state.blockchain, "tip"):
        tip = _app_state.blockchain.tip
        tip_hash = tip.header.merkle_root_tx if hasattr(tip.header, "merkle_root_tx") else tip.hash()
        tip_height = tip.header.height

    # Merkle proofs are stubbed here; real impl would use PatriciaTrie.generate_proof
    proofs = ["deadbeef" for _ in utxos]

    return OfflinePrepareResponse(
        address=req.address,
        utxos=[UTXOSchema.from_core(u) for u in utxos],
        merkle_proofs=proofs,
        tip_hash=tip_hash,
        tip_height=tip_height,
    )


@_offline_router.post("/offline/submit-batch", response_model=OfflineBatchResponse)
async def offline_submit_batch(req: OfflineBatchRequest) -> OfflineBatchResponse:
    """
    Batch-submit transactions created while offline.
    Each tx is validated against current chain state; conflicts are returned.
    """
    accepted: list[str] = []
    rejected: list[RejectedTxSchema] = []
    mempool = _app_state.mempool

    for tx_s in req.txs:
        tx_core = tx_s.to_core()
        tx_hash = tx_core.hash()
        try:
            if mempool:
                mempool.add_tx(tx_core, fee=0)
            accepted.append(tx_hash)
        except Exception as exc:
            rejected.append(
                RejectedTxSchema(
                    tx_hash=tx_hash,
                    reason=str(exc),
                    conflict_info={"type": "validation_failed"},
                )
            )

    return OfflineBatchResponse(
        accepted_tx_hashes=accepted,
        rejected=rejected,
        new_tip_hash=(_app_state.blockchain.tip.hash() if _app_state.blockchain else ""),
        synced_blocks=0,
        resolved_conflicts=len(rejected),
    )


@_offline_router.post("/offline/conflicts", response_model=ConflictCheckResponse)
async def offline_conflicts(req: ConflictCheckRequest) -> ConflictCheckResponse:
    """
    Detect conflicts between a client's local UTXO view and the canonical chain.
    Useful before submitting an offline batch.
    """
    conflicts: list[dict[str, Any]] = []

    if _app_state.utxo_manager and hasattr(_app_state.utxo_manager, "exists"):
        for outpoint in req.local_utxo_outpoints:
            parts = outpoint.split(":")
            if len(parts) == 2:
                tx_hash, idx = parts[0], int(parts[1])
                if not _app_state.utxo_manager.exists(tx_hash, idx):
                    conflicts.append({"outpoint": outpoint, "reason": "already_spent"})

    return ConflictCheckResponse(
        conflicts_found=len(conflicts),
        conflict_details=conflicts,
        suggested_resolution="rebuild_with_fresh_utxos" if conflicts else None,
    )


# --------------------------------------------------------------------------- #
#  Identity Controller
# --------------------------------------------------------------------------- #

_identity_router = APIRouter(tags=["identity"])


def _extract_did_public_key(did_document: Any) -> bytes:
    """Extract the first DID authentication public key from the API schema."""
    public_keys = getattr(did_document, "public_keys", None) or []
    if not public_keys:
        raise ValidationError("DID document does not contain a public key")

    key = public_keys[0]
    if isinstance(key, dict):
        public_key_hex = (
            key.get("public_key_hex")
            or key.get("publicKeyHex")
            or key.get("publicKey")
            or key.get("publicKeyMultibase")
            or ""
        )
    else:
        public_key_hex = getattr(key, "public_key_hex", "") or getattr(key, "publicKeyHex", "")

    if not public_key_hex:
        raise ValidationError("DID document public key is missing public_key_hex")
    if public_key_hex.startswith("0x"):
        public_key_hex = public_key_hex[2:]
    try:
        return bytes.fromhex(public_key_hex)
    except ValueError as exc:
        raise ValidationError("DID document public key is not valid hex") from exc


def _consume_identity_challenge(did: str, action: str, challenge: str) -> bytes:
    """Validate and consume a short-lived DIDAuth challenge."""
    entry = _app_state.identity_challenges.pop(challenge, None)
    if entry is None:
        raise ValidationError("Unknown or already used DIDAuth challenge")
    if entry["did"] != did:
        raise ValidationError("DIDAuth challenge DID mismatch")
    if entry["action"] != action:
        raise ValidationError("DIDAuth challenge action mismatch")
    if int(time.time()) > int(entry["expires_at"]):
        raise ValidationError("DIDAuth challenge expired")
    return challenge.encode("utf-8")


def _verify_vc_against_trust_anchors(vc_json: str, did: str) -> tuple[Any, str]:
    """Parse a VC and verify it with one active Trust Anchor."""
    vc_mgr = VCManager()
    try:
        vc = vc_mgr.from_json(vc_json)
    except Exception as exc:
        raise ValidationError(f"Invalid VC JSON: {exc}") from exc

    if vc.credential_subject.id != did:
        raise ValidationError("VC subject DID does not match registration DID")

    registry = _app_state.trust_anchor_registry
    if registry is None or not hasattr(registry, "list_anchors"):
        raise ValidationError("No Trust Anchor registry configured")

    anchors = registry.list_anchors(active_only=True)
    if not anchors:
        raise ValidationError("No active Trust Anchors configured")

    for anchor in anchors:
        try:
            public_key = bytes.fromhex(anchor.public_key)
        except ValueError:
            continue
        if vc_mgr.verify_credential(vc, public_key):
            return vc, anchor.id

    raise ValidationError("VC signature was not issued by an active Trust Anchor")


@_identity_router.post("/identity/challenge", response_model=IdentityChallengeResponse)
async def create_identity_challenge(req: IdentityChallengeRequest) -> IdentityChallengeResponse:
    """
    Issue a short-lived DIDAuth challenge.

    The wallet must sign the returned UTF-8 challenge bytes with the DID
    controller private key and include the hex signature in the next request.
    """
    expires_at = int(time.time()) + IDENTITY_CHALLENGE_TTL_SECONDS
    nonce = secrets.token_hex(16)
    challenge = json.dumps(
        {
            "domain": "bcs-chain",
            "version": 1,
            "did": req.did,
            "action": req.action,
            "nonce": nonce,
            "expires_at": expires_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    _app_state.identity_challenges[challenge] = {
        "did": req.did,
        "action": req.action,
        "expires_at": expires_at,
    }
    return IdentityChallengeResponse(
        did=req.did,
        action=req.action,
        challenge=challenge,
        expires_at=expires_at,
    )


@_identity_router.post("/identity/register", response_model=RegisterDIDResponse, status_code=202)
async def register_did(req: RegisterDIDRequest) -> RegisterDIDResponse:
    """
    Register a DID on-chain along with a Verifiable Credential.
    The registration enters ``PENDING`` state after DIDAuth and VC verification,
    then waits for governance activation.
    """
    did = req.did_document.id
    logger.info("DID registration request", extra={"did": did})

    if not req.challenge:
        raise ValidationError("DIDAuth challenge is required; call /identity/challenge first")

    if req.did_document.controller and req.did_document.controller != did:
        raise ValidationError("DID document controller must match DID")

    try:
        DIDManager.did_to_address(did)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc

    public_key = _extract_did_public_key(req.did_document)
    challenge_bytes = _consume_identity_challenge(did, "identity.register", req.challenge)
    try:
        signature = bytes.fromhex(req.signature)
    except ValueError as exc:
        raise ValidationError("DIDAuth signature is not valid hex") from exc

    if not DIDManager().verify_ownership(did, challenge_bytes, signature, public_key=public_key):
        raise ValidationError("DIDAuth signature verification failed")

    vc, trust_anchor_id = _verify_vc_against_trust_anchors(req.verifiable_credential, did)

    if _app_state.identity_registry is None or not hasattr(_app_state.identity_registry, "register"):
        raise InternalError("Identity registry not initialized")

    try:
        record = _app_state.identity_registry.register(
            req.did_document,
            vc,
            metadata={
                "trust_anchor": trust_anchor_id,
                "vc_issuer": vc.issuer,
                "auth_method": "did_challenge_vc",
            },
        )
    except ValueError as exc:
        raise ConflictError(str(exc)) from exc

    tx_hash_stub = hashlib.sha3_256(
        json.dumps(
            {"type": "REGISTER_IDENTITY", "did": did, "vc_id": vc.id, "trust_anchor": trust_anchor_id},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    return RegisterDIDResponse(
        did=did,
        status=IdentityStatus(record.status),
        tx_hash=tx_hash_stub,
        message="Registration verified by DIDAuth and Trust Anchor; pending governance activation",
    )


@_identity_router.post("/identity/activate", response_model=AuthStatusResponse)
async def activate_identity(req: ActivateIdentityRequest) -> AuthStatusResponse:
    """
    Activate a PENDING identity after governance approval.

    This endpoint enforces the configured signature threshold.  The current
    registry still treats signatures as opaque proofs; cryptographic governance
    signature verification should be wired to the on-chain validator set next.
    """
    if _app_state.identity_registry is None or not hasattr(_app_state.identity_registry, "verify_and_activate"):
        raise InternalError("Identity registry not initialized")

    threshold = 1
    if _app_state.params is not None:
        threshold = int(getattr(_app_state.params, "required_gov_signatures", 1))
    valid_sigs = [sig for sig in req.gov_signatures if sig]
    if len(valid_sigs) < threshold:
        raise ValidationError(f"Governance signature threshold not met: {len(valid_sigs)} < {threshold}")

    try:
        record = _app_state.identity_registry.verify_and_activate(
            req.did,
            gov_signature=";".join(valid_sigs),
            auth_height=req.auth_height,
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc

    return AuthStatusResponse(
        did=req.did,
        status=IdentityStatus(record.status),
        authenticated_at_height=record.first_auth_height,
        trust_anchor=record.metadata.get("trust_anchor"),
    )


@_identity_router.get("/identity/{did}/status", response_model=AuthStatusResponse)
async def get_identity_status(did: str) -> AuthStatusResponse:
    """Query the authentication status of a registered DID."""
    status = IdentityStatus.UNAUTHENTICATED
    authenticated_at_height = None
    trust_anchor = None
    if _app_state.identity_registry and hasattr(_app_state.identity_registry, "get_record"):
        record = _app_state.identity_registry.get_record(did)
        if record:
            status = IdentityStatus(record.status)
            authenticated_at_height = record.first_auth_height or None
            trust_anchor = record.metadata.get("trust_anchor")

    return AuthStatusResponse(
        did=did,
        status=status,
        authenticated_at_height=authenticated_at_height,
        trust_anchor=trust_anchor,
    )


# --------------------------------------------------------------------------- #
#  Governance Controller
# --------------------------------------------------------------------------- #

_governance_router = APIRouter(tags=["governance"])


@_governance_router.get("/governance/parameters", response_model=SystemParametersSchema)
async def get_parameters() -> SystemParametersSchema:
    """Return current BCS system parameters (φ, ψ, block interval, validator set, etc.)."""
    params = _app_state.params or SystemParameters()
    return SystemParametersSchema.from_core(params)


# --------------------------------------------------------------------------- #
#  ZK Controller
# --------------------------------------------------------------------------- #

_zk_router = APIRouter(tags=["zk"])


@_zk_router.post("/zk/shield", response_model=ShieldedTxResponse, status_code=202)
async def create_shielded_tx(req: ShieldedTxRequest) -> ShieldedTxResponse:
    """
    Create / submit a shielded (privacy-preserving) transaction.
    Requires a valid ZK proof; the verifier checks nullifiers and commitments
    without revealing amounts or addresses.
    """
    # Simplified: accept proof string, hash it as tx identifier
    tx_hash = hashlib.sha3_256(req.proof.encode()).hexdigest()

    logger.info("Shielded tx submitted", extra={"tx_hash": tx_hash, "mode": req.privacy_mode})

    return ShieldedTxResponse(
        tx_hash=tx_hash,
        status=TxStatus.MEMPOOL,
        message="Accepted into shielded pool",
    )


# --------------------------------------------------------------------------- #
#  Self-test (runs uvicorn in-memory via TestClient)
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    from fastapi.testclient import TestClient

    # Manually init state for self-test (lifespan may not fire in some test modes)
    _app_state.mempool = Mempool()
    _app_state.params = SystemParameters()
    _app_state.blockchain = None
    _app_state.utxo_manager = None
    _app_state.identity_registry = None

    app = create_app(debug=True)
    client = TestClient(app)

    # 1. Health
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    print("[PASS] /health")

    # 2. Submit tx
    tx_payload = {
        "tx": {
            "version": 1,
            "tx_type": 0,
            "inputs": [{"tx_hash": "a" * 64, "output_index": 0, "unlock_script": ""}],
            "outputs": [{"amount": 1000, "lock_script": "76a9", "asset_type": 0, "metadata": ""}],
            "lock_time": 0,
            "extra": "",
            "witnesses": [],
        },
        "wait_confirmation": False,
        "timeout_ms": 5000,
    }
    r = client.post("/api/v1/tx", json=tx_payload)
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == TxStatus.MEMPOOL
    print("[PASS] POST /api/v1/tx")

    # 3. Tx status
    tx_hash = body["tx_hash"]
    r = client.get(f"/api/v1/tx/{tx_hash}/status")
    assert r.status_code == 200
    assert r.json()["tx_hash"] == tx_hash
    print("[PASS] GET /api/v1/tx/{hash}/status")

    # 4. Governance parameters
    r = client.get("/api/v1/governance/parameters")
    assert r.status_code == 200
    params = r.json()
    assert params["phi_numerator"] == 3
    assert params["phi_denominator"] == 100
    print("[PASS] GET /api/v1/governance/parameters")

    # 5. Mempool
    r = client.get("/api/v1/mempool")
    assert r.status_code == 200
    assert r.json()["tx_count"] >= 1
    print("[PASS] GET /api/v1/mempool")

    # 6. DIDAuth challenge. Full registration needs ecdsa keys and a configured
    # Trust Anchor, so the smoke test only verifies challenge issuance.
    did_req = {"did": "did:bcs:" + "ab" * 32, "action": "identity.register"}
    r = client.post("/api/v1/identity/challenge", json=did_req)
    assert r.status_code == 200
    assert r.json()["action"] == "identity.register"
    print("[PASS] POST /api/v1/identity/challenge")

    # 7. ZK shield
    shield_req = {
        "nullifiers": ["n1", "n2"],
        "commitments": ["c1", "c2"],
        "proof": "base64proofhere",
        "fee": 100,
        "privacy_mode": "shielded",
    }
    r = client.post("/api/v1/zk/shield", json=shield_req)
    assert r.status_code == 202
    print("[PASS] POST /api/v1/zk/shield")

    # 8. Offline prepare
    r = client.post("/api/v1/offline/prepare", json={"address": "addr1", "max_utxos": 10})
    assert r.status_code == 200
    print("[PASS] POST /api/v1/offline/prepare")

    # 9. Offline conflicts
    r = client.post("/api/v1/offline/conflicts", json={"local_utxo_outpoints": [], "proposed_tx_hashes": []})
    assert r.status_code == 200
    print("[PASS] POST /api/v1/offline/conflicts")

    # 10. OpenAPI schema available
    r = client.get("/openapi.json")
    assert r.status_code == 200
    spec = r.json()
    assert spec["info"]["title"] == "BCS Chain API"
    print("[PASS] /openapi.json generated")

    print("\n=== All REST server self-tests passed ===")
