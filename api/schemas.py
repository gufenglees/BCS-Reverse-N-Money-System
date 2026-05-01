"""
BCS API — Pydantic Schemas
==========================
Comprehensive Pydantic models for BCS REST API and gRPC serialization.
Every model provides ``to_core()`` and ``from_core()`` converters bridging
Pydantic ↔ native dataclasses in ``bcs_chain.core`` and ``bcs_chain.currency``.

Design choices:
  • All monetary fields are ``int`` (nanoN) in API to avoid float rounding.
  • Hex strings are used for hashes / signatures / scripts in JSON.
  • Enums are IntEnum to match Protobuf conventions.
"""

from __future__ import annotations

from decimal import Decimal
from enum import IntEnum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# --------------------------------------------------------------------------- #
#  Helper utilities
# --------------------------------------------------------------------------- #

def _hexify(b: bytes) -> str:
    return b.hex() if b else ""


def _dehexify(s: str) -> bytes:
    return bytes.fromhex(s) if s else b""


# --------------------------------------------------------------------------- #
#  Enums
# --------------------------------------------------------------------------- #

class TxStatus(IntEnum):
    """Lifecycle state of a transaction on the BCS network."""
    UNKNOWN = 0
    PENDING = 1          # Received but not yet in mempool (pre-validation)
    MEMPOOL = 2          # In mempool, awaiting block inclusion
    CONFIRMED = 3        # Included in a finalized block
    REJECTED = 4         # Failed validation, will never be accepted


class IdentityStatus(IntEnum):
    """Derived from core.state.IdentityStatus for API exposure."""
    UNAUTHENTICATED = 0
    PENDING = 1
    AUTHENTICATED = 2
    SUSPENDED = 3
    REVOKED = 4


class TxType(IntEnum):
    """Transaction semantic type codes."""
    TRANSFER = 0
    TRANSFER_SALE = 1
    TRANSFER_WAGE = 2
    MINT = 10
    REPLENISH = 11
    BURN = 12
    REGISTER_IDENTITY = 20
    UPDATE_IDENTITY = 21
    GOV_PARAMETER_CHANGE = 30
    GOV_VALIDATOR_CHANGE = 31


# --------------------------------------------------------------------------- #
#  Transaction sub-schemas
# --------------------------------------------------------------------------- #

class TxInputSchema(BaseModel):
    """API representation of a transaction input."""
    tx_hash: str = Field(default="", description="Hex hash of the referenced transaction")
    output_index: int = Field(default=0, ge=0)
    unlock_script: str = Field(default="", description="Hex-encoded scriptSig")

    @field_validator("unlock_script", mode="before")
    @classmethod
    def _ensure_hex(cls, v: Any) -> str:
        if isinstance(v, bytes):
            return v.hex()
        return str(v)

    def to_core(self) -> "TxInput":
        from core.transaction import TxInput as CoreTxInput
        return CoreTxInput(
            tx_hash=self.tx_hash,
            output_index=self.output_index,
            unlock_script=_dehexify(self.unlock_script),
        )

    @classmethod
    def from_core(cls, obj: "TxInput") -> "TxInputSchema":
        return cls(
            tx_hash=obj.tx_hash,
            output_index=obj.output_index,
            unlock_script=_hexify(obj.unlock_script),
        )


class TxOutputSchema(BaseModel):
    """API representation of a transaction output."""
    amount: int = Field(default=0, ge=0, description="nanoN")
    lock_script: str = Field(default="", description="Hex-encoded scriptPubKey")
    asset_type: int = Field(default=0)
    metadata: str = Field(default="", description="Hex-encoded extra constraints")

    @field_validator("lock_script", "metadata", mode="before")
    @classmethod
    def _ensure_hex(cls, v: Any) -> str:
        if isinstance(v, bytes):
            return v.hex()
        return str(v)

    def to_core(self) -> "TxOutput":
        from core.transaction import TxOutput as CoreTxOutput
        return CoreTxOutput(
            amount=self.amount,
            lock_script=_dehexify(self.lock_script),
            asset_type=self.asset_type,
            metadata=_dehexify(self.metadata),
        )

    @classmethod
    def from_core(cls, obj: "TxOutput") -> "TxOutputSchema":
        return cls(
            amount=obj.amount,
            lock_script=_hexify(obj.lock_script),
            asset_type=obj.asset_type,
            metadata=_hexify(obj.metadata),
        )


class ZKProofSchema(BaseModel):
    """Zero-knowledge proof attachment for shielded transactions."""
    proof_data: str = Field(default="", description="Hex-encoded proof bytes")
    public_inputs: str = Field(default="", description="Hex-encoded public inputs")
    circuit_id: int = Field(default=0)

    @field_validator("proof_data", "public_inputs", mode="before")
    @classmethod
    def _ensure_hex(cls, v: Any) -> str:
        if isinstance(v, bytes):
            return v.hex()
        return str(v)

    def to_core(self) -> "ZKProof":
        from core.transaction import ZKProof as CoreZKProof
        return CoreZKProof(
            proof_data=_dehexify(self.proof_data),
            public_inputs=_dehexify(self.public_inputs),
            circuit_id=self.circuit_id,
        )

    @classmethod
    def from_core(cls, obj: "ZKProof") -> "ZKProofSchema":
        return cls(
            proof_data=_hexify(obj.proof_data),
            public_inputs=_hexify(obj.public_inputs),
            circuit_id=obj.circuit_id,
        )


class TransactionSchema(BaseModel):
    """Full transaction exposed via REST / gRPC."""
    version: int = Field(default=1)
    tx_type: TxType = Field(default=TxType.TRANSFER)
    inputs: list[TxInputSchema] = Field(default_factory=list)
    outputs: list[TxOutputSchema] = Field(default_factory=list)
    lock_time: int = Field(default=0, ge=0)
    extra: str = Field(default="", description="Hex-encoded type-specific data")
    witnesses: list[str] = Field(default_factory=list, description="Hex signatures")
    zk_proof: Optional[ZKProofSchema] = None

    @field_validator("extra", mode="before")
    @classmethod
    def _ensure_hex(cls, v: Any) -> str:
        if isinstance(v, bytes):
            return v.hex()
        return str(v)

    @field_validator("witnesses", mode="before")
    @classmethod
    def _ensure_hex_list(cls, v: Any) -> list[str]:
        if not isinstance(v, list):
            return []
        return [i.hex() if isinstance(i, bytes) else str(i) for i in v]

    def to_core(self) -> "Transaction":
        from core.transaction import Transaction as CoreTx, TxType as CoreTxType
        zk = self.zk_proof.to_core() if self.zk_proof else None
        return CoreTx(
            version=self.version,
            tx_type=CoreTxType(self.tx_type),
            inputs=[i.to_core() for i in self.inputs],
            outputs=[o.to_core() for o in self.outputs],
            lock_time=self.lock_time,
            extra=_dehexify(self.extra),
            witnesses=[_dehexify(w) for w in self.witnesses],
            zk_proof=zk,
        )

    @classmethod
    def from_core(cls, obj: "Transaction") -> "TransactionSchema":
        return cls(
            version=obj.version,
            tx_type=TxType(obj.tx_type),
            inputs=[TxInputSchema.from_core(i) for i in obj.inputs],
            outputs=[TxOutputSchema.from_core(o) for o in obj.outputs],
            lock_time=obj.lock_time,
            extra=_hexify(obj.extra),
            witnesses=[_hexify(w) for w in obj.witnesses],
            zk_proof=ZKProofSchema.from_core(obj.zk_proof) if obj.zk_proof else None,
        )


# --------------------------------------------------------------------------- #
#  Block schemas
# --------------------------------------------------------------------------- #

class BlockHeaderSchema(BaseModel):
    """Block header for REST/gRPC responses."""
    version: int = Field(default=1)
    prev_block_hash: str = Field(default="0" * 64)
    merkle_root_tx: str = Field(default="0" * 64)
    merkle_root_utxo: str = Field(default="0" * 64)
    merkle_root_identity: str = Field(default="0" * 64)
    timestamp: int = Field(default=0)
    height: int = Field(default=0, ge=0)
    tx_count: int = Field(default=0, ge=0)
    validator_pubkey: str = Field(default="")
    signature: str = Field(default="")
    extra_data: str = Field(default="", description="Hex-encoded auxiliary data")

    @field_validator("extra_data", mode="before")
    @classmethod
    def _ensure_hex(cls, v: Any) -> str:
        if isinstance(v, bytes):
            return v.hex()
        return str(v)

    def to_core(self) -> "BlockHeader":
        from core.block import BlockHeader as CoreHeader
        return CoreHeader(
            version=self.version,
            prev_block_hash=self.prev_block_hash,
            merkle_root_tx=self.merkle_root_tx,
            merkle_root_utxo=self.merkle_root_utxo,
            merkle_root_identity=self.merkle_root_identity,
            timestamp=self.timestamp,
            height=self.height,
            tx_count=self.tx_count,
            validator_pubkey=self.validator_pubkey,
            signature=self.signature,
            extra_data=_dehexify(self.extra_data),
        )

    @classmethod
    def from_core(cls, obj: "BlockHeader") -> "BlockHeaderSchema":
        return cls(
            version=obj.version,
            prev_block_hash=obj.prev_block_hash,
            merkle_root_tx=obj.merkle_root_tx,
            merkle_root_utxo=obj.merkle_root_utxo,
            merkle_root_identity=obj.merkle_root_identity,
            timestamp=obj.timestamp,
            height=obj.height,
            tx_count=obj.tx_count,
            validator_pubkey=obj.validator_pubkey,
            signature=obj.signature,
            extra_data=_hexify(obj.extra_data),
        )


class BlockSchema(BaseModel):
    """Full block with header + transactions."""
    header: BlockHeaderSchema
    transactions: list[TransactionSchema] = Field(default_factory=list)

    def to_core(self) -> "Block":
        from core.block import Block as CoreBlock, BlockBody as CoreBlockBody
        return CoreBlock(
            header=self.header.to_core(),
            body=CoreBlockBody(transactions=[tx.to_core() for tx in self.transactions]),
        )

    @classmethod
    def from_core(cls, obj: "Block") -> "BlockSchema":
        return cls(
            header=BlockHeaderSchema.from_core(obj.header),
            transactions=[TransactionSchema.from_core(t) for t in obj.body.transactions],
        )


# --------------------------------------------------------------------------- #
#  UTXO / Balance / Account schemas
# --------------------------------------------------------------------------- #

class UTXOSchema(BaseModel):
    """Unspent transaction output exposed via API."""
    tx_hash: str
    output_index: int
    amount: int = Field(description="nanoN")
    lock_script: str = Field(description="Hex-encoded scriptPubKey")
    asset_type: int = Field(default=0)
    metadata: str = Field(default="", description="Hex-encoded constraints")
    confirmations: int = Field(default=0, ge=0)

    @field_validator("lock_script", "metadata", mode="before")
    @classmethod
    def _ensure_hex(cls, v: Any) -> str:
        if isinstance(v, bytes):
            return v.hex()
        return str(v)

    def to_core(self) -> "UTXO":
        from core.utxo import UTXO as CoreUTXO
        return CoreUTXO(
            tx_hash=self.tx_hash,
            output_index=self.output_index,
            amount=self.amount,
            lock_script=_dehexify(self.lock_script),
            asset_type=self.asset_type,
            metadata=_dehexify(self.metadata),
            confirmations=self.confirmations,
        )

    @classmethod
    def from_core(cls, obj: "UTXO") -> "UTXOSchema":
        return cls(
            tx_hash=obj.tx_hash,
            output_index=obj.output_index,
            amount=obj.amount,
            lock_script=_hexify(obj.lock_script),
            asset_type=obj.asset_type,
            metadata=_hexify(obj.metadata),
            confirmations=obj.confirmations,
        )


class GetUTXOsRequest(BaseModel):
    """Request body for querying UTXOs by address."""
    address: str = Field(description="Base58Check or hex address")
    min_amount: int = Field(default=0, ge=0, description="Minimum nanoN filter")
    include_spent_in_mempool: bool = Field(default=False)


class GetUTXOsResponse(BaseModel):
    """Response wrapping a list of UTXOs."""
    utxos: list[UTXOSchema] = Field(default_factory=list)
    total_amount: int = Field(default=0, description="Sum of all UTXO amounts (nanoN)")


class GetBalanceRequest(BaseModel):
    """Request for balance query."""
    address: str
    at_height: Optional[int] = Field(default=None, description="Historical height; None = latest")


class GetBalanceResponse(BaseModel):
    """Account balance and BCS feasibility summary."""
    address: str
    n_balance: str = Field(description="Total N balance (nanoN as string)")
    n_available: str = Field(description="Spendable N (nanoN as string)")
    max_sale_capacity: str = Field(description="Max D-denominated sale capacity")
    current_sale_volume: str = Field(description="D sales consumed in current window")
    identity_status: str
    last_activity: int = 0


class AccountStateSchema(BaseModel):
    """Full derived account state."""
    address: str
    did: str = ""
    n_balance: int = 0
    n_locked: int = 0
    n_available: int = 0
    max_sale_capacity: int = 0
    current_sale_volume: int = 0
    identity_status: IdentityStatus = IdentityStatus.UNAUTHENTICATED
    first_auth_height: int = 0
    last_replenish_height: int = 0
    nonce: int = 0
    last_activity: int = 0

    def to_core(self) -> "AccountState":
        from core.state import AccountState as CoreAccountState, IdentityStatus as CoreIdentityStatus
        return CoreAccountState(
            address=self.address,
            did=self.did,
            n_balance=self.n_balance,
            n_locked=self.n_locked,
            n_available=self.n_available,
            max_sale_capacity=self.max_sale_capacity,
            current_sale_volume=self.current_sale_volume,
            identity_status=CoreIdentityStatus(self.identity_status),
            first_auth_height=self.first_auth_height,
            last_replenish_height=self.last_replenish_height,
            nonce=self.nonce,
            last_activity=self.last_activity,
        )

    @classmethod
    def from_core(cls, obj: "AccountState") -> "AccountStateSchema":
        return cls(
            address=obj.address,
            did=obj.did,
            n_balance=obj.n_balance,
            n_locked=obj.n_locked,
            n_available=obj.n_available,
            max_sale_capacity=obj.max_sale_capacity,
            current_sale_volume=obj.current_sale_volume,
            identity_status=IdentityStatus(obj.identity_status),
            first_auth_height=obj.first_auth_height,
            last_replenish_height=obj.last_replenish_height,
            nonce=obj.nonce,
            last_activity=obj.last_activity,
        )


# --------------------------------------------------------------------------- #
#  Transaction submit / status schemas
# --------------------------------------------------------------------------- #

class SubmitTxRequest(BaseModel):
    """Client request to submit a transaction."""
    tx: TransactionSchema
    wait_confirmation: bool = Field(default=False, description="Block until confirmed")
    timeout_ms: int = Field(default=30_000, ge=0)


class SubmitTxResponse(BaseModel):
    """Acknowledgement after transaction submission."""
    tx_hash: str
    status: TxStatus
    expected_block_height: Optional[int] = None
    message: str = ""


class TxStatusResponse(BaseModel):
    """Detailed transaction status query response."""
    tx_hash: str
    status: TxStatus
    confirmed_height: Optional[int] = None
    reject_reason: Optional[str] = None
    block_hash: Optional[str] = None
    timestamp: int = Field(default=0, description="Unix ms when status was last updated")


# --------------------------------------------------------------------------- #
#  Offline sync schemas
# --------------------------------------------------------------------------- #

class RejectedTxSchema(BaseModel):
    """A transaction rejected during offline batch submission."""
    tx_hash: str
    reason: str
    conflict_info: Optional[dict[str, Any]] = None


class OfflineBatchRequest(BaseModel):
    """Batch submission from an offline client after reconnection."""
    txs: list[TransactionSchema] = Field(default_factory=list)
    last_known_block_hash: str = Field(default="", description="Hash before going offline")
    sequence_number: int = Field(default=0, ge=0, description="Offline batch sequence")


class OfflineBatchResponse(BaseModel):
    """Result of offline batch processing."""
    accepted_tx_hashes: list[str] = Field(default_factory=list)
    rejected: list[RejectedTxSchema] = Field(default_factory=list)
    new_tip_hash: str = ""
    synced_blocks: int = 0
    resolved_conflicts: int = 0


class OfflinePrepareRequest(BaseModel):
    """Request a light UTXO proof package for offline use."""
    address: str
    max_utxos: int = Field(default=100, ge=1, le=1000)


class OfflinePrepareResponse(BaseModel):
    """Lightweight UTXO set with Merkle proofs for offline validation."""
    address: str
    utxos: list[UTXOSchema] = Field(default_factory=list)
    merkle_proofs: list[str] = Field(default_factory=list, description="Hex proof paths")
    tip_hash: str
    tip_height: int


class ConflictCheckRequest(BaseModel):
    """Request conflict detection between local and chain state."""
    local_utxo_outpoints: list[str] = Field(default_factory=list)
    proposed_tx_hashes: list[str] = Field(default_factory=list)


class ConflictCheckResponse(BaseModel):
    """Conflict detection result."""
    conflicts_found: int
    conflict_details: list[dict[str, Any]] = Field(default_factory=list)
    suggested_resolution: Optional[str] = None


# --------------------------------------------------------------------------- #
#  Identity / DID schemas
# --------------------------------------------------------------------------- #

class DIDDocumentSchema(BaseModel):
    """Simplified DID Document for ``did:bcs`` method."""
    id: str = Field(description="Full DID, e.g. did:bcs:<pubkey_hash>")
    controller: str = ""
    public_keys: list[dict[str, Any]] = Field(default_factory=list)
    authentication: list[str] = Field(default_factory=list)
    service_endpoints: list[dict[str, Any]] = Field(default_factory=list)
    created: int = 0
    updated: int = 0

    @model_validator(mode="before")
    @classmethod
    def _accept_did_json_ld_keys(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        if "public_keys" not in normalized and "verificationMethod" in normalized:
            normalized["public_keys"] = normalized["verificationMethod"]
        if "service_endpoints" not in normalized and "service" in normalized:
            normalized["service_endpoints"] = normalized["service"]
        return normalized


class RegisterDIDRequest(BaseModel):
    """On-chain DID registration request."""
    did_document: DIDDocumentSchema
    verifiable_credential: str = Field(description="JSON-LD VC string")
    signature: str = Field(description="Hex signature over the DIDAuth challenge")
    challenge: str = Field(default="", description="Server-issued DIDAuth challenge")


class RegisterDIDResponse(BaseModel):
    """DID registration acknowledgement."""
    did: str
    status: IdentityStatus = IdentityStatus.PENDING
    tx_hash: Optional[str] = None
    message: str = ""


class IdentityChallengeRequest(BaseModel):
    """Request a short-lived DIDAuth challenge for a privileged identity action."""
    did: str = Field(description="DID proving control")
    action: str = Field(default="identity.register", description="Action being authorized")


class IdentityChallengeResponse(BaseModel):
    """Challenge that must be signed by the DID controller's private key."""
    did: str
    action: str
    challenge: str
    expires_at: int = Field(description="Unix timestamp in seconds")
    signing_instructions: str = "Sign the UTF-8 challenge bytes with the DID private key."


class ActivateIdentityRequest(BaseModel):
    """Governance request to activate a PENDING DID identity."""
    did: str
    gov_signatures: list[str] = Field(default_factory=list, description="Governance signatures")
    auth_height: int = Field(default=0, ge=0)


class AuthStatusResponse(BaseModel):
    """Authentication status of a DID."""
    did: str
    status: IdentityStatus
    authenticated_at_height: Optional[int] = None
    trust_anchor: Optional[str] = None


# --------------------------------------------------------------------------- #
#  Governance / Parameters schemas
# --------------------------------------------------------------------------- #

class SystemParametersSchema(BaseModel):
    """Current BCS economic and consensus parameters."""
    phi_numerator: int = 3
    phi_denominator: int = 100
    psi_numerator: int = 5
    psi_denominator: int = 100
    block_interval_ms: int = 5000
    max_block_size: int = 1_048_576
    max_tx_per_block: int = 2000
    min_n_mint: int = 1_000_000_000
    replenish_threshold: int = 100_000_000_000
    validators: list[str] = Field(default_factory=list)
    required_gov_signatures: int = 2

    @property
    def phi(self) -> Decimal:
        return Decimal(self.phi_numerator) / Decimal(self.phi_denominator)

    @property
    def psi(self) -> Decimal:
        return Decimal(self.psi_numerator) / Decimal(self.psi_denominator)

    def to_core(self) -> "SystemParameters":
        from currency.params import SystemParameters as CoreParams
        return CoreParams(
            phi_numerator=self.phi_numerator,
            phi_denominator=self.phi_denominator,
            psi_numerator=self.psi_numerator,
            psi_denominator=self.psi_denominator,
            block_interval_ms=self.block_interval_ms,
            max_block_size=self.max_block_size,
            max_tx_per_block=self.max_tx_per_block,
            min_n_mint=self.min_n_mint,
            replenish_threshold=self.replenish_threshold,
            validators=tuple(self.validators),
            required_gov_signatures=self.required_gov_signatures,
        )

    @classmethod
    def from_core(cls, obj: "SystemParameters") -> "SystemParametersSchema":
        return cls(
            phi_numerator=obj.phi_numerator,
            phi_denominator=obj.phi_denominator,
            psi_numerator=obj.psi_numerator,
            psi_denominator=obj.psi_denominator,
            block_interval_ms=obj.block_interval_ms,
            max_block_size=obj.max_block_size,
            max_tx_per_block=obj.max_tx_per_block,
            min_n_mint=obj.min_n_mint,
            replenish_threshold=obj.replenish_threshold,
            validators=list(obj.validators),
            required_gov_signatures=obj.required_gov_signatures,
        )


# --------------------------------------------------------------------------- #
#  State proof / Light client schemas
# --------------------------------------------------------------------------- #

class StateProofSchema(BaseModel):
    """Merkle proof for a specific UTXO or account at a given block."""
    block_hash: str
    utxo_root: str
    merkle_proof: str = Field(description="Hex-encoded proof path")
    validator_signatures: list[str] = Field(default_factory=list)
    target_key: str = Field(description="UTXO outpoint or account address")
    target_value_hash: str = Field(description="Hash of the proven value")


class LightProofRequest(BaseModel):
    """Request a light proof for a UTXO or account."""
    target_key: str
    at_height: Optional[int] = None


class LightProofResponse(BaseModel):
    """Lightweight proof for offline/SPV validation."""
    proof: StateProofSchema
    block_header: BlockHeaderSchema


# --------------------------------------------------------------------------- #
#  Mempool / System info schemas
# --------------------------------------------------------------------------- #

class MempoolInfoSchema(BaseModel):
    """Mempool snapshot for monitoring."""
    tx_count: int
    total_size_bytes: int
    max_size_bytes: int
    min_fee_per_byte: int
    peak_size_1h: int


class ShieldedTxRequest(BaseModel):
    """Request to create a shielded (ZK) transaction."""
    nullifiers: list[str] = Field(default_factory=list, description="Hex UTXO nullifiers")
    commitments: list[str] = Field(default_factory=list, description="Hex output commitments")
    proof: str = Field(description="Base64 or hex encoded ZKProof")
    fee: int = Field(default=0, ge=0)
    privacy_mode: str = Field(default="shielded", pattern="^(public|shielded|mixed)$")


class ShieldedTxResponse(BaseModel):
    """Acknowledgement for a shielded transaction."""
    tx_hash: str
    status: TxStatus
    message: str = "Accepted into shielded pool"


class HealthResponse(BaseModel):
    """Node health / liveness check."""
    status: str = "ok"
    version: str = "1.0.0"
    height: int = 0
    peers: int = 0
    uptime_seconds: float = 0.0


# --------------------------------------------------------------------------- #
#  Self-test
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import json

    # 1. Round-trip a TransactionSchema
    tx_s = TransactionSchema(
        tx_type=TxType.TRANSFER_SALE,
        inputs=[TxInputSchema(tx_hash="a" * 64, output_index=0, unlock_script="76a9")],
        outputs=[TxOutputSchema(amount=1_000_000, lock_script="76a914" + "b" * 40 + "88ac")],
        extra="abcd",
    )
    tx_core = tx_s.to_core()
    tx_back = TransactionSchema.from_core(tx_core)
    assert tx_back.tx_type == TxType.TRANSFER_SALE
    assert tx_back.inputs[0].tx_hash == "a" * 64
    print("[PASS] Transaction round-trip")

    # 2. Round-trip SystemParametersSchema
    params_s = SystemParametersSchema(phi_numerator=5, phi_denominator=1000)
    params_core = params_s.to_core()
    params_back = SystemParametersSchema.from_core(params_core)
    assert params_back.phi == Decimal("0.005")
    print("[PASS] SystemParameters round-trip")

    # 3. JSON serialization
    j = tx_s.model_dump_json()
    d = json.loads(j)
    assert d["tx_type"] == 1
    print("[PASS] JSON serialization")

    # 4. Block round-trip
    block_s = BlockSchema(
        header=BlockHeaderSchema(height=42, tx_count=3),
        transactions=[tx_s],
    )
    block_core = block_s.to_core()
    block_back = BlockSchema.from_core(block_core)
    assert block_back.header.height == 42
    print("[PASS] Block round-trip")

    print("\n=== All schema self-tests passed ===")
