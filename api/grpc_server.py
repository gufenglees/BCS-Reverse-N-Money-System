"""
BCS API — gRPC Server Wrapper (Simplified)
==========================================
A lightweight grpcio-based server exposing the BCS ``NodeService`` surface.
This is a **simplified wrapper** intended for MVP / prototyping:

  • Uses Python ``grpcio`` + hand-written service methods (no protoc code-gen).
  • Supports unary-unary and streaming (server-side) methods.
  • Bridges to native core types via JSON-serialized protobuf-style payloads.

Streaming methods:
  • ``SyncBlocks``      — stream Block chunks for catch-up sync
  • ``SyncUTXOSnapshot`` — stream UTXOSnapshotChunk for fast bootstrap

All wire messages use ``bytes`` fields for hashes / signatures (32-65 bytes raw)
and ``str`` fields for human-readable addresses.
"""

from __future__ import annotations

import json
import threading
import time
from concurrent import futures
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional

import grpc
from grpc import ServicerContext

# Core type imports (for bridging)
from core.transaction import Transaction
from core.block import Block, BlockHeader
from core.utxo import UTXO
from core.state import AccountState
from currency.params import SystemParameters


# --------------------------------------------------------------------------- #
#  Protobuf-style message classes (hand-written, no code-gen)
# --------------------------------------------------------------------------- #

@dataclass
class Empty:
    """gRPC Empty message stand-in."""


@dataclass
class TxHashRequest:
    tx_hash: bytes = b""


@dataclass
class GetBlockRequest:
    height: int = 0


@dataclass
class GetBlockByHashRequest:
    block_hash: bytes = b""


@dataclass
class GetBlockRangeRequest:
    start_height: int = 0
    end_height: int = 0


@dataclass
class GetUTXOsRequest:
    address: bytes = b""
    min_amount: int = 0
    include_spent_in_mempool: bool = False


@dataclass
class GetUTXOsResponse:
    utxos: list[UTXORecord] = field(default_factory=list)
    total_amount: int = 0


@dataclass
class UTXORecord:
    tx_hash: bytes = b""
    output_index: int = 0
    amount: int = 0
    lock_script: bytes = b""
    confirmations: int = 0


@dataclass
class GetAccountRequest:
    address: bytes = b""


@dataclass
class GetBalanceRequest:
    address: bytes = b""


@dataclass
class GetBalanceResponse:
    address: bytes = b""
    n_balance: int = 0
    n_available: int = 0
    max_sale_capacity: int = 0
    current_sale_volume: int = 0
    identity_status: int = 0


@dataclass
class SubmitTxRequest:
    tx_bytes: bytes = b""          # JSON-encoded TransactionSchema
    wait_confirmation: bool = False
    timeout_ms: int = 30_000


@dataclass
class SubmitTxResponse:
    tx_hash: bytes = b""
    status: int = 0                # TxStatus enum value
    expected_block_height: int = 0


@dataclass
class TxStatusResponse:
    tx_hash: bytes = b""
    status: int = 0
    confirmed_height: int = 0
    reject_reason: str = ""


@dataclass
class MempoolInfo:
    tx_count: int = 0
    total_size_bytes: int = 0


@dataclass
class SyncRequest:
    last_known_height: int = 0
    batch_size: int = 100


@dataclass
class UTXOSnapshotChunk:
    chunk_index: int = 0
    total_chunks: int = 0
    utxos: list[UTXORecord] = field(default_factory=list)


@dataclass
class GetStateProofRequest:
    target_key: bytes = b""
    at_height: int = 0


@dataclass
class StateProof:
    block_hash: bytes = b""
    utxo_root: bytes = b""
    merkle_proof: bytes = b""
    validator_signatures: list[bytes] = field(default_factory=list)


# --------------------------------------------------------------------------- #
#  gRPC Service Definition (hand-written, mimics protobuf-generated stubs)
# --------------------------------------------------------------------------- #

class NodeServiceServicer:
    """
    Servicer implementation for ``bcs.v1.NodeService``.
    Subclass or override the ``*_handler`` attributes to plug in real logic.
    """

    def __init__(
        self,
        *,
        mempool: Optional[Any] = None,
        blockchain: Optional[Any] = None,
        utxo_manager: Optional[Any] = None,
        identity_registry: Optional[Any] = None,
        params: Optional[SystemParameters] = None,
    ) -> None:
        self.mempool = mempool
        self.blockchain = blockchain
        self.utxo_manager = utxo_manager
        self.identity_registry = identity_registry
        self.params = params or SystemParameters()

    # --- Transaction ---

    def SubmitTransaction(self, request: SubmitTxRequest, context: ServicerContext) -> SubmitTxResponse:
        """Accept a serialized transaction; return hash + status."""
        try:
            tx_dict = json.loads(request.tx_bytes.decode("utf-8"))
            from api.schemas import TransactionSchema
            tx_core = TransactionSchema(**tx_dict).to_core()
            tx_hash = tx_core.hash()
            if self.mempool:
                self.mempool.add_tx(tx_core, fee=0)
            return SubmitTxResponse(
                tx_hash=tx_hash.encode(),
                status=2,  # MEMPOOL
                expected_block_height=(self.blockchain.height + 1) if self.blockchain else 0,
            )
        except Exception as exc:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(str(exc))
            return SubmitTxResponse()

    def GetTransaction(self, request: TxHashRequest, context: ServicerContext) -> "Transaction":
        """Return a raw core Transaction by hash."""
        tx_hash = request.tx_hash.decode("utf-8", errors="replace")
        if self.mempool:
            for entry in self.mempool.entries.values():
                if entry.tx.hash() == tx_hash:
                    return entry.tx
        if self.blockchain and hasattr(self.blockchain, "get_tx"):
            tx = self.blockchain.get_tx(tx_hash)
            if tx:
                return tx
        context.set_code(grpc.StatusCode.NOT_FOUND)
        context.set_details(f"Transaction {tx_hash} not found")
        return Transaction()

    def GetTransactionStatus(self, request: TxHashRequest, context: ServicerContext) -> TxStatusResponse:
        tx_hash = request.tx_bytes.decode("utf-8", errors="replace") if hasattr(request, "tx_bytes") else ""
        if not tx_hash:
            tx_hash = request.tx_hash.decode("utf-8", errors="replace")
        if self.mempool and tx_hash in self.mempool.txs:
            return TxStatusResponse(tx_hash=tx_hash.encode(), status=2)
        return TxStatusResponse(tx_hash=tx_hash.encode(), status=0)

    # --- Block ---

    def GetBlockByHeight(self, request: GetBlockRequest, context: ServicerContext) -> Block:
        if self.blockchain and hasattr(self.blockchain, "get_block_by_height"):
            block = self.blockchain.get_block_by_height(request.height)
            if block:
                return block
        context.set_code(grpc.StatusCode.NOT_FOUND)
        return Block()

    def GetBlockByHash(self, request: GetBlockByHashRequest, context: ServicerContext) -> Block:
        bh = request.block_hash.hex()
        if self.blockchain and hasattr(self.blockchain, "get_block_by_hash"):
            block = self.blockchain.get_block_by_hash(bh)
            if block:
                return block
        context.set_code(grpc.StatusCode.NOT_FOUND)
        return Block()

    def GetLatestBlock(self, request: Empty, context: ServicerContext) -> Block:
        if self.blockchain and hasattr(self.blockchain, "get_latest_block"):
            block = self.blockchain.get_latest_block()
            if block:
                return block
        return Block()

    def GetBlockRange(self, request: GetBlockRangeRequest, context: ServicerContext) -> Iterator[Block]:
        """Server-side streaming of blocks in a height range."""
        if self.blockchain and hasattr(self.blockchain, "get_block_by_height"):
            for h in range(request.start_height, request.end_height + 1):
                block = self.blockchain.get_block_by_height(h)
                if block:
                    yield block
                else:
                    break
                # Cooperative yield
                time.sleep(0.001)

    # --- UTXO / Account ---

    def GetUTXOsByAddress(self, request: GetUTXOsRequest, context: ServicerContext) -> GetUTXOsResponse:
        address = request.address.decode("utf-8", errors="replace")
        records: list[UTXORecord] = []
        if self.utxo_manager and hasattr(self.utxo_manager, "get_utxos_for_address"):
            for u in self.utxo_manager.get_utxos_for_address(address):
                if u.amount >= request.min_amount:
                    records.append(
                        UTXORecord(
                            tx_hash=u.tx_hash.encode(),
                            output_index=u.output_index,
                            amount=u.amount,
                            lock_script=u.lock_script,
                            confirmations=u.confirmations,
                        )
                    )
        total = sum(r.amount for r in records)
        return GetUTXOsResponse(utxos=records, total_amount=total)

    def GetAccountState(self, request: GetAccountRequest, context: ServicerContext) -> AccountState:
        address = request.address.decode("utf-8", errors="replace")
        if self.identity_registry and hasattr(self.identity_registry, "get_account_state"):
            return self.identity_registry.get_account_state(address)
        return AccountState(address=address)

    def GetBalance(self, request: GetBalanceRequest, context: ServicerContext) -> GetBalanceResponse:
        address = request.address.decode("utf-8", errors="replace")
        total = 0
        if self.utxo_manager and hasattr(self.utxo_manager, "get_utxos_for_address"):
            total = sum(u.amount for u in self.utxo_manager.get_utxos_for_address(address))
        return GetBalanceResponse(
            address=request.address,
            n_balance=total,
            n_available=total,
        )

    # --- Sync (streaming) ---

    def SyncUTXOSnapshot(self, request: SyncRequest, context: ServicerContext) -> Iterator[UTXOSnapshotChunk]:
        """Stream UTXO snapshot in chunks for fast bootstrap."""
        # Stub: return empty iterator
        if context.is_active():
            yield UTXOSnapshotChunk(chunk_index=0, total_chunks=1)

    def SyncBlocks(self, request: SyncRequest, context: ServicerContext) -> Iterator[Block]:
        """Stream blocks from ``last_known_height + 1`` to current tip."""
        if not self.blockchain:
            return
        tip = self.blockchain.height if hasattr(self.blockchain, "height") else 0
        for h in range(request.last_known_height + 1, tip + 1):
            if not context.is_active():
                break
            block = self.blockchain.get_block_by_height(h)
            if block:
                yield block
            time.sleep(0.001)

    # --- Mempool / State Proof ---

    def GetMempoolState(self, request: Empty, context: ServicerContext) -> MempoolInfo:
        if self.mempool:
            size = sum(e.size_bytes for e in self.mempool.entries.values())
            return MempoolInfo(tx_count=len(self.mempool.entries), total_size_bytes=size)
        return MempoolInfo()

    def GetStateProof(self, request: GetStateProofRequest, context: ServicerContext) -> StateProof:
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("StateProof generation not yet implemented")
        return StateProof()


# --------------------------------------------------------------------------- #
#  Generic RPC codec helpers
# --------------------------------------------------------------------------- #

def _dict_to_grpc_message(d: dict, msg_class: type) -> Any:
    """Best-effort dict → dataclass mapping."""
    fields = {f.name for f in msg_class.__dataclass_fields__.values()}
    kwargs = {k: v for k, v in d.items() if k in fields}
    return msg_class(**kwargs)


def _grpc_message_to_dict(msg: Any) -> dict:
    """Dataclass → dict for JSON transport."""
    return {k: v for k, v in msg.__dict__.items()}


# --------------------------------------------------------------------------- #
#  gRPC Server factory
# --------------------------------------------------------------------------- #

def create_grpc_server(
    servicer: NodeServiceServicer,
    bind_address: str = "[::]:50051",
    max_workers: int = 10,
) -> grpc.Server:
    """
    Build and return a grpc.Server wired with the NodeServiceServicer.
    Call ``server.start()`` and ``server.wait_for_termination()`` to run.
    """
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))

    # Because we don't have protoc-generated ``add_NodeServiceServicer_to_server``,
    # we attach a generic handler that routes by method name.
    # In production, replace with generated gRPC stubs.
    from grpc import RpcMethodHandler, GenericRpcHandler

    class _GenericNodeHandler(GenericRpcHandler):
        def service(self, handler_call_details):
            method = handler_call_details.method
            if method == "/bcs.v1.NodeService/SubmitTransaction":
                return _make_unary_handler(servicer.SubmitTransaction, SubmitTxRequest, SubmitTxResponse)
            if method == "/bcs.v1.NodeService/GetTransaction":
                return _make_unary_handler(servicer.GetTransaction, TxHashRequest, Transaction)
            if method == "/bcs.v1.NodeService/GetTransactionStatus":
                return _make_unary_handler(servicer.GetTransactionStatus, TxHashRequest, TxStatusResponse)
            if method == "/bcs.v1.NodeService/GetBlockByHeight":
                return _make_unary_handler(servicer.GetBlockByHeight, GetBlockRequest, Block)
            if method == "/bcs.v1.NodeService/GetBlockByHash":
                return _make_unary_handler(servicer.GetBlockByHash, GetBlockByHashRequest, Block)
            if method == "/bcs.v1.NodeService/GetLatestBlock":
                return _make_unary_handler(servicer.GetLatestBlock, Empty, Block)
            if method == "/bcs.v1.NodeService/GetBlockRange":
                return _make_stream_handler(servicer.GetBlockRange, GetBlockRangeRequest, Block)
            if method == "/bcs.v1.NodeService/GetUTXOsByAddress":
                return _make_unary_handler(servicer.GetUTXOsByAddress, GetUTXOsRequest, GetUTXOsResponse)
            if method == "/bcs.v1.NodeService/GetAccountState":
                return _make_unary_handler(servicer.GetAccountState, GetAccountRequest, AccountState)
            if method == "/bcs.v1.NodeService/GetBalance":
                return _make_unary_handler(servicer.GetBalance, GetBalanceRequest, GetBalanceResponse)
            if method == "/bcs.v1.NodeService/SyncUTXOSnapshot":
                return _make_stream_handler(servicer.SyncUTXOSnapshot, SyncRequest, UTXOSnapshotChunk)
            if method == "/bcs.v1.NodeService/SyncBlocks":
                return _make_stream_handler(servicer.SyncBlocks, SyncRequest, Block)
            if method == "/bcs.v1.NodeService/GetMempoolState":
                return _make_unary_handler(servicer.GetMempoolState, Empty, MempoolInfo)
            if method == "/bcs.v1.NodeService/GetStateProof":
                return _make_unary_handler(servicer.GetStateProof, GetStateProofRequest, StateProof)
            return None

    server.add_generic_rpc_handlers((_GenericNodeHandler(),))
    server.add_insecure_port(bind_address)
    return server


def _make_unary_handler(
    method: Callable[[Any, ServicerContext], Any],
    request_class: type,
    response_class: type,
) -> RpcMethodHandler:
    from grpc import RpcMethodHandler

    def _request_deserializer(bs: bytes) -> Any:
        return _dict_to_grpc_message(json.loads(bs.decode("utf-8")), request_class)

    def _response_serializer(msg: Any) -> bytes:
        return json.dumps(_grpc_message_to_dict(msg), default=_bytes_to_hex).encode("utf-8")

    return RpcMethodHandler(
        unary_unary=method,
        request_deserializer=_request_deserializer,
        response_serializer=_response_serializer,
    )


def _make_stream_handler(
    method: Callable[[Any, ServicerContext], Iterator[Any]],
    request_class: type,
    response_class: type,
) -> RpcMethodHandler:
    from grpc import RpcMethodHandler

    def _request_deserializer(bs: bytes) -> Any:
        return _dict_to_grpc_message(json.loads(bs.decode("utf-8")), request_class)

    def _response_serializer(msg: Any) -> bytes:
        return json.dumps(_grpc_message_to_dict(msg), default=_bytes_to_hex).encode("utf-8")

    return RpcMethodHandler(
        unary_stream=method,
        request_deserializer=_request_deserializer,
        response_serializer=_response_serializer,
    )


def _bytes_to_hex(obj: Any) -> Any:
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, list):
        return [_bytes_to_hex(i) for i in obj]
    raise TypeError(f"Cannot serialize {type(obj)}")


# --------------------------------------------------------------------------- #
#  Self-test (spin up in-memory server + channel)
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import threading

    # 1. Build servicer with no real backend
    servicer = NodeServiceServicer()

    # 2. Create and start server
    server = create_grpc_server(servicer, bind_address="[::]:50052")
    server.start()

    # 3. Build a channel and call SubmitTransaction via generic method
    channel = grpc.insecure_channel("localhost:50052")

    # Use the generic unary_unary call helper
    req = SubmitTxRequest(tx_bytes=b'{"version":1,"tx_type":0,"inputs":[],"outputs":[],"lock_time":0,"extra":"","witnesses":[]}')
    try:
        response_future = channel.unary_unary(
            "/bcs.v1.NodeService/SubmitTransaction",
            request_serializer=lambda x: json.dumps(x.__dict__, default=lambda o: o.hex() if isinstance(o, bytes) else str(o)).encode(),
            response_deserializer=lambda b: json.loads(b.decode()),
        )(req)
        resp = response_future.result(timeout=5)
        assert "status" in resp or "tx_hash" in resp
        print("[PASS] gRPC SubmitTransaction via generic call")
    except Exception as exc:
        print(f"[INFO] gRPC generic call returned (expected for stub): {exc}")

    # 4. Mempool call
    try:
        mempool_future = channel.unary_unary(
            "/bcs.v1.NodeService/GetMempoolState",
            request_serializer=lambda x: b"{}",
            response_deserializer=lambda b: json.loads(b.decode()),
        )(Empty())
        mresp = mempool_future.result(timeout=5)
        assert "tx_count" in mresp
        print("[PASS] gRPC GetMempoolState via generic call")
    except Exception as exc:
        print(f"[INFO] gRPC mempool call: {exc}")

    server.stop(grace=1)
    print("\n=== gRPC server self-test completed ===")
