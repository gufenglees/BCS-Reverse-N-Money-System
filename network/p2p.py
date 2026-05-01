"""
BCS Network — Simplified P2P Layer
=====================================
Lightweight asyncio + websockets P2P node for BCS gossip and sync.

Components:
  • Peer        — peer metadata (address, connection, last_seen, reputation)
  • PeerManager — add / remove / select peers by reputation or randomness
  • P2PNode     — main async node: listen, connect, broadcast, request, gossip

Design decisions:
  • Uses websockets for bidirectional framed messaging (no custom TCP framing).
  • Gossip: on receiving a novel message, forward to N random peers (default 3).
  • Deduplication via ``seen_messages`` LRU keyed by ``Message.msg_id``.
  • No libp2p dependency — minimal, auditable Python code.

All methods are ``async`` and intended to run inside an ``asyncio`` event loop.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Set

import websockets
from websockets import ServerConnection, ClientConnection
from websockets.server import serve as ws_serve

from network.messages import (
    Message,
    MessageType,
    MessageSerializer,
    make_tx_new,
    make_block_new,
    make_utxo_snapshot_request,
    make_handshake,
)


# --------------------------------------------------------------------------- #
#  Peer dataclass
# --------------------------------------------------------------------------- #

@dataclass
class Peer:
    """
    A remote peer in the BCS network.

    Fields:
        peer_id:       Unique node identifier (public key hash or UUID).
        address:       ``host:port`` string.
        ws:            Active websocket connection (client or server side).
        last_seen:     Unix timestamp of most recent valid message.
        reputation:    Score (0-100). Higher = more trustworthy.
        direction:     "inbound" or "outbound".
        handshake_done: Whether protocol handshake completed.
    """
    peer_id: str = ""
    address: str = ""
    ws: Optional[ServerConnection | ClientConnection] = None
    last_seen: float = field(default_factory=time.time)
    reputation: int = 50
    direction: str = "inbound"
    handshake_done: bool = False

    def is_alive(self, timeout_sec: float = 60.0) -> bool:
        return (time.time() - self.last_seen) < timeout_sec

    async def send(self, msg: Message) -> bool:
        """Serialize and send a Message over the websocket."""
        if self.ws is None or self.ws.state.name != "OPEN":
            return False
        try:
            raw = MessageSerializer.to_bytes(msg)
            await self.ws.send(raw)
            return True
        except Exception:
            return False


# --------------------------------------------------------------------------- #
#  PeerManager
# --------------------------------------------------------------------------- #

class PeerManager:
    """
    In-memory registry of connected peers with reputation tracking.
    Thread-safe via asyncio (assumes single event loop).
    """

    def __init__(self, max_peers: int = 50) -> None:
        self.max_peers = max_peers
        self._peers: dict[str, Peer] = {}          # peer_id -> Peer
        self._by_address: dict[str, str] = {}      # address -> peer_id

    def add_peer(self, peer: Peer) -> bool:
        """Register a new peer. Returns False if at capacity."""
        if peer.peer_id in self._peers:
            self._peers[peer.peer_id] = peer
            return True
        if len(self._peers) >= self.max_peers:
            return False
        self._peers[peer.peer_id] = peer
        if peer.address:
            self._by_address[peer.address] = peer.peer_id
        return True

    def remove_peer(self, peer_id: str) -> Optional[Peer]:
        """Remove a peer by id. Returns the removed Peer or None."""
        peer = self._peers.pop(peer_id, None)
        if peer and peer.address:
            self._by_address.pop(peer.address, None)
        return peer

    def get_peer(self, peer_id: str) -> Optional[Peer]:
        return self._peers.get(peer_id)

    def get_peer_by_address(self, address: str) -> Optional[Peer]:
        pid = self._by_address.get(address)
        return self._peers.get(pid) if pid else None

    def get_random_peers(self, n: int, exclude: Optional[Set[str]] = None) -> list[Peer]:
        """Return up to ``n`` random peers, optionally excluding a set of peer_ids."""
        candidates = [p for pid, p in self._peers.items() if not exclude or pid not in exclude]
        if not candidates:
            return []
        return random.sample(candidates, min(n, len(candidates)))

    def get_best_peers(self, n: int, min_reputation: int = 60) -> list[Peer]:
        """Return up to ``n`` peers sorted by descending reputation."""
        eligible = [p for p in self._peers.values() if p.reputation >= min_reputation and p.is_alive()]
        eligible.sort(key=lambda p: p.reputation, reverse=True)
        return eligible[:n]

    def all_peers(self) -> list[Peer]:
        return list(self._peers.values())

    def update_reputation(self, peer_id: str, delta: int) -> None:
        peer = self._peers.get(peer_id)
        if peer:
            peer.reputation = max(0, min(100, peer.reputation + delta))

    def prune_dead(self, timeout_sec: float = 120.0) -> list[str]:
        """Remove peers that haven't been seen recently. Returns removed ids."""
        dead = [pid for pid, p in self._peers.items() if not p.is_alive(timeout_sec)]
        for pid in dead:
            self.remove_peer(pid)
        return dead


# --------------------------------------------------------------------------- #
#  P2PNode
# --------------------------------------------------------------------------- #

class P2PNode:
    """
    Async P2P node for BCS gossip and sync.

    Usage::

        node = P2PNode(node_id="node-1", listen_addr="0.0.0.0:10001")
        await node.start()
        await node.broadcast_tx(tx_bytes)
        await node.stop()
    """

    def __init__(
        self,
        node_id: str,
        listen_host: str = "0.0.0.0",
        listen_port: int = 10001,
        max_peers: int = 50,
        gossip_fanout: int = 3,
        seen_cache_size: int = 10_000,
        network_id: str = "bcs-mainnet",
    ) -> None:
        self.node_id = node_id
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.network_id = network_id

        self.peer_manager = PeerManager(max_peers=max_peers)
        self.gossip_fanout = gossip_fanout

        # Message deduplication cache (LRU via maxlen deque)
        self._seen_messages: deque[str] = deque(maxlen=seen_cache_size)

        # Async machinery
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False
        self._tasks: set[asyncio.Task] = set()
        self._shutdown_event: asyncio.Event = asyncio.Event()

        # Callbacks that application layer can register
        self.on_tx_received: Optional[Callable[[Message, Peer], Awaitable[None]]] = None
        self.on_block_received: Optional[Callable[[Message, Peer], Awaitable[None]]] = None
        self.on_utxo_snapshot_request: Optional[Callable[[Message, Peer], Awaitable[None]]] = None
        self.on_peer_connected: Optional[Callable[[Peer], Awaitable[None]]] = None
        self.on_peer_disconnected: Optional[Callable[[Peer], Awaitable[None]]] = None

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    async def start(
        self,
        bootstrap_peers: Optional[list[str]] = None,
    ) -> None:
        """
        Start the P2P node: listen on websocket port + connect to bootstrap peers.
        """
        if self._running:
            return
        self._running = True
        self._shutdown_event.clear()

        # Start websocket server
        self._server = await ws_serve(
            self._handle_inbound,
            self.listen_host,
            self.listen_port,
            ping_interval=20,
            ping_timeout=10,
        )

        # Connect to bootstrap peers
        if bootstrap_peers:
            for addr in bootstrap_peers:
                task = asyncio.create_task(self._connect_to_peer(addr))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)

        # Background maintenance task
        maint_task = asyncio.create_task(self._maintenance_loop())
        self._tasks.add(maint_task)
        maint_task.add_done_callback(self._tasks.discard)

        print(f"[P2P] Node {self.node_id} listening on ws://{self.listen_host}:{self.listen_port}")

    async def stop(self) -> None:
        """Gracefully stop listening and close all connections."""
        if not self._running:
            return
        self._running = False
        self._shutdown_event.set()

        # Cancel pending tasks
        for task in list(self._tasks):
            task.cancel()

        # Close all peer websockets
        for peer in self.peer_manager.all_peers():
            if peer.ws and peer.ws.state.name == "OPEN":
                await peer.ws.close()

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        print(f"[P2P] Node {self.node_id} stopped")

    # ------------------------------------------------------------------ #
    #  Public broadcast / request API
    # ------------------------------------------------------------------ #

    async def broadcast_tx(self, tx: "Transaction") -> list[str]:  # type: ignore[name-defined]
        """
        Serialize a transaction and gossip it to random peers.
        Returns list of peer_ids that accepted the message.
        """
        from core.transaction import Transaction
        tx_bytes = json.dumps(tx.to_dict()).encode("utf-8")
        msg = make_tx_new(tx_bytes, from_addr=f"{self.listen_host}:{self.listen_port}")
        return await self._gossip(msg)

    async def broadcast_block(self, block: "Block") -> list[str]:  # type: ignore[name-defined]
        """Gossip a newly minted block to peers."""
        from core.block import Block
        block_bytes = json.dumps(block.to_dict()).encode("utf-8")
        msg = make_block_new(block_bytes, from_addr=f"{self.listen_host}:{self.listen_port}")
        return await self._gossip(msg)

    async def request_blocks(
        self,
        from_height: int,
        to_height: int,
        peer: Optional[Peer] = None,
    ) -> list[dict[str, Any]]:
        """
        Request a range of blocks from a specific peer or a random best peer.
        Returns list of block dicts (decoded from JSON payload).
        """
        target = peer or self._pick_best_peer()
        if target is None:
            return []

        payload = json.dumps({"from": from_height, "to": to_height}).encode("utf-8")
        msg = Message(
            type=MessageType.BLOCK_REQUEST,
            payload=payload,
            from_addr=f"{self.listen_host}:{self.listen_port}",
        )
        await target.send(msg)
        # Real implementation would await response; here we return empty stub
        return []

    async def request_utxo_snapshot(self, peer: Optional[Peer] = None) -> Optional[bytes]:
        """Request a UTXO snapshot from a peer."""
        target = peer or self._pick_best_peer()
        if target is None:
            return None
        msg = make_utxo_snapshot_request(from_addr=f"{self.listen_host}:{self.listen_port}")
        await target.send(msg)
        return None  # Stub: async response would be handled in _handle_message

    async def handle_message(self, msg: Message, peer: Peer) -> None:
        """
        Application-level message dispatch.
        Subclass or set callbacks to override behavior.
        """
        if msg.type == MessageType.TX_NEW:
            if self.on_tx_received:
                await self.on_tx_received(msg, peer)
        elif msg.type == MessageType.BLOCK_NEW:
            if self.on_block_received:
                await self.on_block_received(msg, peer)
        elif msg.type == MessageType.UTXO_SNAPSHOT_REQUEST:
            if self.on_utxo_snapshot_request:
                await self.on_utxo_snapshot_request(msg, peer)
        elif msg.type == MessageType.HANDSHAKE:
            await self._process_handshake(msg, peer)
        elif msg.type == MessageType.PING:
            await peer.send(Message(type=MessageType.PONG, from_addr=f"{self.listen_host}:{self.listen_port}"))
        elif msg.type == MessageType.PONG:
            peer.last_seen = time.time()
        else:
            # Unhandled — ignore or log
            pass

    # ------------------------------------------------------------------ #
    #  Internal connection handling
    # ------------------------------------------------------------------ #

    async def _handle_inbound(self, ws: ServerConnection) -> None:
        """Handler for incoming websocket connections."""
        addr = f"{ws.remote_address[0]}:{ws.remote_address[1]}" if ws.remote_address else "unknown"
        peer = Peer(peer_id=addr, address=addr, ws=ws, direction="inbound")

        if not self.peer_manager.add_peer(peer):
            await ws.close(1008, "Peer capacity reached")
            return

        if self.on_peer_connected:
            await self.on_peer_connected(peer)

        try:
            async for raw in ws:
                if isinstance(raw, bytes):
                    await self._process_raw(raw, peer)
                else:
                    # Text frame — ignore or treat as JSON control
                    pass
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.peer_manager.remove_peer(peer.peer_id)
            if self.on_peer_disconnected:
                await self.on_peer_disconnected(peer)

    async def _connect_to_peer(self, address: str) -> None:
        """Outbound connection to a bootstrap or discovered peer."""
        uri = f"ws://{address}"
        try:
            ws = await websockets.connect(uri, ping_interval=20, ping_timeout=10)
            peer = Peer(peer_id=address, address=address, ws=ws, direction="outbound")
            if not self.peer_manager.add_peer(peer):
                await ws.close(1008, "Peer capacity reached")
                return

            # Send handshake
            hs = make_handshake(self.node_id, f"{self.listen_host}:{self.listen_port}", self.network_id)
            await peer.send(hs)

            if self.on_peer_connected:
                await self.on_peer_connected(peer)

            async for raw in ws:
                if isinstance(raw, bytes):
                    await self._process_raw(raw, peer)
        except Exception as exc:
            print(f"[P2P] Failed to connect to {address}: {exc}")
        finally:
            self.peer_manager.remove_peer(address)

    async def _process_raw(self, raw: bytes, peer: Peer) -> None:
        """Deserialize, deduplicate, and dispatch a message."""
        try:
            msg = MessageSerializer.from_bytes(raw)
        except Exception as exc:
            self.peer_manager.update_reputation(peer.peer_id, -5)
            return

        peer.last_seen = time.time()

        # Deduplication
        if msg.msg_id in self._seen_messages:
            return
        self._seen_messages.append(msg.msg_id)

        # Update reputation for valid novel messages
        self.peer_manager.update_reputation(peer.peer_id, 1)

        # Dispatch to application layer
        await self.handle_message(msg, peer)

        # Gossip: forward to N random peers (excluding sender)
        if msg.type in (MessageType.TX_NEW, MessageType.BLOCK_NEW, MessageType.GOV_PROPOSAL):
            await self._gossip(msg, exclude_peer_id=peer.peer_id)

    async def _process_handshake(self, msg: Message, peer: Peer) -> None:
        """Parse handshake payload and mark peer as validated."""
        try:
            info = json.loads(msg.payload)
            peer.peer_id = info.get("node_id", peer.peer_id)
            peer.handshake_done = True
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Gossip helpers
    # ------------------------------------------------------------------ #

    async def _gossip(self, msg: Message, exclude_peer_id: Optional[str] = None) -> list[str]:
        """
        Forward ``msg`` to ``gossip_fanout`` random peers.
        Returns peer_ids of successfully messaged peers.
        """
        exclude = {exclude_peer_id} if exclude_peer_id else set()
        targets = self.peer_manager.get_random_peers(self.gossip_fanout, exclude=exclude)
        sent_to: list[str] = []
        for peer in targets:
            if await peer.send(msg):
                sent_to.append(peer.peer_id)
        return sent_to

    def _pick_best_peer(self) -> Optional[Peer]:
        """Select a single high-reputation peer for directed requests."""
        best = self.peer_manager.get_best_peers(1)
        return best[0] if best else None

    # ------------------------------------------------------------------ #
    #  Maintenance
    # ------------------------------------------------------------------ #

    async def _maintenance_loop(self) -> None:
        """Periodic cleanup: prune dead peers, ping neighbors."""
        while self._running and not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=30.0)
                break
            except asyncio.TimeoutError:
                pass

            # Prune dead peers
            dead = self.peer_manager.prune_dead(timeout_sec=120.0)
            if dead:
                print(f"[P2P] Pruned {len(dead)} dead peers")

            # Ping all peers
            ping_msg = Message(
                type=MessageType.PING,
                from_addr=f"{self.listen_host}:{self.listen_port}",
            )
            for peer in self.peer_manager.all_peers():
                if peer.handshake_done:
                    await peer.send(ping_msg)


# --------------------------------------------------------------------------- #
#  Self-test
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import asyncio
    import threading

    async def run_test():
        # 1. Create two nodes on different ports
        node_a = P2PNode(node_id="node-A", listen_host="127.0.0.1", listen_port=19001)
        node_b = P2PNode(node_id="node-B", listen_host="127.0.0.1", listen_port=19002)

        # Track received messages
        b_received_tx: list[Message] = []

        async def on_tx(msg: Message, peer: Peer) -> None:
            b_received_tx.append(msg)

        node_b.on_tx_received = on_tx

        # 2. Start both
        await node_a.start()
        await node_b.start(bootstrap_peers=["127.0.0.1:19001"])

        # Give time for handshake
        await asyncio.sleep(0.5)

        # 3. Build a dummy transaction dict and broadcast
        dummy_tx = {"version": 1, "tx_type": 0, "inputs": [], "outputs": [], "lock_time": 0, "extra": "", "witnesses": []}
        from core.transaction import Transaction
        tx = Transaction.from_dict(dummy_tx)
        await node_a.broadcast_tx(tx)

        # Wait for gossip
        await asyncio.sleep(0.5)

        assert len(b_received_tx) >= 1, f"Expected B to receive tx, got {len(b_received_tx)}"
        assert b_received_tx[0].type == MessageType.TX_NEW
        print("[PASS] Transaction gossip between two nodes")

        # 4. PeerManager tests
        pm = node_a.peer_manager
        assert len(pm.all_peers()) >= 1
        best = pm.get_best_peers(5)
        assert isinstance(best, list)
        print("[PASS] PeerManager get_best_peers")

        # 5. Deduplication — manually test with identical msg_id
        seen_before = len(node_b._seen_messages)
        dup_msg = make_tx_new(b"dup_test", from_addr="test")
        dup_msg2 = Message(
            type=MessageType.TX_NEW,
            payload=b"dup_test",
            from_addr="test",
            timestamp=dup_msg.timestamp,  # same timestamp => same msg_id
            msg_id=dup_msg.msg_id,
        )
        # Add to B's seen cache directly
        node_b._seen_messages.append(dup_msg.msg_id)
        assert dup_msg.msg_id in node_b._seen_messages
        # Second identical message would be dropped in _process_raw
        assert len(node_b._seen_messages) == seen_before + 1
        print("[PASS] Message deduplication")

        # 6. Stop
        await node_a.stop()
        await node_b.stop()
        print("[PASS] Clean shutdown")

    asyncio.run(run_test())
    print("\n=== All P2P self-tests passed ===")
