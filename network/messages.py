"""
BCS Network — Message Definitions
==================================
Structured network messages for the BCS P2P protocol.

Design choices:
  • ``MessageType`` enum maps directly to the protobuf definition in §2.6.
  • ``Message`` dataclass wraps type + payload + sender metadata + signature.
  • ``MessageSerializer`` converts to/from compact bytes using msgpack
    (fallback to JSON for maximum portability).

All wire payloads are ``bytes`` so the serializer is agnostic to the
inner encoding (can be protobuf, capnp, or JSON).
"""

from __future__ import annotations

import hashlib
import json
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional

try:
    import msgpack
    _HAS_MSGPACK = True
except Exception:  # pragma: no cover
    _HAS_MSGPACK = False


# --------------------------------------------------------------------------- #
#  MessageType enum
# --------------------------------------------------------------------------- #

class MessageType(IntEnum):
    """
    BCS P2P protocol message type codes.
    Segmented by functional area to aid readability.
    """

    # Transaction messages (0x00–0x0F)
    TX_NEW = 0
    TX_BATCH_SYNC = 1
    TX_REQUEST = 2

    # Block messages (0x10–0x1F)
    BLOCK_NEW = 10
    BLOCK_REQUEST = 11
    BLOCK_BATCH = 12

    # State / sync messages (0x20–0x2F)
    UTXO_SNAPSHOT_REQUEST = 20
    UTXO_SNAPSHOT_RESPONSE = 21
    STATE_DELTA = 22

    # Governance messages (0x30–0x3F)
    GOV_PROPOSAL = 30
    GOV_VOTE = 31
    GOV_CERT = 32

    # Control / handshake (0xF0–0xFF)
    PING = 240
    PONG = 241
    HANDSHAKE = 242
    DISCONNECT = 243


# --------------------------------------------------------------------------- #
#  Message dataclass
# --------------------------------------------------------------------------- #

@dataclass
class Message:
    """
    A wire-level P2P message.

    Fields:
        type:         Semantic message type.
        payload:      Opaque payload bytes (encoding defined per type).
        from_addr:    Human-readable sender address (for logging / routing).
        timestamp:    Unix ms when the message was created.
        signature:    Optional ECDSA signature over ``type || timestamp || payload``.
        msg_id:       Deterministic message id (SHA3-256) used for deduplication.
    """
    type: MessageType
    payload: bytes = field(default_factory=bytes)
    from_addr: str = ""
    timestamp: int = field(default_factory=lambda: int(time.time() * 1000))
    signature: bytes = field(default_factory=bytes)
    msg_id: str = field(default="")

    def __post_init__(self) -> None:
        if isinstance(self.type, int):
            object.__setattr__(self, "type", MessageType(self.type))
        if not self.msg_id:
            object.__setattr__(self, "msg_id", self._compute_id())

    def _compute_id(self) -> str:
        """Deterministic message identifier for deduplication."""
        raw = struct.pack("<BQ", int(self.type), self.timestamp) + self.payload
        return hashlib.sha3_256(raw).hexdigest()

    def signing_bytes(self) -> bytes:
        """Bytes that the signature should cover."""
        return struct.pack("<BQ", int(self.type), self.timestamp) + self.payload

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": int(self.type),
            "payload": self.payload.hex(),
            "from_addr": self.from_addr,
            "timestamp": self.timestamp,
            "signature": self.signature.hex(),
            "msg_id": self.msg_id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Message":
        return cls(
            type=MessageType(d["type"]),
            payload=bytes.fromhex(d["payload"]),
            from_addr=d.get("from_addr", ""),
            timestamp=d.get("timestamp", 0),
            signature=bytes.fromhex(d.get("signature", "")),
            msg_id=d.get("msg_id", ""),
        )


# --------------------------------------------------------------------------- #
#  MessageSerializer
# --------------------------------------------------------------------------- #

class MessageSerializer:
    """
    Bidirectional serializer for ``Message`` <-> ``bytes``.

    Wire format (msgpack enabled)::

        [4 bytes: magic "BCSM"]
        [1 byte:  version]
        [N bytes: msgpack(Message)]

    Wire format (msgpack disabled, JSON fallback)::

        [4 bytes: magic "BCSJ"]
        [1 byte:  version]
        [N bytes: utf-8 JSON]

    The magic header allows quick protocol identification and framing.
    """

    MAGIC_MSGPACK = b"BCSM"
    MAGIC_JSON = b"BCSJ"
    VERSION = 1

    @classmethod
    def to_bytes(cls, msg: Message) -> bytes:
        if _HAS_MSGPACK:
            return cls._to_msgpack(msg)
        return cls._to_json(msg)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Message":
        if len(data) < 5:
            raise ValueError("Data too short for BCS message framing")
        magic = data[:4]
        version = data[4]
        if version != cls.VERSION:
            raise ValueError(f"Unsupported wire version {version}")
        payload = data[5:]
        if magic == cls.MAGIC_MSGPACK:
            return cls._from_msgpack(payload)
        if magic == cls.MAGIC_JSON:
            return cls._from_json(payload)
        raise ValueError(f"Unknown magic bytes: {magic!r}")

    # --- msgpack path ---

    @classmethod
    def _to_msgpack(cls, msg: Message) -> bytes:
        assert _HAS_MSGPACK
        packed = msgpack.packb(
            {
                "t": int(msg.type),
                "p": msg.payload,
                "f": msg.from_addr,
                "ts": msg.timestamp,
                "s": msg.signature,
                "id": msg.msg_id,
            },
            use_bin_type=True,
        )
        return cls.MAGIC_MSGPACK + bytes([cls.VERSION]) + packed

    @classmethod
    def _from_msgpack(cls, payload: bytes) -> "Message":
        assert _HAS_MSGPACK
        d = msgpack.unpackb(payload, raw=False)
        return Message(
            type=MessageType(d["t"]),
            payload=d.get("p", b""),
            from_addr=d.get("f", ""),
            timestamp=d.get("ts", 0),
            signature=d.get("s", b""),
            msg_id=d.get("id", ""),
        )

    # --- JSON path ---

    @classmethod
    def _to_json(cls, msg: Message) -> bytes:
        j = json.dumps(
            {
                "type": int(msg.type),
                "payload": msg.payload.hex(),
                "from_addr": msg.from_addr,
                "timestamp": msg.timestamp,
                "signature": msg.signature.hex(),
                "msg_id": msg.msg_id,
            },
            ensure_ascii=False,
        )
        return cls.MAGIC_JSON + bytes([cls.VERSION]) + j.encode("utf-8")

    @classmethod
    def _from_json(cls, payload: bytes) -> "Message":
        d = json.loads(payload.decode("utf-8"))
        return Message.from_dict(d)


# --------------------------------------------------------------------------- #
#  Convenience helpers for common message types
# --------------------------------------------------------------------------- #

def make_tx_new(tx_bytes: bytes, from_addr: str = "", signature: bytes = b"") -> Message:
    """Helper to build a ``TX_NEW`` message."""
    return Message(
        type=MessageType.TX_NEW,
        payload=tx_bytes,
        from_addr=from_addr,
        signature=signature,
    )


def make_block_new(block_bytes: bytes, from_addr: str = "", signature: bytes = b"") -> Message:
    """Helper to build a ``BLOCK_NEW`` message."""
    return Message(
        type=MessageType.BLOCK_NEW,
        payload=block_bytes,
        from_addr=from_addr,
        signature=signature,
    )


def make_utxo_snapshot_request(from_addr: str = "") -> Message:
    """Helper to build a ``UTXO_SNAPSHOT_REQUEST``."""
    return Message(type=MessageType.UTXO_SNAPSHOT_REQUEST, from_addr=from_addr)


def make_handshake(node_id: str, listen_addr: str, network_id: str = "bcs-mainnet") -> Message:
    """Build a handshake message for peer identification."""
    payload = json.dumps({
        "node_id": node_id,
        "listen_addr": listen_addr,
        "network_id": network_id,
        "protocol_version": 1,
    }).encode("utf-8")
    return Message(type=MessageType.HANDSHAKE, payload=payload, from_addr=listen_addr)


# --------------------------------------------------------------------------- #
#  Self-test
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import sys

    # 1. Message ID determinism
    m1 = make_tx_new(b"hello", from_addr="node-A")
    m2 = make_tx_new(b"hello", from_addr="node-A")
    assert m1.msg_id == m2.msg_id, "Message ID must be deterministic"
    print("[PASS] Message ID determinism")

    # 2. Round-trip serialization
    ser = MessageSerializer.to_bytes(m1)
    m_back = MessageSerializer.from_bytes(ser)
    assert m_back.type == MessageType.TX_NEW
    assert m_back.payload == b"hello"
    assert m_back.msg_id == m1.msg_id
    print("[PASS] Message round-trip")

    # 3. Signing bytes coverage
    sb = m1.signing_bytes()
    assert len(sb) > len(m1.payload)
    print("[PASS] Signing bytes include type + timestamp + payload")

    # 4. Dict round-trip
    d = m1.to_dict()
    m3 = Message.from_dict(d)
    assert m3.type == m1.type
    assert m3.payload == m1.payload
    print("[PASS] Dict round-trip")

    # 5. Handshake construction
    hs = make_handshake("node-1", "127.0.0.1:10001")
    assert hs.type == MessageType.HANDSHAKE
    hs_back = MessageSerializer.from_bytes(MessageSerializer.to_bytes(hs))
    info = json.loads(hs_back.payload)
    assert info["node_id"] == "node-1"
    print("[PASS] Handshake message")

    # 6. Block NEW message
    bm = make_block_new(b"\x00" * 256)
    bm_back = MessageSerializer.from_bytes(MessageSerializer.to_bytes(bm))
    assert bm_back.payload == b"\x00" * 256
    print("[PASS] Block NEW message")

    print(f"\n=== All message self-tests passed (msgpack={'enabled' if _HAS_MSGPACK else 'disabled'}) ===")
