"""
BCS Blockchain Core — Simplified Script Engine
===============================================
A minimal stack-based script interpreter supporting the opcodes
required by BCS, including P2PKH, multisig, governance, and DID
verification.

Supported Opcodes
-----------------
OP_DUP          0x76  – Duplicate top stack item
OP_HASH160      0xa9  – RIPEMD160(SHA256(x))
OP_EQUALVERIFY  0x88  – Equality check, fail if mismatch
OP_CHECKSIG     0xac  – ECDSA (secp256k1) signature verification
OP_CHECKMULTISIG 0xae – M-of-N multisig verification
OP_CHECKGOVSIG  0xb0  – BCS governance multi-sig verification
OP_CHECKDID     0xb1  – DID document binding verification (stub)

All amounts use int (nanoN units).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Optional

from ecdsa import SECP256k1, BadSignatureError
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der, sigencode_der


# ---------------------------------------------------------------------------
# Opcode definitions
# ---------------------------------------------------------------------------

class Opcode(IntEnum):
    OP_0 = 0x00
    OP_1 = 0x51
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_16 = 0x60

    OP_DUP = 0x76
    OP_HASH160 = 0xa9
    OP_EQUALVERIFY = 0x88
    OP_CHECKSIG = 0xac
    OP_CHECKMULTISIG = 0xae
    OP_CHECKGOVSIG = 0xb0
    OP_CHECKDID = 0xb1


# Push-data opcodes: 0x01–0x4b directly encode length
MAX_SINGLE_BYTE_PUSH = 0x4b
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d


# ---------------------------------------------------------------------------
# Script result
# ---------------------------------------------------------------------------

@dataclass
class ScriptResult:
    """Result of script execution."""
    success: bool
    stack: list[bytes]
    alt_stack: list[bytes]
    error_message: str = ""


# ---------------------------------------------------------------------------
# Script Engine
# ---------------------------------------------------------------------------

class ScriptEngine:
    """
    Simplified stack-machine script interpreter.

    Typical usage::

        engine = ScriptEngine()
        result = engine.execute(lock_script, unlock_script, tx_hash=b"...", context=ctx)
        if result.success:
            # UTXO is unlocked
    """

    def __init__(self) -> None:
        self.stack: list[bytes] = []
        self.alt_stack: list[bytes] = []
        self._handlers: dict[int, Callable[[], bool]] = {
            Opcode.OP_DUP: self._op_dup,
            Opcode.OP_HASH160: self._op_hash160,
            Opcode.OP_EQUALVERIFY: self._op_equalverify,
            Opcode.OP_CHECKSIG: self._op_checksig,
            Opcode.OP_CHECKMULTISIG: self._op_checkmultisig,
            Opcode.OP_CHECKGOVSIG: self._op_checkgovsig,
            Opcode.OP_CHECKDID: self._op_checkdid,
            Opcode.OP_0: lambda: self._op_push_n(0),
            Opcode.OP_1: lambda: self._op_push_n(1),
            Opcode.OP_2: lambda: self._op_push_n(2),
            Opcode.OP_3: lambda: self._op_push_n(3),
            Opcode.OP_4: lambda: self._op_push_n(4),
            Opcode.OP_5: lambda: self._op_push_n(5),
            Opcode.OP_16: lambda: self._op_push_n(16),
        }
        self._tx_hash: bytes = b""
        self._context: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(
        self,
        lock_script: bytes,
        unlock_script: bytes,
        tx_hash: bytes = b"",
        context: Optional[dict[str, Any]] = None,
    ) -> ScriptResult:
        """
        Execute the concatenated unlock_script + lock_script.

        Args:
            lock_script: The spending conditions (scriptPubKey).
            unlock_script: The proof of satisfaction (scriptSig).
            tx_hash: Transaction hash for signature checks.
            context: Additional execution context (validator pubkeys, DID docs, etc.).
        """
        self.stack = []
        self.alt_stack = []
        self._tx_hash = tx_hash
        self._context = context or {}

        full_script = unlock_script + lock_script
        try:
            self._run(full_script)
            success = len(self.stack) > 0 and self._cast_to_bool(self.stack[-1])
            return ScriptResult(
                success=success,
                stack=self.stack[:],
                alt_stack=self.alt_stack[:],
            )
        except ScriptError as exc:
            return ScriptResult(
                success=False,
                stack=self.stack[:],
                alt_stack=self.alt_stack[:],
                error_message=str(exc),
            )

    # ------------------------------------------------------------------
    # Internal runner
    # ------------------------------------------------------------------

    def _run(self, script: bytes) -> None:
        i = 0
        while i < len(script):
            opcode = script[i]
            i += 1

            # Push data
            if opcode <= MAX_SINGLE_BYTE_PUSH:
                length = opcode
                self._push(script[i : i + length])
                i += length
                continue
            if opcode == OP_PUSHDATA1:
                length = script[i]
                i += 1
                self._push(script[i : i + length])
                i += length
                continue
            if opcode == OP_PUSHDATA2:
                length = struct.unpack("<H", script[i : i + 2])[0]
                i += 2
                self._push(script[i : i + length])
                i += length
                continue

            # Opcodes
            handler = self._handlers.get(opcode)
            if handler is None:
                raise ScriptError(f"Unsupported opcode: 0x{opcode:02x}")
            ok = handler()
            if not ok:
                raise ScriptError(f"Opcode 0x{opcode:02x} failed")

    # ------------------------------------------------------------------
    # Opcode implementations
    # ------------------------------------------------------------------

    def _push(self, data: bytes) -> None:
        self.stack.append(data)

    def _pop(self) -> bytes:
        if not self.stack:
            raise ScriptError("Stack underflow")
        return self.stack.pop()

    @staticmethod
    def _cast_to_bool(data: bytes) -> bool:
        return any(b != 0 for b in data)

    def _op_dup(self) -> bool:
        if not self.stack:
            return False
        self.stack.append(self.stack[-1])
        return True

    def _op_hash160(self) -> bool:
        """RIPEMD160(SHA256(x))."""
        if not self.stack:
            return False
        data = self._pop()
        h = hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()
        self._push(h)
        return True

    def _op_equalverify(self) -> bool:
        if len(self.stack) < 2:
            return False
        a = self._pop()
        b = self._pop()
        if a != b:
            return False
        return True

    def _op_checksig(self) -> bool:
        """Verify ECDSA signature against pubkey, using tx_hash as message."""
        if len(self.stack) < 2:
            return False
        pubkey = self._pop()
        sig = self._pop()
        # Remove sighash byte if present (last byte)
        if sig and sig[-1] in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
            sig = sig[:-1]
        try:
            vk = VerifyingKey.from_string(pubkey, curve=SECP256k1)
            valid = vk.verify_digest(sig, self._tx_hash, sigdecode=sigdecode_der)
        except (BadSignatureError, Exception):
            valid = False
        self._push(b"\x01" if valid else b"\x00")
        return True

    def _op_checkmultisig(self) -> bool:
        """M-of-N multisig verification (simplified)."""
        if len(self.stack) < 1:
            return False
        m = self._pop_int()
        if len(self.stack) < m:
            return False
        pubkeys = [self._pop() for _ in range(m)]
        n = self._pop_int()
        if len(self.stack) < n:
            return False
        sigs = [self._pop() for _ in range(n)]
        _dummy = self._pop()  # Bitcoin bug compatibility
        valid_count = 0
        sig_idx = 0
        for pk in pubkeys:
            if sig_idx >= len(sigs):
                break
            try:
                vk = VerifyingKey.from_string(pk, curve=SECP256k1)
                sig = sigs[sig_idx]
                if sig and sig[-1] in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
                    sig = sig[:-1]
                if vk.verify_digest(sig, self._tx_hash, sigdecode=sigdecode_der):
                    valid_count += 1
                    sig_idx += 1
            except Exception:
                continue
        self._push(b"\x01" if valid_count >= n else b"\x00")
        return True

    def _op_checkgovsig(self) -> bool:
        """
        Verify governance committee multi-signature.

        Context must provide ``gov_pubkeys`` (list of bytes) and
        ``gov_threshold`` (int).
        """
        gov_pubkeys = self._context.get("gov_pubkeys", [])
        threshold = self._context.get("gov_threshold", 0)
        sigs = self._context.get("gov_signatures", [])
        if not gov_pubkeys or threshold <= 0:
            self._push(b"\x00")
            return True
        valid = 0
        used_sigs = set()
        for pk in gov_pubkeys:
            for idx, sig in enumerate(sigs):
                if idx in used_sigs:
                    continue
                try:
                    vk = VerifyingKey.from_string(pk, curve=SECP256k1)
                    if sig and sig[-1] in (0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
                        sig = sig[:-1]
                    vk.verify_digest(sig, self._tx_hash, sigdecode=sigdecode_der)
                    valid += 1
                    used_sigs.add(idx)
                    break
                except Exception:
                    continue
        self._push(b"\x01" if valid >= threshold else b"\x00")
        return True

    def _op_checkdid(self) -> bool:
        """
        Verify DID document binding.

        Context must provide ``did_document`` and ``did_proof``.
        This is a simplified stub; full DID verification is handled
        by the identity module.
        """
        did_doc = self._context.get("did_document")
        did_proof = self._context.get("did_proof")
        if did_doc is None or did_proof is None:
            self._push(b"\x00")
            return True
        # Stub: in production, verify the proof against the DID document
        self._push(b"\x01")
        return True

    def _op_push_n(self, n: int) -> bool:
        self._push(struct.pack("<B", n))
        return True

    def _pop_int(self) -> int:
        data = self._pop()
        if len(data) == 1:
            return data[0]
        return int.from_bytes(data, "little")


class ScriptError(Exception):
    """Raised when script execution fails."""


# ---------------------------------------------------------------------------
# Standard script generators / validators
# ---------------------------------------------------------------------------

class StandardScripts:
    """Helpers to generate and validate standard BCS scripts."""

    @staticmethod
    def p2pkh_lock_script(pubkey_hash: bytes) -> bytes:
        """
        Generate P2PKH lock script: OP_DUP OP_HASH160 <20-byte-pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG
        """
        if len(pubkey_hash) != 20:
            raise ValueError("pubkey_hash must be 20 bytes")
        return (
            bytes([Opcode.OP_DUP])
            + bytes([Opcode.OP_HASH160])
            + bytes([20])
            + pubkey_hash
            + bytes([Opcode.OP_EQUALVERIFY])
            + bytes([Opcode.OP_CHECKSIG])
        )

    @staticmethod
    def p2pkh_unlock_script(signature: bytes, pubkey: bytes) -> bytes:
        """Generate P2PKH unlock script (scriptSig)."""
        sig_len = len(signature)
        pub_len = len(pubkey)
        # Encode lengths as single-byte pushes if ≤75 bytes
        script = bytes([sig_len]) + signature + bytes([pub_len]) + pubkey
        return script

    @staticmethod
    def multisig_lock_script(m: int, pubkeys: list[bytes]) -> bytes:
        """
        Generate M-of-N multisig lock script.

        Args:
            m: Required signatures.
            pubkeys: All N public keys (order matters).
        """
        n = len(pubkeys)
        if not (1 <= m <= n <= 16):
            raise ValueError("Invalid m-of-n parameters")
        script = bytes([0x50 + m])  # OP_1 … OP_16
        for pk in pubkeys:
            script += bytes([len(pk)]) + pk
        script += bytes([0x50 + n, Opcode.OP_CHECKMULTISIG])
        return script

    @staticmethod
    def gov_lock_script(threshold: int, gov_pubkeys: list[bytes]) -> bytes:
        """Generate governance multi-sig lock script using OP_CHECKGOVSIG."""
        n = len(gov_pubkeys)
        script = bytes([0x50 + threshold])
        for pk in gov_pubkeys:
            script += bytes([len(pk)]) + pk
        script += bytes([0x50 + n, Opcode.OP_CHECKGOVSIG])
        return script

    @staticmethod
    def did_lock_script(did_hash: bytes) -> bytes:
        """Generate DID-bound lock script: OP_CHECKDID <did_hash> OP_CHECKSIG"""
        return (
            bytes([Opcode.OP_CHECKDID])
            + bytes([len(did_hash)])
            + did_hash
            + bytes([Opcode.OP_CHECKSIG])
        )

    @staticmethod
    def extract_pubkey_hash_from_p2pkh(lock_script: bytes) -> Optional[bytes]:
        """Parse a P2PKH lock script and return the embedded 20-byte pubkey hash."""
        expected_len = 1 + 1 + 1 + 20 + 1 + 1  # DUP HASH160 len hash EQV CHECKSIG
        if len(lock_script) != expected_len:
            return None
        if (
            lock_script[0] == Opcode.OP_DUP
            and lock_script[1] == Opcode.OP_HASH160
            and lock_script[2] == 20
            and lock_script[23] == Opcode.OP_EQUALVERIFY
            and lock_script[24] == Opcode.OP_CHECKSIG
        ):
            return lock_script[3:23]
        return None


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from ecdsa.keys import SigningKey

    engine = ScriptEngine()
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = vk.to_string("compressed")
    pubkey_hash = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()

    # 1. P2PKH round-trip
    lock = StandardScripts.p2pkh_lock_script(pubkey_hash)
    tx_hash = hashlib.sha3_256(b"test_tx").digest()
    sig = sk.sign_digest(tx_hash, sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order))
    unlock = StandardScripts.p2pkh_unlock_script(sig, pubkey)

    res = engine.execute(lock, unlock, tx_hash=tx_hash)
    assert res.success, f"P2PKH failed: {res.error_message}"
    print("P2PKH script execution OK")

    # 2. Wrong signature should fail
    bad_sk = SigningKey.generate(curve=SECP256k1)
    bad_sig = bad_sk.sign_digest(tx_hash, sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order))
    bad_unlock = StandardScripts.p2pkh_unlock_script(bad_sig, pubkey)
    res2 = engine.execute(lock, bad_unlock, tx_hash=tx_hash)
    assert not res2.success
    print("P2PKH bad signature correctly rejected")

    # 3. Multisig 2-of-3
    keys = [SigningKey.generate(curve=SECP256k1) for _ in range(3)]
    pubs = [k.get_verifying_key().to_string("compressed") for k in keys]
    ms_lock = StandardScripts.multisig_lock_script(2, pubs)
    ctx = {
        "gov_pubkeys": pubs,
        "gov_threshold": 2,
        "gov_signatures": [
            keys[0].sign_digest(tx_hash, sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order)),
            keys[2].sign_digest(tx_hash, sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order)),
        ],
    }
    ms_unlock = bytes([0x00])  # dummy for Bitcoin bug
    for sig in ctx["gov_signatures"]:
        ms_unlock += bytes([len(sig)]) + sig

    engine2 = ScriptEngine()
    res3 = engine2.execute(ms_lock, ms_unlock, tx_hash=tx_hash, context=ctx)
    assert res3.success, f"Multisig failed: {res3.error_message}"
    print("2-of-3 multisig OK")

    # 4. OP_HASH160 test
    test_engine = ScriptEngine()
    h160 = hashlib.new("ripemd160", hashlib.sha256(b"abc").digest()).digest()
    hash_script = bytes([3]) + b"abc" + bytes([Opcode.OP_HASH160])
    rh = test_engine.execute(hash_script, b"", tx_hash=b"")
    assert rh.stack[-1] == h160
    print("OP_HASH160 OK")

    # 5. Extract pubkey hash from P2PKH
    extracted = StandardScripts.extract_pubkey_hash_from_p2pkh(lock)
    assert extracted == pubkey_hash
    print("extract_pubkey_hash_from_p2pkh OK")

    print("script.py self-test PASSED")
