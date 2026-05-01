"""
BCS Transaction Exporter / Importer
===================================
Export and import transactions in multiple formats for portability:

  • QR Code   — Base64-encoded compact JSON (for camera scanning)
  • JSON File — Human-readable transaction array
  • NFC       — Minimal binary payload (simplified)

All formats preserve the full Transaction structure including signatures,
making them suitable for:
  1. Moving an unsigned/signed tx from an air-gapped signer to a broadcaster
  2. Batch-importing offline transactions
  3. NFC tap-to-pay scenarios

Architecture reference: architecture_design.md §2.7 (Wallet/Client)
"""

from __future__ import annotations

import base64
import json
import struct
from pathlib import Path
from typing import Any

from core.transaction import Transaction


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# NFC packet header magic bytes
NFC_MAGIC: bytes = b"BCS\x01"
NFC_MAX_PAYLOAD: int = 2048  # Typical NFC NDEF max ~2KB

# QR chunk size limit — keep under common scanner limits
QR_MAX_BYTES: int = 2953  # QR Code version 40 alphanumeric max


# --------------------------------------------------------------------------- #
# TxExporter
# --------------------------------------------------------------------------- #

class TxExporter:
    """
    Export and import BCS Transactions in portable formats.

    Usage::

        exporter = TxExporter()

        # To QR
        qr_data = exporter.export_to_qr(tx)

        # To file
        exporter.export_to_file([tx, tx2], "/tmp/txs.json")

        # From file
        txs = exporter.import_from_file("/tmp/txs.json")

        # NFC
        nfc_bytes = exporter.export_to_nfc(tx)
    """

    # ------------------------------------------------------------------ #
    # QR Code
    # ------------------------------------------------------------------ #

    def export_to_qr(self, tx: Transaction) -> str:
        """
        Export a transaction to a QR-code-scannable string.

        Encoding:
            base64(json.dumps(tx.to_dict()))

        The result is URL-safe base64 (no +/ padding issues) and
        fits within standard QR capacity limits for single transactions.

        Args:
            tx: Transaction to encode.

        Returns:
            Base64 string (no padding, URL-safe alphabet).
        """
        tx_json = json.dumps(tx.to_dict(), sort_keys=True, separators=(",", ":"))
        tx_bytes = tx_json.encode("utf-8")
        if len(tx_bytes) > QR_MAX_BYTES:
            raise ValueError(
                f"Transaction too large for QR ({len(tx_bytes)} > {QR_MAX_BYTES} bytes). "
                "Consider exporting to file instead."
            )
        return base64.urlsafe_b64encode(tx_bytes).decode("ascii").rstrip("=")

    def import_from_qr(self, qr_data: str) -> Transaction:
        """
        Decode a transaction from QR string.

        Args:
            qr_data: Base64-encoded transaction JSON (as produced by export_to_qr).

        Returns:
            Transaction instance.

        Raises:
            ValueError: If decoding fails or JSON is invalid.
        """
        # Add padding back if stripped
        padding = 4 - len(qr_data) % 4
        if padding != 4:
            qr_data += "=" * padding
        try:
            tx_bytes = base64.urlsafe_b64decode(qr_data)
        except Exception as exc:
            raise ValueError(f"Invalid QR base64: {exc}") from exc

        try:
            tx_dict = json.loads(tx_bytes.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"Invalid QR JSON: {exc}") from exc

        return Transaction.from_dict(tx_dict)

    # ------------------------------------------------------------------ #
    # JSON File
    # ------------------------------------------------------------------ #

    def export_to_file(self, txs: list[Transaction], filepath: str) -> None:
        """
        Write a list of transactions to a JSON file.

        Format::

            {
              "version": 1,
              "export_time": <unix_timestamp>,
              "count": <n>,
              "transactions": [ {tx1}, {tx2}, ... ]
            }

        Args:
            txs: Transactions to export.
            filepath: Destination path (will be overwritten).
        """
        payload = {
            "version": 1,
            "export_time": int(__import__("time").time()),
            "count": len(txs),
            "transactions": [tx.to_dict() for tx in txs],
        }
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)

    def import_from_file(self, filepath: str) -> list[Transaction]:
        """
        Read transactions from a JSON file.

        Args:
            filepath: Path to the JSON file.

        Returns:
            List of Transaction instances.

        Raises:
            FileNotFoundError: If filepath does not exist.
            ValueError: If JSON structure is invalid.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Transaction file not found: {filepath}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if "transactions" in data:
            tx_dicts = data["transactions"]
        elif isinstance(data, list):
            tx_dicts = data
        else:
            raise ValueError("JSON file must contain a 'transactions' array or be an array itself")

        return [Transaction.from_dict(d) for d in tx_dicts]

    # ------------------------------------------------------------------ #
    # NFC (simplified binary format)
    # ------------------------------------------------------------------ #

    def export_to_nfc(self, tx: Transaction) -> bytes:
        """
        Export a transaction to a minimal NFC-friendly binary payload.

        Format::

            [magic: 4 bytes]  = b"BCS\x01"
            [tx_json_len: 4 bytes BE]
            [tx_json_bytes: N bytes]
            [checksum: 4 bytes CRC32 of tx_json_bytes]

        Total size is kept under NFC_MAX_PAYLOAD (2KB).

        Args:
            tx: Transaction to encode.

        Returns:
            Binary bytes suitable for NFC NDEF payload.
        """
        tx_json = json.dumps(tx.to_dict(), sort_keys=True, separators=(",", ":"))
        tx_bytes = tx_json.encode("utf-8")

        if len(tx_bytes) > NFC_MAX_PAYLOAD - 12:
            raise ValueError(
                f"Transaction too large for NFC ({len(tx_bytes)} bytes). "
                "Consider QR or file export."
            )

        checksum = _crc32(tx_bytes)
        payload = (
            NFC_MAGIC
            + struct.pack(">I", len(tx_bytes))
            + tx_bytes
            + struct.pack(">I", checksum)
        )
        return payload

    def import_from_nfc(self, nfc_bytes: bytes) -> Transaction:
        """
        Decode a transaction from NFC binary payload.

        Args:
            nfc_bytes: Binary data from export_to_nfc().

        Returns:
            Transaction instance.

        Raises:
            ValueError: If format or checksum is invalid.
        """
        if len(nfc_bytes) < 12:
            raise ValueError("NFC payload too short")

        magic = nfc_bytes[:4]
        if magic != NFC_MAGIC:
            raise ValueError(f"Invalid NFC magic: expected {NFC_MAGIC!r}, got {magic!r}")

        tx_len = struct.unpack(">I", nfc_bytes[4:8])[0]
        tx_bytes = nfc_bytes[8 : 8 + tx_len]
        stored_checksum = struct.unpack(">I", nfc_bytes[8 + tx_len : 12 + tx_len])[0]

        computed_checksum = _crc32(tx_bytes)
        if computed_checksum != stored_checksum:
            raise ValueError(
                f"NFC checksum mismatch: computed {computed_checksum:#010x}, "
                f"stored {stored_checksum:#010x}"
            )

        tx_dict = json.loads(tx_bytes.decode("utf-8"))
        return Transaction.from_dict(tx_dict)

    # ------------------------------------------------------------------ #
    # Batch helpers
    # ------------------------------------------------------------------ #

    def export_batch_to_qr_chunks(self, txs: list[Transaction]) -> list[str]:
        """
        Export multiple transactions as a list of QR strings.

        Each string encodes one transaction. Use this when you need to
        scan a batch of transactions one at a time.

        Args:
            txs: Transactions to encode.

        Returns:
            List of QR data strings.
        """
        return [self.export_to_qr(tx) for tx in txs]

    def import_batch_from_qr_chunks(self, qr_chunks: list[str]) -> list[Transaction]:
        """Decode a list of QR strings back to transactions."""
        return [self.import_from_qr(chunk) for chunk in qr_chunks]


# --------------------------------------------------------------------------- #
# CRC32 helper (simplified, no table lookup needed for small payloads)
# --------------------------------------------------------------------------- #

def _crc32(data: bytes) -> int:
    """Compute CRC32 of data using zlib (if available) or pure Python fallback."""
    try:
        import zlib
        return zlib.crc32(data) & 0xFFFFFFFF
    except ImportError:
        # Pure Python fallback (very slow for large data, fine for tx JSON)
        crc = 0xFFFFFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xEDB88320
                else:
                    crc >>= 1
        return crc ^ 0xFFFFFFFF


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #

def _self_test() -> None:
    import os
    import tempfile

    print("=" * 60)
    print("BCS TxExporter Self-Test")
    print("=" * 60)

    from ecdsa import SigningKey, SECP256k1
    from core.transaction import Transaction, TxInput, TxOutput, TxType

    exporter = TxExporter()

    # Build a sample transaction
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = vk.to_string("compressed")

    tx = Transaction(
        version=1,
        tx_type=TxType.TRANSFER,
        inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
        outputs=[TxOutput(amount=1_000_000_000, lock_script=b"\x76\xa9" + b"\x00" * 20 + b"\x88\xac")],
        lock_time=0,
        extra=b"test_extra",
    )
    # Sign it
    sighash = tx.signing_hash()
    sig = sk.sign_digest(sighash, sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order))
    tx.inputs[0].unlock_script = bytes([len(sig)]) + sig + bytes([len(pubkey)]) + pubkey
    tx.witnesses.append(tx.inputs[0].unlock_script)

    # 1. QR export / import
    qr_data = exporter.export_to_qr(tx)
    assert len(qr_data) > 0
    print(f"[1] QR export OK ({len(qr_data)} chars)")

    tx_back = exporter.import_from_qr(qr_data)
    assert tx_back.hash() == tx.hash()
    assert tx_back.tx_type == tx.tx_type
    assert tx_back.inputs[0].tx_hash == tx.inputs[0].tx_hash
    print(f"[2] QR import OK, hash matches: {tx_back.hash()[:16]}...")

    # 3. JSON file export / import
    tmpdir = tempfile.mkdtemp(prefix="bcs_exporter_test_")
    filepath = os.path.join(tmpdir, "txs.json")

    tx2 = Transaction(
        version=1,
        tx_type=TxType.TRANSFER_SALE,
        inputs=[TxInput(tx_hash="b" * 64, output_index=1)],
        outputs=[TxOutput(amount=500_000_000)],
        extra=json.dumps({"d_amount": 1000}).encode("utf-8"),
    )

    exporter.export_to_file([tx, tx2], filepath)
    assert os.path.exists(filepath)
    print(f"[3] File export OK: {filepath}")

    loaded = exporter.import_from_file(filepath)
    assert len(loaded) == 2
    assert loaded[0].hash() == tx.hash()
    assert loaded[1].tx_type == TxType.TRANSFER_SALE
    print(f"[4] File import OK: {len(loaded)} transactions loaded")

    # 5. NFC export / import
    nfc_bytes = exporter.export_to_nfc(tx)
    assert nfc_bytes[:4] == NFC_MAGIC
    print(f"[5] NFC export OK ({len(nfc_bytes)} bytes)")

    tx_nfc = exporter.import_from_nfc(nfc_bytes)
    assert tx_nfc.hash() == tx.hash()
    print(f"[6] NFC import OK, hash matches: {tx_nfc.hash()[:16]}...")

    # 7. NFC checksum tamper detection
    bad_bytes = bytearray(nfc_bytes)
    bad_bytes[-1] ^= 0xFF  # corrupt last checksum byte
    try:
        exporter.import_from_nfc(bytes(bad_bytes))
        assert False, "Expected checksum error"
    except ValueError as exc:
        assert "checksum mismatch" in str(exc).lower()
        print("[7] NFC tamper detection OK")

    # 8. Batch QR chunks
    chunks = exporter.export_batch_to_qr_chunks([tx, tx2])
    assert len(chunks) == 2
    txs_back = exporter.import_batch_from_qr_chunks(chunks)
    assert txs_back[0].hash() == tx.hash()
    assert txs_back[1].hash() == tx2.hash()
    print(f"[8] Batch QR chunks OK: {len(chunks)} chunks")

    # 9. Invalid QR data
    try:
        exporter.import_from_qr("!!!not_valid_base64!!!")
        assert False, "Expected error"
    except ValueError:
        print("[9] Invalid QR data correctly rejected")

    # Cleanup
    os.remove(filepath)
    os.rmdir(tmpdir)

    print("\n" + "=" * 60)
    print("All exporter.py self-tests PASSED")
    print("=" * 60)


if __name__ == "__main__":
    _self_test()
