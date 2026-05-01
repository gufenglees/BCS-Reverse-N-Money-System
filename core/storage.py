"""
BCS Blockchain Core — Storage Layer
====================================
SQLite-based persistent storage for blocks, transactions, and indexes.

Components:
  • BlockStore    – block persistence with height/hash lookup
  • IndexStore    – address-UTXO and tx-hash secondary indexes

Design choices:
  • SQLite for zero-config embedded relational storage.
  • Blocks stored as JSON blobs for flexibility.
  • Indexes use normalized tables for efficient querying.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from block import Block, BlockHeader, BlockBody
from transaction import Transaction
from utxo import UTXO


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dict_factory(cursor, row):
    """SQLite row factory returning dicts."""
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


# ---------------------------------------------------------------------------
# BlockStore
# ---------------------------------------------------------------------------

class BlockStore:
    """
    Persistent block storage using SQLite.

    Schema:
      blocks(id INTEGER PRIMARY KEY, height INTEGER UNIQUE, hash TEXT UNIQUE,
             prev_hash TEXT, timestamp INTEGER, tx_count INTEGER,
             header_json TEXT, body_json TEXT)
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = _dict_factory
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                height INTEGER NOT NULL UNIQUE,
                hash TEXT NOT NULL UNIQUE,
                prev_hash TEXT,
                timestamp INTEGER,
                tx_count INTEGER,
                header_json TEXT NOT NULL,
                body_json TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_blocks_prev ON blocks(prev_hash)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_blocks_time ON blocks(timestamp)"
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save_block(self, block: Block) -> None:
        """Persist a block. Overwrites if height/hash already exists."""
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO blocks (height, hash, prev_hash, timestamp, tx_count, header_json, body_json)
                VALUES (:height, :hash, :prev_hash, :timestamp, :tx_count, :header_json, :body_json)
                ON CONFLICT(height) DO UPDATE SET
                    hash=excluded.hash,
                    prev_hash=excluded.prev_hash,
                    timestamp=excluded.timestamp,
                    tx_count=excluded.tx_count,
                    header_json=excluded.header_json,
                    body_json=excluded.body_json
                """,
                {
                    "height": block.header.height,
                    "hash": block.hash,
                    "prev_hash": block.header.prev_block_hash,
                    "timestamp": block.header.timestamp,
                    "tx_count": block.header.tx_count,
                    "header_json": json.dumps(block.header.to_dict(), sort_keys=True),
                    "body_json": json.dumps(block.body.to_dict(), sort_keys=True),
                },
            )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_block_by_height(self, height: int) -> Optional[Block]:
        """Retrieve a block by its height."""
        row = self._conn.execute(
            "SELECT * FROM blocks WHERE height = ?", (height,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_block(row)

    def get_block_by_hash(self, block_hash: str) -> Optional[Block]:
        """Retrieve a block by its hash."""
        row = self._conn.execute(
            "SELECT * FROM blocks WHERE hash = ?", (block_hash,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_block(row)

    def get_latest_block(self) -> Optional[Block]:
        """Return the highest-height block."""
        row = self._conn.execute(
            "SELECT * FROM blocks ORDER BY height DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return self._row_to_block(row)

    def get_blocks_range(self, start_height: int, end_height: int) -> list[Block]:
        """Retrieve blocks in a height range [start, end), ordered by height."""
        rows = self._conn.execute(
            "SELECT * FROM blocks WHERE height >= ? AND height < ? ORDER BY height",
            (start_height, end_height),
        ).fetchall()
        return [self._row_to_block(r) for r in rows]

    def get_chain_height(self) -> int:
        """Return the current chain height, or -1 if empty."""
        row = self._conn.execute(
            "SELECT MAX(height) as max_h FROM blocks"
        ).fetchone()
        return row["max_h"] if row and row["max_h"] is not None else -1

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_block(row: dict[str, Any]) -> Block:
        header = BlockHeader.from_dict(json.loads(row["header_json"]))
        body_dict = json.loads(row["body_json"])
        # Reconstruct body with Transaction objects
        from block import BlockBody
        from transaction import Transaction
        txs = [Transaction.from_dict(t) for t in body_dict.get("transactions", [])]
        return Block(header=header, body=BlockBody(transactions=txs))

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------------------
# IndexStore
# ---------------------------------------------------------------------------

class IndexStore:
    """
    Secondary indexes for efficient lookups.

    Tables:
      tx_index(tx_hash TEXT PRIMARY KEY, block_height INTEGER, tx_index INTEGER,
               tx_json TEXT)
      utxo_index(outpoint TEXT PRIMARY KEY, tx_hash TEXT, output_index INTEGER,
                 address TEXT, amount INTEGER, spent INTEGER DEFAULT 0,
                 spent_by_tx TEXT, lock_script TEXT)
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = _dict_factory
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tx_index (
                tx_hash TEXT PRIMARY KEY,
                block_height INTEGER,
                tx_index INTEGER,
                tx_json TEXT
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS utxo_index (
                outpoint TEXT PRIMARY KEY,
                tx_hash TEXT,
                output_index INTEGER,
                address TEXT,
                amount INTEGER,
                spent INTEGER DEFAULT 0,
                spent_by_tx TEXT,
                lock_script TEXT
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_utxo_addr ON utxo_index(address)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_utxo_unspent ON utxo_index(address, spent) WHERE spent = 0"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tx_height ON tx_index(block_height)"
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Transaction index
    # ------------------------------------------------------------------

    def index_transaction(
        self,
        tx: Transaction,
        block_height: int,
        tx_index: int,
    ) -> None:
        """Add a transaction to the tx index."""
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO tx_index (tx_hash, block_height, tx_index, tx_json)
                VALUES (:tx_hash, :block_height, :tx_index, :tx_json)
                ON CONFLICT(tx_hash) DO UPDATE SET
                    block_height=excluded.block_height,
                    tx_index=excluded.tx_index,
                    tx_json=excluded.tx_json
                """,
                {
                    "tx_hash": tx.hash(),
                    "block_height": block_height,
                    "tx_index": tx_index,
                    "tx_json": json.dumps(tx.to_dict(), sort_keys=True),
                },
            )

    def get_transaction(self, tx_hash: str) -> Optional[Transaction]:
        """Lookup a transaction by its hash."""
        row = self._conn.execute(
            "SELECT tx_json FROM tx_index WHERE tx_hash = ?", (tx_hash,)
        ).fetchone()
        if row is None:
            return None
        return Transaction.from_dict(json.loads(row["tx_json"]))

    def get_transactions_by_height(self, block_height: int) -> list[Transaction]:
        """Return all transactions in a given block height."""
        rows = self._conn.execute(
            "SELECT tx_json FROM tx_index WHERE block_height = ? ORDER BY tx_index",
            (block_height,),
        ).fetchall()
        return [Transaction.from_dict(json.loads(r["tx_json"])) for r in rows]

    # ------------------------------------------------------------------
    # UTXO index
    # ------------------------------------------------------------------

    def index_utxo(self, utxo: UTXO, address: str = "") -> None:
        """Add a UTXO to the index."""
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO utxo_index
                (outpoint, tx_hash, output_index, address, amount, spent, lock_script)
                VALUES (:outpoint, :tx_hash, :output_index, :address, :amount, 0, :lock_script)
                ON CONFLICT(outpoint) DO UPDATE SET
                    address=excluded.address,
                    amount=excluded.amount,
                    lock_script=excluded.lock_script,
                    spent=0,
                    spent_by_tx=NULL
                """,
                {
                    "outpoint": utxo.outpoint,
                    "tx_hash": utxo.tx_hash,
                    "output_index": utxo.output_index,
                    "address": address,
                    "amount": utxo.amount,
                    "lock_script": utxo.lock_script.hex(),
                },
            )

    def spend_utxo(self, tx_hash: str, output_index: int, spent_by_tx: str) -> None:
        """Mark a UTXO as spent."""
        outpoint = f"{tx_hash}:{output_index}"
        with self._conn:
            self._conn.execute(
                "UPDATE utxo_index SET spent = 1, spent_by_tx = ? WHERE outpoint = ?",
                (spent_by_tx, outpoint),
            )

    def get_utxos_by_address(self, address: str, unspent_only: bool = True) -> list[UTXO]:
        """Return UTXOs for an address, optionally filtering to unspent."""
        if unspent_only:
            rows = self._conn.execute(
                "SELECT * FROM utxo_index WHERE address = ? AND spent = 0",
                (address,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM utxo_index WHERE address = ?",
                (address,),
            ).fetchall()
        return [
            UTXO(
                tx_hash=r["tx_hash"],
                output_index=r["output_index"],
                amount=r["amount"],
                lock_script=bytes.fromhex(r["lock_script"]),
            )
            for r in rows
        ]

    def get_utxo(self, tx_hash: str, output_index: int) -> Optional[UTXO]:
        """Lookup a single UTXO by outpoint."""
        row = self._conn.execute(
            "SELECT * FROM utxo_index WHERE outpoint = ?",
            (f"{tx_hash}:{output_index}",),
        ).fetchone()
        if row is None:
            return None
        return UTXO(
            tx_hash=row["tx_hash"],
            output_index=row["output_index"],
            amount=row["amount"],
            lock_script=bytes.fromhex(row["lock_script"]),
        )

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from transaction import TxInput, TxOutput, TxType

    # 1. BlockStore
    bs = BlockStore(":memory:")
    tx = Transaction(
        inputs=[TxInput(tx_hash="a" * 64, output_index=0)],
        outputs=[TxOutput(amount=1_000_000_000)],
    )
    genesis = Block(
        header=BlockHeader(height=0, prev_block_hash="0" * 64),
        body=BlockBody(transactions=[tx]),
    )
    genesis.header.merkle_root_tx = genesis.tx_merkle_root()
    bs.save_block(genesis)

    fetched = bs.get_block_by_height(0)
    assert fetched is not None
    assert fetched.hash == genesis.hash
    assert fetched.body.transactions[0].hash() == tx.hash()
    print("BlockStore save/load OK")

    # 2. Range query
    for h in range(1, 5):
        b = Block(
            header=BlockHeader(height=h, prev_block_hash="0" * 64),
            body=BlockBody(),
        )
        bs.save_block(b)
    rng = bs.get_blocks_range(1, 4)
    assert len(rng) == 3
    assert rng[0].header.height == 1
    print("Range query OK")

    latest = bs.get_latest_block()
    assert latest is not None and latest.header.height == 4
    print("Latest block OK:", latest.header.height)

    # 3. IndexStore
    ix = IndexStore(":memory:")
    ix.index_transaction(tx, block_height=0, tx_index=0)
    ft = ix.get_transaction(tx.hash())
    assert ft is not None
    assert ft.hash() == tx.hash()
    print("Tx index OK")

    utxo = UTXO(tx_hash=tx.hash(), output_index=0, amount=1_000_000_000)
    ix.index_utxo(utxo, address="addr_test")
    by_addr = ix.get_utxos_by_address("addr_test")
    assert len(by_addr) == 1
    assert by_addr[0].amount == 1_000_000_000
    print("UTXO index OK")

    ix.spend_utxo(tx.hash(), 0, spent_by_tx="bbbb")
    spent = ix.get_utxos_by_address("addr_test", unspent_only=True)
    assert len(spent) == 0
    print("Spend tracking OK")

    bs.close()
    ix.close()
    print("storage.py self-test PASSED")
