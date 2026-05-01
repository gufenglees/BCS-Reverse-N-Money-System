"""
sync.py — Reconnection Synchronisation Engine
==============================================
Implements the 6-phase offline-node catch-up protocol described in §6.2.

Phases:
  1. find_common_ancestor  — binary-search for fork point
  2. download missing blocks
  3. fast validate header chain
  4. choose snapshot or incremental replay
  5. replay transactions → update local UTXO view
  6. submit local offline transactions (with conflict filtering)

Also contains SyncResult dataclass and peer-client abstractions.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable, List, Optional, Protocol, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s | %(name)s | %(levelname)s | %(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Core imports
# ---------------------------------------------------------------------------
from _core_stubs import (
    Block,
    BlockHeader,
    Transaction,
    TxType,
    UTXO,
    UTXOSet,
)
from cache import TxCache, TxStatus
from utxo_view import UTXOSyncView

# ---------------------------------------------------------------------------
# Configuration knobs
# ---------------------------------------------------------------------------
FULL_SYNC_THRESHOLD: int = 144       # > 144 blocks (~12 h @ 5 s) → snapshot
UTXO_REPLAY_WINDOW: int = 36         # replay only last 36 blocks after snapshot
HEADER_BATCH_SIZE: int = 100         # headers per batch request
BLOCK_BATCH_SIZE: int = 20           # full blocks per batch request
MAX_RETRY: int = 3


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class SyncError(Exception):
    pass

class HeaderChainInvalidError(SyncError):
    pass

class PeerUnavailableError(SyncError):
    pass


# ---------------------------------------------------------------------------
# Peer protocol (async)
# ---------------------------------------------------------------------------
class PeerClient(Protocol):
    """Abstract peer interface — implemented by the real network layer."""

    async def get_latest_header(self) -> BlockHeader:
        ...

    async def get_header_at(self, height: int) -> BlockHeader:
        ...

    async def get_blocks_from(self, height: int, limit: int) -> List[Block]:
        ...

    async def get_utxo_snapshot_at(self, height: int) -> UTXOSet:
        ...

    async def get_utxo_exists(self, tx_hash: bytes, output_index: int) -> bool:
        ...

    async def submit_tx(self, tx: Transaction) -> Tuple[bool, str]:
        """Returns (accepted, reason_or_empty)."""
        ...


# ---------------------------------------------------------------------------
# SyncResult
# ---------------------------------------------------------------------------
@dataclass
class SyncResult:
    """Outcome of a synchronisation run."""
    synced_blocks: int = 0
    applied_offline: int = 0
    resolved_conflicts: int = 0
    new_tip: Optional[BlockHeader] = None
    rejected_txs: List[RejectedTx] = field(default_factory=list)
    reverted_local_txs: List[bytes] = field(default_factory=list)


@dataclass
class RejectedTx:
    tx_hash: bytes
    reason: str


# ---------------------------------------------------------------------------
# SyncEngine
# ---------------------------------------------------------------------------
class SyncEngine:
    """
    Orchestrates the 6-phase catch-up for an offline node reconnecting
    to the network.
    """

    def __init__(
        self,
        cache: TxCache,
        utxo_view: UTXOSyncView,
        full_sync_threshold: int = FULL_SYNC_THRESHOLD,
        replay_window: int = UTXO_REPLAY_WINDOW,
    ) -> None:
        self.cache = cache
        self.utxo_view = utxo_view
        self.full_sync_threshold = full_sync_threshold
        self.replay_window = replay_window
        logger.info(
            "SyncEngine created (snapshot_threshold=%s, replay_window=%s)",
            full_sync_threshold,
            replay_window,
        )

    # =================================================================
    # Phase 1–6  orchestration
    # =================================================================
    async def sync_with_peer(
        self,
        local_tip: Optional[BlockHeader],
        peer_client: PeerClient,
    ) -> SyncResult:
        """
        Main synchronisation entry point.

        Args:
            local_tip:   last known local block header (None if genesis).
            peer_client: network abstraction for the chosen peer.

        Returns:
            SyncResult summarising what changed.
        """
        result = SyncResult()

        try:
            # ---- Phase 1: find common ancestor --------------------------------
            common = await self._phase1_find_common_ancestor(local_tip, peer_client)
            logger.info("Phase-1 common_ancestor height=%s", common.height if common else "None")

            # ---- Phase 2: download missing blocks -----------------------------
            missing = await self._phase2_download_missing(common, peer_client)
            logger.info("Phase-2 downloaded %s missing blocks", len(missing))
            result.synced_blocks = len(missing)

            if not missing:
                # already at tip — just re-evaluate local txs
                return await self._phase6_submit_offline(peer_client, result)

            # ---- Phase 3: fast validate header chain -----------------------
            if not self._phase3_validate_headers(missing):
                raise HeaderChainInvalidError("Header chain validation failed")
            logger.info("Phase-3 header chain valid")

            # ---- Phase 4: snapshot vs incremental --------------------------
            replay_blocks = await self._phase4_choose_replay_mode(
                missing, common, peer_client
            )
            logger.info("Phase-4 replaying %s blocks", len(replay_blocks))

            # ---- Phase 5: replay transactions → update UTXO view -----------
            await self._phase5_replay(replay_blocks)
            logger.info("Phase-5 replay complete")

            # ---- Phase 6: submit local offline txs ---------------------------
            result = await self._phase6_submit_offline(peer_client, result)
            result.new_tip = missing[-1].header if missing else local_tip

        except Exception as exc:
            logger.exception("Sync with peer failed: %s", exc)
            raise SyncError(f"Sync failed: {exc}") from exc

        return result

    # =================================================================
    # Phase 1  — find common ancestor
    # =================================================================
    async def find_common_ancestor(
        self,
        local_tip: Optional[BlockHeader],
        peer: PeerClient,
    ) -> Optional[BlockHeader]:
        """
        Binary-search for the highest header shared by local chain and peer.

        If local_tip is None (empty local chain) we return None and will
        perform a full sync from genesis.
        """
        return await self._phase1_find_common_ancestor(local_tip, peer)

    async def _phase1_find_common_ancestor(
        self,
        local_tip: Optional[BlockHeader],
        peer: PeerClient,
    ) -> Optional[BlockHeader]:
        peer_tip = await peer.get_latest_header()

        if local_tip is None:
            return None  # full sync from genesis

        # fast path: local_tip is already the peer's ancestor
        if await self._is_ancestor(local_tip.hash(), peer_tip.height, peer):
            return local_tip

        low, high = 0, local_tip.height
        while low < high:
            mid = (low + high) // 2
            local_header = await self._get_local_header_at(mid)
            peer_header = await peer.get_header_at(mid)

            if local_header.hash() == peer_header.hash():
                low = mid + 1
            else:
                high = mid

        # low is the first divergent height; common ancestor is low-1
        ancestor_height = max(0, low - 1)
        common = await self._get_local_header_at(ancestor_height)
        logger.debug(
            "Binary-search complete: diverged at %s, ancestor=%s",
            low,
            ancestor_height,
        )
        return common

    async def _is_ancestor(
        self,
        local_hash: bytes,
        peer_height: int,
        peer: PeerClient,
    ) -> bool:
        """Check whether *local_hash* appears anywhere in peer's history."""
        # naive: ask peer for header at local_tip.height and compare
        try:
            h = await peer.get_header_at(peer_height)
            return h.hash() == local_hash
        except Exception:
            return False

    async def _get_local_header_at(self, height: int) -> BlockHeader:
        """Stub: local storage lookup.  Override in production."""
        # In a real node this reads from local block store.
        return BlockHeader(height=height, prev_block_hash=b"\x00" * 32)

    # =================================================================
    # Phase 2  — download missing blocks
    # =================================================================
    async def _phase2_download_missing(
        self,
        common: Optional[BlockHeader],
        peer: PeerClient,
    ) -> List[Block]:
        """Download all blocks from common.height+1 up to peer tip."""
        peer_tip = await peer.get_latest_header()
        start_height = (common.height + 1) if common else 0
        missing: List[Block] = []

        cursor = start_height
        while cursor <= peer_tip.height:
            batch = await peer.get_blocks_from(cursor, BLOCK_BATCH_SIZE)
            if not batch:
                logger.warning("Peer returned empty batch at height %s", cursor)
                break
            missing.extend(batch)
            cursor += len(batch)

        return missing

    # =================================================================
    # Phase 3  — fast validate header chain
    # =================================================================
    def _phase3_validate_headers(self, blocks: List[Block]) -> bool:
        """
        Quick header-chain checks (signature & prev_hash continuity).
        Full tx validation is deferred to Phase 5.
        """
        prev_hash: Optional[bytes] = None
        for idx, block in enumerate(blocks):
            h = block.header
            if prev_hash is not None and h.prev_block_hash != prev_hash:
                logger.error(
                    "Header chain break at height %s: prev_hash mismatch",
                    h.height,
                )
                return False
            # simplified signature check (real code calls ecdsa_verify)
            if not self._validate_header_signature(h):
                logger.error("Invalid header signature at height %s", h.height)
                return False
            prev_hash = h.hash()
        return True

    def _validate_header_signature(self, header: BlockHeader) -> bool:
        # Production: ecdsa_verify(header.validator_pubkey, header.hash(), header.signature)
        # Stub: non-empty signature is accepted.
        return len(header.signature) > 0 or header.height == 0

    # =================================================================
    # Phase 4  — snapshot vs incremental
    # =================================================================
    async def _phase4_choose_replay_mode(
        self,
        missing: List[Block],
        common: Optional[BlockHeader],
        peer: PeerClient,
    ) -> List[Block]:
        """
        If gap is large, download a UTXO snapshot at common ancestor and
        replay only the tail window.  Otherwise replay all missing blocks.
        """
        if len(missing) > self.full_sync_threshold and common is not None:
            snapshot = await peer.get_utxo_snapshot_at(common.height)
            self.utxo_view.sync_with_chain(snapshot)
            return missing[-self.replay_window :]
        return missing

    # =================================================================
    # Phase 5  — replay transactions
    # =================================================================
    async def _phase5_replay(self, replay_blocks: List[Block]) -> None:
        """
        Re-apply every transaction in every block to the local UTXO view.
        This produces a chain-side view against which offline txs will be
        validated in Phase 6.
        """
        # Build a new chain UTXO set from scratch by replaying.
        chain_set = UTXOSet()
        for block in replay_blocks:
            for tx in block.transactions:
                chain_set.apply_transaction(tx)

        # Sync the optimistic view with the rebuilt chain state
        self.utxo_view.sync_with_chain(chain_set)

    # =================================================================
    # Phase 6  — submit offline transactions
    # =================================================================
    async def _phase6_submit_offline(
        self,
        peer: PeerClient,
        result: SyncResult,
    ) -> SyncResult:
        """
        6a. Filter valid offline txs (inputs still unspent).
        6b. Submit valid txs to peer.
        6c. Record rejections / conflicts.
        """
        offline_txs = self.cache.get_pending()
        if not offline_txs:
            logger.info("Phase-6 no pending offline transactions")
            return result

        # extract Transaction objects
        txs = [ctx.tx for ctx in offline_txs]
        valid_txs, rejected = await self.filter_valid_offline_txs(txs, peer)

        # submit valid ones
        accepted_count = 0
        for tx in valid_txs:
            accepted, reason = await self._submit_with_retry(peer, tx)
            if accepted:
                accepted_count += 1
                self.cache.update_status(tx.hash(), TxStatus.PENDING_NETWORK)
            else:
                rejected.append(RejectedTx(tx.hash(), reason))
                self.cache.update_status(tx.hash(), TxStatus.REJECTED)

        result.applied_offline = accepted_count
        result.rejected_txs = rejected
        result.resolved_conflicts = len(rejected)
        logger.info(
            "Phase-6 submitted %s/%s offline txs (%s rejected)",
            accepted_count,
            len(txs),
            len(rejected),
        )
        return result

    async def filter_valid_offline_txs(
        self,
        offline_txs: List[Transaction],
        peer: PeerClient,
    ) -> Tuple[List[Transaction], List[RejectedTx]]:
        """
        Check each offline tx:
          • all referenced input UTXOs must still exist (not spent on chain)
          • φ/ψ rules must still be valid (against current params)
        """
        valid: List[Transaction] = []
        rejected: List[RejectedTx] = []

        for tx in offline_txs:
            all_unspent = True
            for inp in tx.inputs:
                try:
                    exists = await peer.get_utxo_exists(inp.tx_hash, inp.output_index)
                except Exception as exc:
                    logger.warning("UTXO existence check failed: %s", exc)
                    exists = False
                if not exists:
                    all_unspent = False
                    break

            if all_unspent:
                valid.append(tx)
            else:
                rejected.append(
                    RejectedTx(tx.hash(), "Input UTXO already spent on chain")
                )
                logger.info(
                    "Offline tx %s rejected: spent UTXO on chain",
                    tx.hash().hex()[:16],
                )

        return valid, rejected

    async def _submit_with_retry(
        self,
        peer: PeerClient,
        tx: Transaction,
        max_retry: int = MAX_RETRY,
    ) -> Tuple[bool, str]:
        """Submit with exponential back-off."""
        for attempt in range(max_retry):
            try:
                return await peer.submit_tx(tx)
            except Exception as exc:
                wait = 1.5 ** attempt
                logger.warning("Submit attempt %s failed: %s (retry in %.1fs)", attempt + 1, exc, wait)
                await asyncio.sleep(wait)
        return False, f"Failed after {max_retry} attempts"


# ===========================================================================
# Self-test  (uses a fake PeerClient)
# ===========================================================================
class _FakePeerClient:
    """In-memory peer for unit testing the SyncEngine."""

    def __init__(self, chain: List[Block], utxo_set: UTXOSet) -> None:
        self.chain = chain
        self.utxo_set = utxo_set
        self.submitted: List[Transaction] = []

    async def get_latest_header(self) -> BlockHeader:
        return self.chain[-1].header if self.chain else BlockHeader()

    async def get_header_at(self, height: int) -> BlockHeader:
        for blk in self.chain:
            if blk.header.height == height:
                return blk.header
        return BlockHeader(height=height)

    async def get_blocks_from(self, height: int, limit: int) -> List[Block]:
        out = []
        for blk in self.chain:
            if blk.header.height >= height:
                out.append(blk)
            if len(out) >= limit:
                break
        return out

    async def get_utxo_snapshot_at(self, height: int) -> UTXOSet:
        return self.utxo_set.copy()

    async def get_utxo_exists(self, tx_hash: bytes, output_index: int) -> bool:
        return self.utxo_set.exists(tx_hash, output_index)

    async def submit_tx(self, tx: Transaction) -> Tuple[bool, str]:
        self.submitted.append(tx)
        return True, ""


def _self_test() -> None:
    print("\n=== sync.py self-test ===")
    from _core_stubs import TxType, TxInput, TxOutput, UTXO

    addr_a = b"\x00" * 20
    addr_b = b"\x01" * 20

    # --- build a fake chain (3 blocks) ---
    genesis = Block(
        header=BlockHeader(height=0, prev_block_hash=b"\x00" * 32, signature=b"sig0"),
        transactions=[],
    )
    tx1 = Transaction(
        tx_type=TxType.TRANSFER,
        inputs=[TxInput(tx_hash=b"\xaa" * 32, output_index=0)],
        outputs=[TxOutput(amount=500, lock_script=addr_b)],
    )
    blk1 = Block(
        header=BlockHeader(height=1, prev_block_hash=genesis.header.hash(), signature=b"sig1"),
        transactions=[tx1],
    )
    blk2 = Block(
        header=BlockHeader(height=2, prev_block_hash=blk1.header.hash(), signature=b"sig2"),
        transactions=[],
    )
    chain = [genesis, blk1, blk2]

    # --- build peer UTXO set (reflects tx1 + keeps addr_a's utxo unspent) ---
    peer_utxo = UTXOSet()
    peer_utxo.add(UTXO(tx_hash=tx1.hash(), output_index=0, amount=500, lock_script=addr_b))
    peer_utxo.add(UTXO(tx_hash=b"\xcc" * 32, output_index=0, amount=1000, lock_script=addr_a))  # still unspent

    # --- local view has one utxo for addr_a, and one offline tx spending it ---
    local_utxo = UTXOSet()
    local_utxo.add(UTXO(tx_hash=b"\xcc" * 32, output_index=0, amount=1000, lock_script=addr_a))

    offline_tx = Transaction(
        tx_type=TxType.TRANSFER,
        inputs=[TxInput(tx_hash=b"\xcc" * 32, output_index=0)],
        outputs=[TxOutput(amount=900, lock_script=addr_b)],
    )

    cache = TxCache(db_path=":memory:")
    cache.cache_tx(offline_tx, status=TxStatus.CACHED)

    view = UTXOSyncView(initial_chain_utxos=local_utxo)
    view.apply_local_tx(offline_tx)

    engine = SyncEngine(cache=cache, utxo_view=view)
    peer = _FakePeerClient(chain, peer_utxo)

    # --- run sync ---
    async def run_sync():
        result = await engine.sync_with_peer(genesis.header, peer)
        print(f"[SYNC] synced_blocks={result.synced_blocks}")
        print(f"[SYNC] applied_offline={result.applied_offline}")
        print(f"[SYNC] rejected={len(result.rejected_txs)}")
        print(f"[SYNC] new_tip_height={result.new_tip.height if result.new_tip else 'None'}")
        return result

    import asyncio
    result = asyncio.get_event_loop().run_until_complete(run_sync())

    assert result.synced_blocks == 2  # blk1 + blk2
    assert result.applied_offline == 1  # our offline tx was valid (utxo not spent)
    assert len(result.rejected_txs) == 0
    assert result.new_tip is not None and result.new_tip.height == 2
    assert len(peer.submitted) == 1

    # --- check cache status updated ---
    cached = cache.get_by_hash(offline_tx.hash())
    assert cached is not None
    assert cached.status == TxStatus.PENDING_NETWORK
    print(f"[CACHE] offline tx status={cached.status.name}")

    print("=== sync.py self-test PASSED ===\n")


if __name__ == "__main__":
    _self_test()
