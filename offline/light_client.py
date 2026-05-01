"""
light_client.py — Light Client Verification
=============================================
Provides Merkle-proof, state-proof, and header-chain validation utilities
for resource-constrained clients that do not store the full blockchain.

Capabilities:
  • verify_merkle_proof     — SPV-style tx inclusion proof
  • verify_state_proof      — Patricia-trie / UTXO-root state proof
  • validate_header_chain   — PoA header continuity & signature check
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

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
    BlockHeader,
    Transaction,
    UTXO,
    AccountState,
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class LightClientError(Exception):
    pass

class MerkleProofInvalidError(LightClientError):
    pass

class StateProofInvalidError(LightClientError):
    pass

class HeaderChainInvalidError(LightClientError):
    pass


# ---------------------------------------------------------------------------
# Merkle tree helpers (simplified binary Merkle tree)
# ---------------------------------------------------------------------------
def _sha3_leaf(data: bytes) -> bytes:
    """Leaf hash with domain separator to prevent second-preimage."""
    return hashlib.sha3_256(b"\x00" + data).digest()


def _sha3_node(left: bytes, right: bytes) -> bytes:
    """Internal node hash."""
    return hashlib.sha3_256(b"\x01" + left + right).digest()


def _build_merkle_root(leaves: List[bytes]) -> bytes:
    """Build a binary Merkle root from a list of leaf hashes."""
    if not leaves:
        return hashlib.sha3_256(b"").digest()
    # pad to power of two
    nodes = list(leaves)
    while len(nodes) < _next_power_of_two(len(nodes)):
        nodes.append(nodes[-1])
    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes), 2):
            next_level.append(_sha3_node(nodes[i], nodes[i + 1]))
        nodes = next_level
    return nodes[0]


def _next_power_of_two(n: int) -> int:
    p = 1
    while p < n:
        p <<= 1
    return p


# ---------------------------------------------------------------------------
# LightClient
# ---------------------------------------------------------------------------
class LightClient:
    """
    Minimal verification client.

    Does **not** store blocks or full UTXO set — only headers and
    validator public keys needed to verify proofs.
    """

    def __init__(self, trusted_validators: Optional[List[bytes]] = None) -> None:
        """
        Args:
            trusted_validators: list of known validator pubkeys.
        """
        self.validators = trusted_validators or []
        self._header_cache: Dict[int, BlockHeader] = {}  # height → header
        logger.info("LightClient initialised with %s validator(s)", len(self.validators))

    # =================================================================
    # 1. Merkle proof verification (SPV)
    # =================================================================
    def verify_merkle_proof(
        self,
        tx_hash: bytes,
        block_header: BlockHeader,
        merkle_proof: List[Tuple[bytes, bool]],
    ) -> bool:
        """
        Verify that *tx_hash* is included in the block identified by
        *block_header.merkle_root_tx*.

        Args:
            tx_hash:      32-byte transaction hash.
            block_header:   block header containing merkle_root_tx.
            merkle_proof:   list of (sibling_hash, is_right_sibling) pairs
                            from leaf to root.  `is_right_sibling=True` means
                            the sibling is on the right of the current hash.

        Returns:
            True if the proof is valid.

        Raises:
            MerkleProofInvalidError: if proof is malformed.
        """
        if not merkle_proof:
            raise MerkleProofInvalidError("Empty merkle proof")

        current = _sha3_leaf(tx_hash)
        for sibling, is_right in merkle_proof:
            if len(sibling) != 32:
                raise MerkleProofInvalidError("Sibling hash must be 32 bytes")
            if is_right:
                current = _sha3_node(current, sibling)
            else:
                current = _sha3_node(sibling, current)

        if current == block_header.merkle_root_tx:
            logger.debug("Merkle proof valid for tx %s", tx_hash.hex()[:16])
            return True

        logger.warning("Merkle proof mismatch for tx %s", tx_hash.hex()[:16])
        return False

    # =================================================================
    # 2. State proof verification (Patricia-trie style)
    # =================================================================
    def verify_state_proof(
        self,
        account_state: AccountState,
        utxo_root: bytes,
        proof_path: List[Tuple[bytes, bool]],
    ) -> bool:
        """
        Verify that *account_state* exists in the state trie rooted at
        *utxo_root* following *proof_path*.

        Args:
            account_state:  the claimed account state.
            utxo_root:      32-byte root of the state trie.
            proof_path:     list of (node_hash, is_right_branch) pairs
                            from leaf to root.

        Returns:
            True if the proof validates.

        Raises:
            StateProofInvalidError: on structural issues.
        """
        if not proof_path:
            raise StateProofInvalidError("Empty proof path")

        # leaf hash = hash(serialized state)
        leaf_data = self._serialize_state(account_state)
        current = hashlib.sha3_256(b"\x02" + leaf_data).digest()

        for node_hash, is_right in proof_path:
            if is_right:
                current = _sha3_node(current, node_hash)
            else:
                current = _sha3_node(node_hash, current)

        if current == utxo_root:
            logger.debug("State proof valid for address %s", account_state.address.hex()[:16])
            return True

        logger.warning("State proof mismatch for address %s", account_state.address.hex()[:16])
        return False

    # =================================================================
    # 3. Header chain validation
    # =================================================================
    def validate_header_chain(self, headers: List[BlockHeader]) -> bool:
        """
        Validate a contiguous sequence of headers:
          • prev_hash linkage
          • height monotonicity (+1)
          • validator rotation correctness
          • signature presence (real code: ECDSA verify)

        Args:
            headers: oldest → newest.

        Returns:
            True if the chain is valid.
        """
        if not headers:
            return True

        prev_hash: Optional[bytes] = None
        expected_height: Optional[int] = None

        for idx, h in enumerate(headers):
            # height continuity
            if expected_height is not None and h.height != expected_height:
                logger.error(
                    "Header chain break at idx %s: expected height %s, got %s",
                    idx, expected_height, h.height,
                )
                return False
            expected_height = h.height + 1

            # prev_hash linkage
            if prev_hash is not None and h.prev_block_hash != prev_hash:
                logger.error(
                    "Header chain break at idx %s: prev_hash mismatch",
                    idx,
                )
                return False
            prev_hash = h.hash()

            # signature presence (stub)
            if h.height > 0 and len(h.signature) == 0:
                logger.error("Header at height %s missing signature", h.height)
                return False

            # validator rotation (PoA round-robin)
            if self.validators:
                expected_val = self.validators[h.height % len(self.validators)]
                if h.validator_pubkey != expected_val:
                    logger.error(
                        "Wrong validator at height %s (expected %s, got %s)",
                        h.height,
                        expected_val.hex()[:8],
                        h.validator_pubkey.hex()[:8] if h.validator_pubkey else "empty",
                    )
                    return False

        logger.info("Header chain valid: %s headers", len(headers))
        return True

    # =================================================================
    # Helpers
    # =================================================================
    @staticmethod
    def _serialize_state(state: AccountState) -> bytes:
        """Minimal deterministic serialization for state hashing."""
        return (
            state.address
            + state.n_balance.to_bytes(8, "big")
            + state.n_locked.to_bytes(8, "big")
            + state.n_available.to_bytes(8, "big")
            + state.identity_status.to_bytes(1, "big")
        )

    def add_header(self, header: BlockHeader) -> None:
        """Cache a header for future reference."""
        self._header_cache[header.height] = header

    def get_header(self, height: int) -> Optional[BlockHeader]:
        return self._header_cache.get(height)


# ===========================================================================
# Self-test
# ===========================================================================
def _build_proof_for_leaf(leaves: List[bytes], leaf_index: int) -> Tuple[bytes, List[Tuple[bytes, bool]]]:
    """
    Build a binary Merkle tree and return (root, proof_path) for *leaf_index*.
    Proof path contains (sibling_hash, is_right_sibling) pairs from leaf to root.
    """
    if not leaves:
        return hashlib.sha3_256(b"").digest(), []

    # Hash leaves first
    leaf_hashes = [_sha3_leaf(l) for l in leaves]

    # pad to power of two
    n = len(leaf_hashes)
    target = _next_power_of_two(n)
    padded = list(leaf_hashes)
    while len(padded) < target:
        padded.append(padded[-1])

    # store tree layers for proof extraction
    layers: List[List[bytes]] = [list(padded)]
    while len(layers[-1]) > 1:
        cur = layers[-1]
        nxt = []
        for i in range(0, len(cur), 2):
            nxt.append(_sha3_node(cur[i], cur[i + 1]))
        layers.append(nxt)

    root = layers[-1][0]

    # build proof
    proof: List[Tuple[bytes, bool]] = []
    idx = leaf_index
    for layer in layers[:-1]:
        sibling_idx = idx ^ 1  # flip lowest bit
        is_right = sibling_idx > idx  # sibling is on the right
        proof.append((layer[sibling_idx], is_right))
        idx //= 2

    return root, proof


def _self_test() -> None:
    print("\n=== light_client.py self-test ===")
    from _core_stubs import TxType, TxInput, TxOutput

    client = LightClient(trusted_validators=[b"\xab" * 32, b"\xcd" * 32])

    # --- Merkle proof ---
    tx = Transaction(
        tx_type=TxType.TRANSFER,
        inputs=[TxInput(tx_hash=b"\x11" * 32, output_index=0)],
        outputs=[TxOutput(amount=100, lock_script=b"\x00" * 20)],
    )
    tx_hash = tx.hash()

    leaves = [b"\xaa" * 32, tx_hash, b"\xbb" * 32, b"\xcc" * 32]
    root, proof = _build_proof_for_leaf(leaves, leaf_index=1)
    header = BlockHeader(merkle_root_tx=root, height=1, signature=b"sig")

    ok = client.verify_merkle_proof(tx_hash, header, proof)
    print(f"[MERKLE] verify={ok}")
    assert ok, "Merkle proof should validate"

    # --- Bad proof should fail ---
    bad_proof = [(b"\xde" * 32, True)] * len(proof)
    ok_bad = client.verify_merkle_proof(tx_hash, header, bad_proof)
    assert not ok_bad, "Bad proof should fail"
    print(f"[MERKLE_BAD] correctly rejected")

    # --- State proof ---
    state = AccountState(
        address=b"\x00" * 20,
        n_balance=1000,
        n_available=800,
        identity_status=2,
    )
    leaf = hashlib.sha3_256(b"\x02" + client._serialize_state(state)).digest()
    sibling = hashlib.sha3_256(b"\x02" + b"\xff" * 50).digest()
    root2 = _sha3_node(leaf, sibling)
    ok2 = client.verify_state_proof(state, root2, [(sibling, True)])
    print(f"[STATE] verify={ok2}")
    assert ok2, "State proof should validate"

    # wrong root should fail
    ok2_bad = client.verify_state_proof(state, b"\x00" * 32, [(sibling, True)])
    assert not ok2_bad, "Wrong root should fail"
    print(f"[STATE_BAD] correctly rejected")

    # --- Header chain ---
    h0 = BlockHeader(height=0, prev_block_hash=b"\x00" * 32, signature=b"", validator_pubkey=b"\xab" * 32)
    h1 = BlockHeader(height=1, prev_block_hash=h0.hash(), signature=b"sig1", validator_pubkey=b"\xcd" * 32)
    h2 = BlockHeader(height=2, prev_block_hash=h1.hash(), signature=b"sig2", validator_pubkey=b"\xab" * 32)
    ok3 = client.validate_header_chain([h0, h1, h2])
    print(f"[HEADER_CHAIN] valid={ok3}")
    assert ok3

    # --- Broken chain ---
    h_bad = BlockHeader(height=2, prev_block_hash=b"\x99" * 32, signature=b"sig2")
    ok4 = client.validate_header_chain([h0, h1, h_bad])
    assert not ok4
    print(f"[HEADER_CHAIN_BAD] correctly rejected broken chain")

    print("=== light_client.py self-test PASSED ===\n")


if __name__ == "__main__":
    _self_test()
