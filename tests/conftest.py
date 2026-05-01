import os
import sys
import pytest
import asyncio
import tempfile
import sqlite3
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass, field

# Ensure bcs_chain modules are importable
_bcs_chain_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# Parent dir must come FIRST so packages are found before individual modules
if _bcs_chain_root not in sys.path:
    sys.path.insert(0, _bcs_chain_root)
_subdirs = ["core", "currency", "offline", "identity", "zk", "api", "wallet", "network", "cli"]
for _d in [os.path.join(_bcs_chain_root, s) for s in _subdirs]:
    if _d not in sys.path:
        sys.path.append(_d)  # append so parent dir takes precedence

from ecdsa import SigningKey, VerifyingKey, SECP256k1

# Core imports
from block import Block, BlockHeader, BlockBody, compute_merkle_root
from transaction import Transaction, TxInput, TxOutput, TxType, ZKProof
from storage import BlockStore, IndexStore
from utxo import UTXO, UTXOSet
from state import AccountState, IdentityStatus, StateManager

# Currency imports
from params import SystemParameters, GovernanceParams
from rules_engine import CurrencyRulesEngine, ValidationResult
from feasibility import NFeasibilityEngine, FeasibilityResult, SaleUsageRecord

# Offline imports
from cache import TxCache, TxStatus, CachedTx
from sync import SyncEngine, SyncResult, RejectedTx, PeerClient
from tx_builder import OfflineTxBuilder
from _core_stubs import UTXOSet as StubUTXOSet, Block as StubBlock, BlockHeader as StubBlockHeader

# Identity imports
from did import DIDManager, DIDDocument, VerificationMethod
from vc import VCManager, VerifiableCredential, CredentialSubject, CredentialProof
from auth import AuthEngine, Permission
from registry import IdentityRegistry, IdentityStatus as RegIdentityStatus
from trust_anchor import TrustAnchorRegistry, TrustAnchor

# ZK imports
from commitment import PedersenCommitment, NullifierGenerator, Commitment, _random_scalar
from prover import ZKProver, ZKProof as ZKProverProof
from verifier import ZKVerifier, NullifierSet
from circuits import NTransferCircuit, RatioVerifyCircuit, IdentityBindCircuit, UTXO as ZKUTXO, Output as ZKOutput

# API imports
from api.rest_server import create_app, NodeAppState, _app_state as app_state
from api.schemas import (
    SubmitTxRequest, SubmitTxResponse, GetBalanceRequest, GetBalanceResponse,
    OfflinePrepareRequest, OfflinePrepareResponse,
    RegisterDIDRequest, RegisterDIDResponse,
    SystemParametersSchema,
)

# Wallet imports
from wallet.wallet import Wallet


# =============================================================================
# Event loop fixture
# =============================================================================
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# =============================================================================
# Storage fixtures
# =============================================================================
@pytest.fixture
def temp_storage():
    """Provide a temporary SQLite-based block and index store."""
    bs = BlockStore(":memory:")
    ix = IndexStore(":memory:")
    yield {"block_store": bs, "index_store": ix}
    bs.close()
    ix.close()


@pytest.fixture
def temp_wallet_db():
    """Provide a temporary wallet database path."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        path = tmp.name
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


# =============================================================================
# Genesis block fixture
# =============================================================================
@pytest.fixture
def genesis_block():
    """Create a valid genesis block."""
    header = BlockHeader(
        version=1,
        prev_block_hash="0" * 64,
        merkle_root_tx="0" * 64,
        merkle_root_utxo="0" * 64,
        merkle_root_identity="0" * 64,
        timestamp=1609459200000,  # 2021-01-01 00:00:00 UTC
        height=0,
        tx_count=0,
        validator_pubkey="",
        signature="",
        extra_data=b"",
    )
    return Block(header=header, body=BlockBody(transactions=[]))


# =============================================================================
# Validator keys fixture
# =============================================================================
@pytest.fixture
def validator_keys() -> List[Tuple[bytes, bytes]]:
    """Generate 3 validator key pairs (priv, pub compressed)."""
    keys = []
    for _ in range(3):
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.get_verifying_key()
        pubkey = vk.to_string("compressed")
        keys.append((sk.to_string(), pubkey))
    return keys


# =============================================================================
# Sample wallet fixture
# =============================================================================
@pytest.fixture
def sample_wallet(temp_wallet_db):
    """Create a pre-configured wallet with 2 addresses."""
    wallet = Wallet(temp_wallet_db)
    wallet.init_database()
    password = "test_password_123"
    addr1 = wallet.create_new(label="test-account-a", password=password)
    addr2 = wallet.create_new(label="test-account-b", password=password)
    return {
        "wallet": wallet,
        "password": password,
        "addresses": [addr1, addr2],
    }


# =============================================================================
# Mock node fixture
# =============================================================================
@pytest.fixture
def mock_node(genesis_block, validator_keys):
    """Create a lightweight mock node with basic chain state."""

    class MockNode:
        def __init__(self):
            self.block_store = BlockStore(":memory:")
            self.index_store = IndexStore(":memory:")
            self.utxo_set = UTXOSet()
            self.state_manager = StateManager()
            self.mempool = []
            self.validator_keys = validator_keys
            self.governance = GovernanceParams()
            self.rules_engine = CurrencyRulesEngine(governance=self.governance)
            self.feasibility_engine = NFeasibilityEngine(current_height=0)
            self.params = SystemParameters()
            self.chain: List[Block] = [genesis_block]
            self.block_store.save_block(genesis_block)
            self.height = 0

        def create_block(self, transactions: List[Transaction], validator_index: int = 0) -> Block:
            """Create and link a new block."""
            prev = self.chain[-1]
            priv, pub = self.validator_keys[validator_index]
            vk = VerifyingKey.from_string(pub, curve=SECP256k1)

            header = BlockHeader(
                version=1,
                prev_block_hash=prev.hash,
                merkle_root_tx=compute_merkle_root([tx.hash() for tx in transactions]) if transactions else "0" * 64,
                merkle_root_utxo=self.utxo_set.merkle_root,
                merkle_root_identity="0" * 64,
                timestamp=prev.header.timestamp + self.params.block_interval_ms,
                height=prev.header.height + 1,
                tx_count=len(transactions),
                validator_pubkey=pub.hex(),
                signature="",
            )
            # Sign header
            sig = SigningKey.from_string(priv, curve=SECP256k1).sign_digest(
                header.signing_hash(), sigencode=lambda r, s, order: __import__("ecdsa").util.sigencode_der(r, s, order)
            )
            header.signature = sig.hex()

            block = Block(header=header, body=BlockBody(transactions=transactions))
            self.chain.append(block)
            self.block_store.save_block(block)
            self.height = block.header.height
            self.utxo_set.apply_block(block)
            return block

        def get_balance(self, address: str) -> int:
            utxos = self.utxo_set.get_by_address(address)
            return sum(u.amount for u in utxos)

        def mint_to(self, address: str, amount: int, gov_index: int = 0) -> Transaction:
            """Create a MINT transaction to an address."""
            gov_priv, gov_pub = self.validator_keys[gov_index]
            # Build lock script for address
            lock_script = b"\x76\xa9\x14" + bytes.fromhex(address[:40] if len(address) >= 40 else address.ljust(40, "0")) + b"\x88\xac"
            tx = Transaction(
                version=1,
                tx_type=TxType.MINT,
                inputs=[],
                outputs=[TxOutput(amount=amount, lock_script=lock_script)],
                witnesses=[b"gov_sig_1", b"gov_sig_2"],
            )
            return tx

        def close(self):
            self.block_store.close()
            self.index_store.close()

    node = MockNode()
    yield node
    node.close()


# =============================================================================
# DID / Identity fixtures
# =============================================================================
@pytest.fixture
def sample_dids():
    """Create a set of sample DIDs with their managers."""
    mgr = DIDManager()
    keys = []
    dids = []
    for i in range(4):
        priv, pub = mgr.generate_keypair()
        did = mgr.create_did(priv)
        doc = mgr.create_did_document(did, pub)
        keys.append((priv, pub))
        dids.append({"did": did, "doc": doc, "priv": priv, "pub": pub, "mgr": mgr})
    return dids


# =============================================================================
# Currency params fixture
# =============================================================================
@pytest.fixture
def sample_params():
    """Return a set of test system parameters."""
    return SystemParameters(
        phi_numerator=3,
        phi_denominator=100,
        psi_numerator=5,
        psi_denominator=100,
        block_interval_ms=5000,
        max_block_size=1_048_576,
        max_tx_per_block=2000,
        min_n_mint=1_000_000_000,
        replenish_threshold=100_000_000_000,
        validators=("0xval1", "0xval2", "0xval3"),
        required_gov_signatures=2,
    )


# =============================================================================
# API app fixture
# =============================================================================
@pytest.fixture
def api_app():
    """Create a FastAPI test app with initialized state."""
    app = create_app(debug=True)
    # Reset global state for tests
    app_state.mempool = None
    app_state.params = SystemParameters()
    app_state.blockchain = None
    app_state.utxo_manager = None
    app_state.identity_registry = None
    return app
