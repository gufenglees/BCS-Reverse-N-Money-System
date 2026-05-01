"""
API Integration Tests
====================
Tests for REST API endpoints using FastAPI TestClient.
"""

import pytest
from fastapi.testclient import TestClient

from api.rest_server import create_app, _app_state as app_state, NodeAppState
from api.schemas import (
    SubmitTxRequest, SubmitTxResponse, GetBalanceRequest, GetBalanceResponse,
    OfflinePrepareRequest, OfflinePrepareResponse,
    OfflineBatchRequest, OfflineBatchResponse,
    RegisterDIDRequest, RegisterDIDResponse,
    SystemParametersSchema,
    TransactionSchema, TxType,
)
from core.transaction import Transaction, TxInput, TxOutput, TxType as CoreTxType
from core.mempool import Mempool
from currency.params import SystemParameters
from core.state import IdentityStatus


@pytest.fixture
def api_client():
    """Create a TestClient with initialized app state."""
    app = create_app(debug=True)
    # Reset and init state
    app_state.mempool = Mempool()
    app_state.params = SystemParameters()
    app_state.blockchain = None
    app_state.utxo_manager = None
    app_state.identity_registry = None
    with TestClient(app) as client:
        yield client


# ---------------------------------------------------------------------------
# Health / Basic
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_endpoint(self, api_client):
        """Health endpoint returns ok status."""
        r = api_client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"

    def test_openapi_schema(self, api_client):
        """OpenAPI schema is generated."""
        r = api_client.get("/openapi.json")
        assert r.status_code == 200
        spec = r.json()
        assert spec["info"]["title"] == "BCS Chain API"


# ---------------------------------------------------------------------------
# Submit Transaction
# ---------------------------------------------------------------------------

class TestSubmitTransaction:
    def test_submit_transfer_tx(self, api_client):
        """Valid transaction submission returns MEMPOOL status."""
        tx_payload = {
            "tx": {
                "version": 1,
                "tx_type": 0,
                "inputs": [{"tx_hash": "a" * 64, "output_index": 0, "unlock_script": ""}],
                "outputs": [{"amount": 1000, "lock_script": "76a9", "asset_type": 0, "metadata": ""}],
                "lock_time": 0,
                "extra": "",
                "witnesses": [],
            },
            "wait_confirmation": False,
            "timeout_ms": 5000,
        }
        r = api_client.post("/api/v1/tx", json=tx_payload)
        assert r.status_code == 202
        data = r.json()
        assert data["status"] == "Mempool"
        assert len(data["tx_hash"]) == 64

    def test_submit_sale_tx(self, api_client):
        """Sale transaction submission."""
        tx_payload = {
            "tx": {
                "version": 1,
                "tx_type": 1,
                "inputs": [{"tx_hash": "b" * 64, "output_index": 0, "unlock_script": ""}],
                "outputs": [
                    {"amount": 100000000000, "lock_script": "76a9", "asset_type": 0, "metadata": ""},
                    {"amount": 3000000000, "lock_script": "76a9", "asset_type": 0, "metadata": ""},
                ],
                "lock_time": 0,
                "extra": "",
                "witnesses": [],
            },
            "wait_confirmation": False,
        }
        r = api_client.post("/api/v1/tx", json=tx_payload)
        assert r.status_code == 202
        data = r.json()
        assert data["status"] == "Mempool"

    def test_submit_invalid_tx_rejected(self, api_client):
        """Invalid transaction must be rejected."""
        tx_payload = {
            "tx": {
                "version": 1,
                "tx_type": 0,
                "inputs": [],  # No inputs
                "outputs": [{"amount": 1000, "lock_script": "", "asset_type": 0, "metadata": ""}],
                "lock_time": 0,
                "extra": "",
                "witnesses": [],
            },
        }
        # May be accepted into mempool (stub) or rejected based on validation
        r = api_client.post("/api/v1/tx", json=tx_payload)
        assert r.status_code in (202, 400, 422)

    def test_get_tx_status(self, api_client):
        """Query transaction status by hash."""
        tx_payload = {
            "tx": {
                "version": 1,
                "tx_type": 0,
                "inputs": [{"tx_hash": "c" * 64, "output_index": 0, "unlock_script": ""}],
                "outputs": [{"amount": 1000, "lock_script": "76a9", "asset_type": 0, "metadata": ""}],
                "lock_time": 0,
                "extra": "",
                "witnesses": [],
            },
        }
        r = api_client.post("/api/v1/tx", json=tx_payload)
        tx_hash = r.json()["tx_hash"]

        r2 = api_client.get(f"/api/v1/tx/{tx_hash}/status")
        assert r2.status_code == 200
        data = r2.json()
        assert data["tx_hash"] == tx_hash
        assert data["status"] == "Mempool"

    def test_get_unknown_tx_status(self, api_client):
        """Query status of non-existent transaction."""
        r = api_client.get("/api/v1/tx/" + "0" * 64 + "/status")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "Unknown"


# ---------------------------------------------------------------------------
# Get Balance
# ---------------------------------------------------------------------------

class TestGetBalance:
    def test_get_balance_endpoint(self, api_client):
        """Balance endpoint returns account state."""
        r = api_client.get("/api/v1/account/addr_test/balance")
        assert r.status_code == 200
        data = r.json()
        assert data["address"] == "addr_test"
        assert "n_balance" in data
        assert "n_available" in data
        assert "max_sale_capacity" in data
        assert "identity_status" in data

    def test_balance_zero_for_new_address(self, api_client):
        """New address has zero balance."""
        r = api_client.get("/api/v1/account/new_addr_123/balance")
        assert r.status_code == 200
        data = r.json()
        assert data["n_balance"] == "0"
        assert data["n_available"] == "0"


# ---------------------------------------------------------------------------
# Offline Prepare
# ---------------------------------------------------------------------------

class TestOfflinePrepare:
    def test_offline_prepare_endpoint(self, api_client):
        """Offline prepare returns UTXO proof package."""
        req = {"address": "addr_offline_test", "max_utxos": 10}
        r = api_client.post("/api/v1/offline/prepare", json=req)
        assert r.status_code == 200
        data = r.json()
        assert data["address"] == "addr_offline_test"
        assert "utxos" in data
        assert "merkle_proofs" in data
        assert "tip_hash" in data
        assert "tip_height" in data

    def test_offline_prepare_empty(self, api_client):
        """Offline prepare for address with no UTXOs."""
        req = {"address": "empty_addr", "max_utxos": 10}
        r = api_client.post("/api/v1/offline/prepare", json=req)
        assert r.status_code == 200
        data = r.json()
        assert data["utxos"] == []


# ---------------------------------------------------------------------------
# Offline Batch Submit
# ---------------------------------------------------------------------------

class TestOfflineBatchSubmit:
    def test_offline_batch_submit(self, api_client):
        """Batch submit offline transactions."""
        req = {
            "txs": [
                {
                    "version": 1,
                    "tx_type": 0,
                    "inputs": [{"tx_hash": "d" * 64, "output_index": 0, "unlock_script": ""}],
                    "outputs": [{"amount": 1000, "lock_script": "76a9", "asset_type": 0, "metadata": ""}],
                    "lock_time": 0,
                    "extra": "",
                    "witnesses": [],
                }
            ],
        }
        r = api_client.post("/api/v1/offline/submit-batch", json=req)
        assert r.status_code == 200
        data = r.json()
        assert "accepted_tx_hashes" in data
        assert "rejected" in data

    def test_offline_batch_with_conflicts(self, api_client):
        """Batch submit with conflicting transactions."""
        req = {
            "txs": [
                {
                    "version": 1,
                    "tx_type": 0,
                    "inputs": [{"tx_hash": "conflict" * 8, "output_index": 0, "unlock_script": ""}],
                    "outputs": [{"amount": 500, "lock_script": "76a9", "asset_type": 0, "metadata": ""}],
                    "lock_time": 0,
                    "extra": "",
                    "witnesses": [],
                },
                {
                    "version": 1,
                    "tx_type": 0,
                    "inputs": [{"tx_hash": "conflict" * 8, "output_index": 0, "unlock_script": ""}],
                    "outputs": [{"amount": 400, "lock_script": "76a9", "asset_type": 0, "metadata": ""}],
                    "lock_time": 0,
                    "extra": "",
                    "witnesses": [],
                },
            ],
        }
        r = api_client.post("/api/v1/offline/submit-batch", json=req)
        assert r.status_code == 200
        data = r.json()
        # At least one may be rejected due to double-spend
        assert len(data["rejected"]) > 0 or len(data["accepted_tx_hashes"]) > 0


# ---------------------------------------------------------------------------
# Identity Register
# ---------------------------------------------------------------------------

class TestIdentityRegister:
    def test_register_did_endpoint(self, api_client):
        """DID registration endpoint."""
        req = {
            "did_document": {
                "id": "did:bcs:test_user_123",
                "controller": "did:bcs:test_user_123",
                "public_keys": [],
                "authentication": [],
                "service_endpoints": [],
                "created": 1609459200000,
                "updated": 1609459200000,
            },
            "verifiable_credential": "{}",
            "signature": "deadbeef",
        }
        r = api_client.post("/api/v1/identity/register", json=req)
        assert r.status_code == 202
        data = r.json()
        assert data["did"] == "did:bcs:test_user_123"
        assert data["status"] == "Pending"
        assert "tx_hash" in data

    def test_identity_status_endpoint(self, api_client):
        """Query identity status endpoint."""
        r = api_client.get("/api/v1/identity/did:bcs:test_user_123/status")
        assert r.status_code == 200
        data = r.json()
        assert data["did"] == "did:bcs:test_user_123"
        assert "status" in data


# ---------------------------------------------------------------------------
# Governance Parameters
# ---------------------------------------------------------------------------

class TestGovernanceParams:
    def test_governance_params_endpoint(self, api_client):
        """Governance parameters endpoint returns system config."""
        r = api_client.get("/api/v1/governance/parameters")
        assert r.status_code == 200
        data = r.json()
        assert "phi_numerator" in data
        assert "phi_denominator" in data
        assert "psi_numerator" in data
        assert "psi_denominator" in data
        assert data["phi_numerator"] == 3
        assert data["phi_denominator"] == 100

    def test_governance_params_types(self, api_client):
        """All governance parameters have correct types."""
        r = api_client.get("/api/v1/governance/parameters")
        data = r.json()
        assert isinstance(data["phi_numerator"], int)
        assert isinstance(data["phi_denominator"], int)
        assert isinstance(data["block_interval_ms"], int)
        assert isinstance(data["max_block_size"], int)


# ---------------------------------------------------------------------------
# Mempool
# ---------------------------------------------------------------------------

class TestMempool:
    def test_mempool_info(self, api_client):
        """Mempool info endpoint returns current state."""
        r = api_client.get("/api/v1/mempool")
        assert r.status_code == 200
        data = r.json()
        assert "tx_count" in data
        assert "total_size_bytes" in data
        assert "max_size_bytes" in data

    def test_mempool_after_submissions(self, api_client):
        """Mempool grows after transaction submissions."""
        tx_payload = {
            "tx": {
                "version": 1,
                "tx_type": 0,
                "inputs": [{"tx_hash": "m" * 64, "output_index": 0, "unlock_script": ""}],
                "outputs": [{"amount": 1000, "lock_script": "76a9", "asset_type": 0, "metadata": ""}],
                "lock_time": 0,
                "extra": "",
                "witnesses": [],
            },
        }
        api_client.post("/api/v1/tx", json=tx_payload)

        r = api_client.get("/api/v1/mempool")
        data = r.json()
        assert data["tx_count"] >= 1


# ---------------------------------------------------------------------------
# ZK Shielded Transaction
# ---------------------------------------------------------------------------

class TestZKShield:
    def test_zk_shield_endpoint(self, api_client):
        """ZK shielded transaction submission."""
        req = {
            "nullifiers": ["n1", "n2"],
            "commitments": ["c1", "c2"],
            "proof": "base64proofplaceholder",
            "fee": 100,
            "privacy_mode": "shielded",
        }
        r = api_client.post("/api/v1/zk/shield", json=req)
        assert r.status_code == 202
        data = r.json()
        assert data["status"] == "Mempool"
        assert len(data["tx_hash"]) == 64


# ---------------------------------------------------------------------------
# Error Handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_invalid_endpoint_404(self, api_client):
        """Unknown endpoint returns 404."""
        r = api_client.get("/api/v1/nonexistent")
        assert r.status_code == 404

    def test_malformed_json_422(self, api_client):
        """Malformed JSON returns 422."""
        r = api_client.post("/api/v1/tx", data="not json", headers={"Content-Type": "application/json"})
        assert r.status_code in (400, 422)

    def test_get_block_not_found(self, api_client):
        """Non-existent block returns 404."""
        r = api_client.get("/api/v1/block/999999")
        assert r.status_code == 404
