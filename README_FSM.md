# BCS Chain — Bidirectional Currency System Blockchain

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../LICENSE)

> A blockchain implementation for the **Bidirectional Currency System (BCS)**. The MVP settles only N-money ("being-needed") on-chain. The D side is represented by `external_amount` for φ/ψ calculation; bank, cash, gateway, invoice and payroll references are optional metadata.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
- [Docker Deployment](#docker-deployment)
- [API Documentation](#api-documentation)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [License](#license)

---

## Project Overview

**BCS Chain** implements a Proof-of-Authority BFT blockchain with the following characteristics:

- **UTXO-based ledger** with SHA3-256 hashing and secp256k1 signatures
- **PoA-BFT consensus** with round-robin proposers and 2/3 signature finality
- **φ/ψ currency rules** enforcing N settlement against external sale/wage amounts
- **DID + VC identity layer** with governance-authorized activation
- **Offline transaction support** with conflict resolution and optimistic UTXO views
- **Zero-knowledge privacy** primitives for shielded transactions
- **REST + gRPC APIs** for node operation, wallet integration, and light clients
- **P2P gossip network** over WebSockets with reputation-based peer management

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         BCS Node                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────┐   │
│  │ REST    │  │ gRPC    │  │ CLI     │  │ P2P Network │   │
│  │ 8080    │  │ 50051   │  │ bcs     │  │ 10001       │   │
│  └────┬────┘  └────┬────┘  └────┬────┘  └──────┬──────┘   │
│       └─────────────┴────────────┴──────────────┘          │
│                         │                                    │
│              ┌──────────┴──────────┐                         │
│              │    BCSNode Core     │                         │
│              │  (node.py)          │                         │
│              └──────────┬──────────┘                         │
│        ┌────────────────┼────────────────┐                  │
│        │                │                │                    │
│   ┌────┴────┐    ┌─────┴──────┐   ┌────┴─────┐             │
│   │ Core    │    │ Currency   │   │ Identity │             │
│   │ Block   │    │ Rules (φ/ψ)│   │ Registry │             │
│   │ Tx      │    │ Feasibility│   │ Trust    │             │
│   │ UTXO    │    │ Gov Params │   │ Anchor   │             │
│   │ Consensus│   │ N-Lifecycle│   │ DID/VC   │             │
│   │ Storage  │   └────────────┘   └──────────┘             │
│   └─────────┘                                              │
│        │                                                    │
│   ┌────┴──────────────────────────┐                       │
│   │ Offline  │  ZK   │  Wallet    │                       │
│   │ Sync     │  Prover│  Key Mgmt │                       │
│   │ Cache    │  Verif │  Balance  │                       │
│   └──────────┴────────┴───────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

### Module Reference

| Module | Purpose | Key Classes |
|--------|---------|------------|
| `core/` | Blockchain primitives | `Block`, `Transaction`, `UTXOSet`, `PoABFTConsensus`, `BlockStore` |
| `currency/` | Monetary policy | `CurrencyRulesEngine`, `SystemParameters`, `FeasibilityChecker` |
| `identity/` | DID / VC lifecycle | `IdentityRegistry`, `DIDDocument`, `TrustAnchor` |
| `offline/` | Offline support | `SyncEngine`, `TxCache`, `UTXOSyncView`, `ConflictResolver` |
| `zk/` | Zero-knowledge proofs | `ZKVerifier`, `Commitment`, `Prover` |
| `api/` | REST & gRPC servers | `create_app()`, `BCSGrpcServer` |
| `network/` | P2P layer | `P2PNode`, `PeerManager`, `Message` |
| `wallet/` | Key & balance management | `Wallet`, `TxCreator`, `OfflineMode` |
| `cli/` | Command-line interface | `bcs` command tree |

---

## Installation

### Prerequisites

- **Python 3.11+**
- **pip** or **poetry**
- **Docker** (optional, for containerized deployment)

### From Source

```bash
# Clone the repository
git clone https://github.com/example/bcs-chain.git
cd bcs-chain

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Or install as an editable package with test tooling from the repository root
pip install -e ".[dev]"

# Verify installation
python -m bcs_chain.core.block
python -m bcs_chain.core.transaction
python -m bcs_chain.currency.params
```

---

## Quick Start

### 1. Run a Single-Node Testnet

```bash
# Generate keys for the testnet validator
python -m bcs_chain.scripts.keygen --count 1 --output validator_keys.json

# Generate the genesis block
python -m bcs_chain.scripts.genesis_generator \
    --validators 1 \
    --network-id bcs-local \
    --output genesis.json

# Start the node with default config
python -m bcs_chain.node config/node.default.toml
```

The node will start:
- REST API on `http://localhost:8080`
- gRPC on `localhost:50051`
- P2P on `ws://localhost:10001`

### 2. Check Node Health

```bash
curl http://localhost:8080/health
```

Expected response:
```json
{
  "status": "ok",
  "version": "1.0.0",
  "height": 0,
  "peers": 0,
  "uptime_seconds": 12.345
}
```

### 3. Query Governance Parameters

```bash
curl http://localhost:8080/api/v1/governance/parameters
```

### 4. Submit a Transaction

```bash
curl -X POST http://localhost:8080/api/v1/tx \
  -H "Content-Type: application/json" \
  -d '{
    "tx": {
      "version": 1,
      "tx_type": 0,
      "inputs": [{"tx_hash": "a"*64, "output_index": 0, "unlock_script": ""}],
      "outputs": [{"amount": 1000, "lock_script": "76a9", "asset_type": 0, "metadata": ""}],
      "lock_time": 0,
      "extra": "",
      "witnesses": []
    }
  }'
```

### 5. Check Mempool

```bash
curl http://localhost:8080/api/v1/mempool
```

---

## CLI Usage

The `bcs` CLI provides wallet management, transaction creation, and node interaction.

```bash
# Show help
python -m bcs_chain.cli.main --help

# Create a wallet
python -m bcs_chain.cli.main wallet create --label "personal"

# List wallets
python -m bcs_chain.cli.main wallet list

# Check balance
python -m bcs_chain.cli.main balance --address <addr>

# Create a transfer transaction (offline)
python -m bcs_chain.cli.main tx transfer \
    --from <addr> \
    --to <addr> \
    --amount 1000000000 \
    --output tx.json

# Create a SALE transaction (coupled N+D)
python -m bcs_chain.cli.main tx sale \
    --from <seller> \
    --to <buyer> \
    --d-amount 5000 \
    --n-amount 150 \
    --output sale_tx.json

# Enable offline mode
python -m bcs_chain.cli.main offline enable

# Submit offline batch
python -m bcs_chain.cli.main offline submit --file batch.json
```

---

## Docker Deployment

### Development Testnet (4 nodes)

```bash
cd docker

# Build and start all services
docker-compose up --build

# View logs
docker-compose logs -f node1

# Scale observer nodes
docker-compose up -d --scale observer=2

# Stop everything
docker-compose down -v
```

Services exposed:
| Service | REST API | P2P |
|---------|----------|-----|
| node1 | http://localhost:8081 | ws://localhost:10001 |
| node2 | http://localhost:8082 | ws://localhost:10002 |
| node3 | http://localhost:8083 | ws://localhost:10003 |
| observer | http://localhost:8084 | ws://localhost:10004 |

### Production Deployment

```bash
# Build production image
docker-compose -f docker/docker-compose.prod.yml build

# Deploy
docker-compose -f docker/docker-compose.prod.yml up -d

# View status
docker-compose -f docker/docker-compose.prod.yml ps

# Rolling update
docker-compose -f docker/docker-compose.prod.yml build --no-cache
docker-compose -f docker/docker-compose.prod.yml up -d
```

### Single Node (Docker)

```bash
docker build -f docker/Dockerfile.node -t bcs-node .
docker run -d \
    -p 8080:8080 \
    -p 10001:10001 \
    -p 50051:50051 \
    -v bcs-data:/data/bcs \
    bcs-node
```

### Client Container

```bash
docker build -f docker/Dockerfile.client -t bcs-client .
docker run -it bcs-client wallet create --label "docker_wallet"
```

---

## API Documentation

### REST Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Node health status |
| `POST` | `/api/v1/tx` | Submit transaction |
| `GET` | `/api/v1/tx/{hash}` | Get transaction by hash |
| `GET` | `/api/v1/tx/{hash}/status` | Transaction status |
| `GET` | `/api/v1/block/{height}` | Get block by height |
| `GET` | `/api/v1/block/latest` | Get latest block |
| `GET` | `/api/v1/account/{addr}/balance` | Account balance |
| `GET` | `/api/v1/account/{addr}/utxos` | Account UTXOs |
| `GET` | `/api/v1/mempool` | Mempool info |
| `POST` | `/api/v1/offline/prepare` | Prepare offline package |
| `POST` | `/api/v1/offline/submit-batch` | Submit offline batch |
| `POST` | `/api/v1/offline/conflicts` | Check conflicts |
| `POST` | `/api/v1/identity/register` | Register DID |
| `GET` | `/api/v1/identity/{did}/status` | DID status |
| `GET` | `/api/v1/governance/parameters` | System parameters |
| `POST` | `/api/v1/zk/shield` | Shielded transaction |

### Interactive API Docs

When the REST server is running, visit:
- **Swagger UI**: `http://localhost:8080/docs`
- **ReDoc**: `http://localhost:8080/redoc`
- **OpenAPI JSON**: `http://localhost:8080/openapi.json`

### gRPC Service

The gRPC server exposes `NodeService` with methods for block streaming, UTXO snapshots, and transaction submission.

```protobuf
service NodeService {
  rpc GetBlock(GetBlockRequest) returns (Block);
  rpc GetLatestBlock(Empty) returns (Block);
  rpc GetBalance(GetBalanceRequest) returns (GetBalanceResponse);
  rpc SubmitTx(Transaction) returns (TxReceipt);
  rpc SyncBlocks(SyncBlocksRequest) returns (stream BlockChunk);
  rpc SyncUTXOSnapshot(Empty) returns (stream UTXOSnapshotChunk);
}
```

---

## Testing

### Run All Module Self-Tests

```bash
# Core modules
python -m bcs_chain.core.block
python -m bcs_chain.core.transaction
python -m bcs_chain.core.validator
python -m bcs_chain.core.consensus
python -m bcs_chain.core.storage
python -m bcs_chain.core.mempool

# Currency modules
python -m bcs_chain.currency.params
python -m bcs_chain.currency.rules_engine

# Identity
python -m bcs_chain.identity.registry

# Network
python -m bcs_chain.network.p2p
python -m bcs_chain.network.messages

# Offline
python -m bcs_chain.offline.sync

# API
python -m bcs_chain.api.rest_server
python -m bcs_chain.api.grpc_server
```

### Run pytest Suite

```bash
python -m pytest bcs_chain/tests -v --tb=short
```

### Integration Test (Docker)

```bash
cd docker
docker-compose up -d

# Wait for healthchecks, then test
curl -sf http://localhost:8081/health
curl -sf http://localhost:8082/health
curl -sf http://localhost:8083/health

# Submit a transaction through the gateway
curl -X POST http://localhost/api/v1/tx \
  -H "Content-Type: application/json" \
  -d '{"tx": {"version": 1, "tx_type": 0, "inputs": [], "outputs": [{"amount": 100, "lock_script": "76a9", "asset_type": 0, "metadata": ""}], "lock_time": 0, "extra": "", "witnesses": []}}'

docker-compose down
```

---

## Project Structure

```
bcs_chain/
├── __init__.py              # Package entry point
├── node.py                  # Main BCSNode runtime
│
├── core/                    # Blockchain core
│   ├── __init__.py
│   ├── block.py             # Block, BlockHeader, BlockBody
│   ├── transaction.py       # Transaction, TxInput, TxOutput, TxType
│   ├── utxo.py              # UTXO, UTXOSet, PatriciaTrie
│   ├── state.py             # AccountState, StateManager
│   ├── script.py            # ScriptEngine, StandardScripts
│   ├── validator.py         # TxValidator, BlockValidator
│   ├── mempool.py           # Mempool, MempoolEntry
│   ├── consensus.py         # PoABFTConsensus, ValidatorSet
│   └── storage.py           # BlockStore, IndexStore
│
├── currency/                # Monetary policy
│   ├── __init__.py
│   ├── params.py            # SystemParameters, GovernanceParams
│   ├── rules_engine.py      # CurrencyRulesEngine (φ/ψ)
│   ├── feasibility.py       # FeasibilityChecker
│   └── n_lifecycle.py       # NLifecycleTracker
│
├── identity/                # Identity management
│   ├── __init__.py
│   ├── did.py               # DIDDocument
│   ├── vc.py                # VerifiableCredential
│   ├── registry.py          # IdentityRegistry (SQLite)
│   ├── trust_anchor.py      # TrustAnchor
│   └── auth.py              # Authentication helpers
│
├── offline/                 # Offline operation
│   ├── __init__.py
│   ├── tx_builder.py        # OfflineTxBuilder
│   ├── cache.py             # TxCache
│   ├── sync.py              # SyncEngine (6-phase catch-up)
│   ├── conflict_resolver.py # ConflictResolver
│   ├── utxo_view.py         # UTXOSyncView
│   ├── light_client.py      # LightClient
│   └── _core_stubs.py       # Type stubs for standalone testing
│
├── zk/                      # Zero-knowledge proofs
│   ├── __init__.py
│   ├── commitment.py        # PedersenCommitment
│   ├── circuits.py          # Circuit definitions
│   ├── prover.py            # ZKProver
│   └── verifier.py          # ZKVerifier
│
├── api/                     # API servers
│   ├── __init__.py
│   ├── rest_server.py       # FastAPI REST application
│   ├── grpc_server.py       # gRPC service wrapper
│   ├── schemas.py           # Pydantic models
│   └── middleware.py        # ASGI middleware stack
│
├── network/                 # P2P networking
│   ├── __init__.py
│   ├── messages.py          # Wire protocol messages
│   └── p2p.py               # Async P2P node
│
├── wallet/                  # Wallet functionality
│   ├── __init__.py
│   ├── wallet.py            # Key management & encryption
│   ├── tx_creator.py        # Transaction builder
│   ├── balance.py           # Balance tracker
│   ├── offline_mode.py      # Offline wallet mode
│   └── exporter.py          # Key export utilities
│
├── cli/                     # Command-line interface
│   ├── __init__.py
│   └── main.py              # Click-based CLI
│
├── scripts/                 # Utility scripts
│   ├── genesis_generator.py # Genesis block generator
│   └── keygen.py            # Key & DID generator
│
├── config/                  # Configuration files
│   ├── node.default.toml    # Default node config
│   └── testnet/             # Testnet validator configs
│       ├── node1.toml
│       ├── node2.toml
│       └── node3.toml
│
├── docker/                  # Container orchestration
│   ├── Dockerfile.node      # Node image
│   ├── Dockerfile.client    # Client image
│   ├── docker-compose.yml   # Dev 4-node testnet
│   └── docker-compose.prod.yml  # Production config
│
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

---

## Configuration

### Node Configuration (TOML)

```toml
[network]
listen_host = "0.0.0.0"
p2p_port = 10001
rest_port = 8080
grpc_port = 50051
bootstrap_peers = ["peer1:10001", "peer2:10001"]
network_id = "bcs-mainnet"

[consensus]
block_interval_ms = 5000
validator_id = 0
validator_pubkey_hex = "0495a2f0..."
validator_privkey_hex = "deadbeef..."
validator_name = "validator-0"

[storage]
data_dir = "/data/bcs"
db_name = "bcs_chain.db"

[governance]
phi_numerator = 3
phi_denominator = 100
psi_numerator = 5
psi_denominator = 100
required_gov_signatures = 2
n_lower_bound = 0
n_upper_bound = 10_000_000_000_000

[api]
enable_rest = true
enable_grpc = true
cors_origins = ["*"]
rate_limit_rps = 100
```

---

## Economic Parameters

| Parameter | Symbol | Default | Description |
|-----------|--------|---------|-------------|
| Seller rebate | φ | 3/100 (3%) | Minimum N seller must transfer to buyer |
| Wage rebate | ψ | 5/100 (5%) | Minimum N worker must transfer to employer |
| Block interval | — | 5,000 ms | Target time between blocks |
| Governance sigs | — | 2 | Required signatures for MINT / parameter changes |
| N lower bound | — | 0 | Minimum N balance in circulation |
| N upper bound | — | 10 T nanoN | Maximum N supply ceiling |

---

## Security Notes

- **Private keys** in TOML configs should be rotated and stored in secrets management for production.
- **Validator keys** should never leave the validator host.
- **gRPC** and **REST** endpoints should be behind TLS in production (see `docker-compose.prod.yml` nginx config).
- **Governance** parameter changes require on-chain multi-sig approval.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Run tests (`pytest tests/ -v`)
4. Commit changes (`git commit -am 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing`)
6. Open a Pull Request

---

## License

MIT License — see [LICENSE](../LICENSE) for details.

---

## Contact

For questions or support, please open an issue on GitHub or contact the BCS team.
