# BCS (Bidirectional Currency System) — 完整技术架构设计

> **版本**: v1.0  
> **日期**: 2024  
> **目标**: 为基于论文《Bidirectional Currency System (BCS)》的逆向货币系统提供可直接工程化落地的完整技术蓝图。  
> **核心约束**: 离线优先、轻量级区块链、PoA 共识、UTXO 模型、零知识可选隐私、DID 身份认证。

---

## 目录

1. [系统概述与架构全景图](#1-系统概述与架构全景图)
2. [核心模块定义](#2-核心模块定义)
3. [数据模型](#3-数据模型)
4. [API 接口定义](#4-api-接口定义)
5. [技术栈与文件结构](#5-技术栈与文件结构)
6. [关键算法设计](#6-关键算法设计)
7. [部署架构](#7-部署架构)
8. [安全与隐私策略](#8-安全与隐私策略)
9. [第一阶段里程碑 (MVP)](#9-第一阶段里程碑-mvp)
10. [附录：核心代码骨架](#10-附录核心代码骨架)
11. [项目审计与优化清单](#11-项目审计与优化清单)

---

## 1. 系统概述与架构全景图

### 1.1 BCS 业务规则映射

| 论文概念 | 系统实现 |
|---------|---------|
| 外部支付金额 (原 D 侧) | MVP 不发行链上 D；链上必须记录 `external_amount` 用于验证 φ/ψ。现实货币/银行/现金/支付网关/发票/工资单只是可选外部凭证引用，非强制协议字段 |
| N 货币 (Being-Needed Money) | 唯一链上原生资产，UTXO 模型，可精确追踪流转 |
| 销售规则 (φ) | 交易类型 `TRANSFER_SALE`: 卖家输出必须包含 N 转移给买家，比例 φ × external_amount；支付凭证引用可选 |
| 工资规则 (ψ) | 交易类型 `TRANSFER_WAGE`: 工人输出必须包含 N 转移给雇主，比例 ψ × external_amount；工资单/流水引用可选 |
| N 可行性约束 | 账户状态中的 `available_n_limit` 字段，由 UTXO 中的 N 余额推导 |
| N 发放/补充 | 交易类型 `MINT` (初始化) 和 `REPLENISH` (后续补充)，需 DID 认证 + 治理签名 |

### 1.2 架构图

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                BCS Node / Client                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │   Wallet /   │  │   Identity   │  │   Offline    │  │   ZK (Privacy)       │ │
│  │   Client UI  │  │   Module     │  │   Module     │  │   ├─ Prover         │ │
│  │   (CLI/REST) │  │   (DID/Vc)   │  │   (Tx Cache  │  │   ├─ Verifier       │ │
│  │              │  │              │  │   + Sync)    │  │   └─ Circuit Builder  │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘ │
│         │                 │                 │                     │              │
│         ▼                 ▼                 ▼                     ▼              │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │                        Currency Module (N/D Logic)                        │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │  │
│  │  │  N Issuance  │  │  N Transfer  │  │  φ/ψ Rules   │  │  Limit Check │  │  │
│  │  │  (Mint/Repl) │  │  (UTXO)      │  │  Enforcer    │  │  (Feasibility│  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │  │
│  └─────────────────────────┬────────────────────────────────────────────────┘  │
│                            │                                                      │
│         ┌──────────────────┼──────────────────┐                                   │
│         ▼                  ▼                  ▼                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                          │
│  │  Blockchain  │  │  Consensus   │  │  Network /   │                          │
│  │  Core        │  │  (PoA +      │  │  P2P Sync    │                          │
│  │  (Blocks/    │  │  BFT-like)   │  │  (LibP2P)    │                          │
│  │  UTXO/State) │  │              │  │              │                          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                          │
│         │                 │                 │                                   │
│         ▼                 ▼                 ▼                                   │
│  ┌──────────────────────────────────────────────────────────────────────────┐    │
│  │                         Storage Layer                                     │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │    │
│  │  │  Block Store │  │  UTXO Set    │  │  Identity DB │  │  Offline Tx  │ │    │
│  │  │  (LevelDB/   │  │  (Merkle +   │  │  (DID Doc +  │  │  Pool (SQLite│ │    │
│  │  │  SQLite)     │  │  Patricia Trie│ │  Verifiable  │  │  / LMDB)     │ │    │
│  │  └──────────────┘  └──────────────┘  │  Credentials)│  └──────────────┘ │    │
│  │                                      └──────────────┘                   │    │
│  └──────────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 1.3 数据流

**在线 N 结算流 (Fast Path)**:
```
User A ──► Wallet ──► Currency Module ──► Blockchain Core ──► Network Broadcast
                    (validate φ/ψ)       (add to mempool)    (gossip to validators)
                                              │
                                              ▼
                                       Consensus (PoA)
                                              │
                                              ▼
                                       Block Commit ──► Storage
```

**离线支付流 (Slow Path)**:
```
User A (offline) ──► Wallet ──► Offline Module (create unsigned/partially signed tx)
                                        │
                                        ▼ (store in local SQLite)
                              Offline Tx Pool (with TTL, sequence numbers)
                                        │
     (reconnect) ──► Sync Protocol ─────┘
                                        │
                                        ▼
                              Conflict Resolution (DAG-based, see §6.3)
                                        │
                                        ▼
                              Merge to local UTXO view ──► Broadcast
```

---

## 2. 核心模块定义

### 2.1 Blockchain Core (`bcs_core/`)

**职责**: 区块生命周期、链状态、UTXO 集管理、Merkle/Patricia Trie 根计算。

**子组件**:

| 子组件 | 职责 | 接口 |
|-------|------|------|
| `BlockBuilder` | 从 mempool 选 tx 构建候选块 | `build_block(txs, prev_hash, timestamp) -> Block` |
| `BlockValidator` | 验证区块头、tx 列表、Merkle 根 | `validate_block(block) -> Result<(), ValidationError>` |
| `UTXOManager` | 维护未花费输出集，双花检测 | `get_utxos_for_address(addr) -> Vec<UTXO>` |
| `StateManager` | 维护账户派生状态 (N limit, nonce) | `get_account_state(addr) -> AccountState` |
| `Mempool` | 内存交易池，按 fee 排序 | `add_tx(tx) -> Result<TxHash, MempoolError>` |

**设计决策**:
- **UTXO 而非账户模型**: 选择 UTXO，因为 (1) 离线交易天然可并行验证，无需全局 nonce 顺序；(2) 支持同笔交易多输入多输出，方便实现 φ/ψ 多流向；(3) 与 BTC 类似，降低学习成本。
- 区块间隔: **5 秒** (轻量场景，无需挖矿)。
- 区块大小: 软上限 **1 MB** (~2000 笔简单 tx)。

### 2.2 Offline Module (`bcs_offline/`)

**职责**: 离线环境下创建交易、缓存、冲突检测、重连后批量同步。

**子组件**:

| 子组件 | 职责 | 接口 |
|-------|------|------|
| `OfflineTxBuilder` | 无网络时基于本地 UTXO 视图构建 tx | `create_offline_tx(inputs, outputs, rules) -> UnsignedTx` |
| `UTXOSyncView` | 本地维护的"乐观 UTXO 快照" | `apply_local_tx(tx)` / `revert_on_conflict()` |
| `TxCache` | SQLite 持久化未同步的 tx | `cache_tx(tx, expiry)` / `get_pending()` |
| `SyncEngine` | 重连后的同步与冲突解决 | `sync_with_peer(peer_utxo_set) -> SyncResult` |

**离线交易状态机**:
```
[Draft] --sign--> [SignedLocal] --cache--> [Cached] --sync attempt--> [PendingNetwork]
                                                    │
                                                    ├─ conflict detected ─► [Conflicted]
                                                    │                         │
                                                    │                         ▼
                                                    │                    [Resolved]
                                                    │                         │
                                                    └─────────────────────────┘
                                                              (retry)
```

### 2.3 ZK Module (`bcs_zk/`)

**职责**: 可选隐私保护。使用 zk-SNARKs (Groth16) 或 zk-STARKs (轻量级)。

**电路定义**:

| 电路 | 功能 | 输入 | 输出 |
|-----|------|------|------|
| `NTransferCircuit` | 证明 N 转移金额正确，不暴露具体数值 | 私钥、UTXO 见证、金额 | 公开: 新 commitment, nullifier |
| `RatioVerifyCircuit` | 证明 φ/ψ 比例合规 | 外部支付金额、N 金额、比例参数 | 公开: 布尔有效性 + range proof |
| `IdentityBindCircuit` | 证明 DID 控制私钥与交易签名关联 | DID document, 签名 | 公开: 有效/无效 |

**实现选择**:
- **默认**: 使用 `bellman` (Rust, Zcash) 或 `snarkjs` (JS，适配性更好)。
- **Python 端**: 使用 `py_ecc` 进行椭圆曲线运算，调用预编译的 Rust prover FFI。
- **隐私模式开关**: 每笔交易可标记 `privacy: public | shielded`。Public 走普通验证，Shielded 走 ZK 验证。

### 2.4 Identity Module (`bcs_identity/`)

**职责**: DID 解析、VC 验证、KYC/认证状态管理、权限控制。

**架构**:
```
┌─────────────────────────────────────────────┐
│           Identity Module                   │
├─────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────────────┐ │
│  │  DID Resolver│───►│  DID Document Store │ │
│  │  (方法注册表) │    │  (SQLite/JSON-LD)    │ │
│  └─────────────┘    └─────────────────────┘ │
│         │                                   │
│         ▼                                   │
│  ┌─────────────┐    ┌─────────────────────┐ │
│  │  VC Verifier │───►│  Trust Anchor Store  │ │
│  │  (签名/过期) │    │  (发行者公钥白名单)   │ │
│  └─────────────┘    └─────────────────────┘ │
│         │                                   │
│         ▼                                   │
│  ┌─────────────┐                            │
│  │  Auth Engine│───► 权限判断: N-Mint 资格?  │
│  │             │    活跃认证用户?              │
│  └─────────────┘                            │
└─────────────────────────────────────────────┘
```

**DID 方法**: 自定义 `did:bcs:<pubkey_hash>`。
**认证流程**:
1. 用户生成密钥对，创建 DID Document。
2. 向认证机构 (Trust Anchor) 提交身份证明。
3. Trust Anchor 签发 VC (类型: `BCSIdentityCredential`)。
4. 用户提交 VC 到链上 `REGISTER_IDENTITY` 交易。
5. 治理节点验证后，账户获得 `AUTHENTICATED` 状态，可接收 `MINT`。

### 2.5 Currency Module (`bcs_currency/`)

**职责**: N 货币全生命周期管理、φ/ψ 规则执行、N 可行性约束计算。

**核心规则引擎**:

```python
class CurrencyRulesEngine:
    """
    执行 BCS 核心经济规则
    """

    def validate_sale_transaction(tx: Transaction) -> Result:
        """
        销售规则: 卖家销售商品时，必须向买家转移 φ 比例的 N 货币
        """
        # 1. 识别卖家、买家
        # 2. 从 tx.outputs 找到流向买家的 N UTXO
        # 3. 验证 N_amount >= φ * external_amount
        # 4. 验证卖家 UTXO 中有足够的 N 余额
        pass

    def validate_wage_transaction(tx: Transaction) -> Result:
        """
        工资规则: 雇主支付工资时，工人必须向雇主转移 ψ 比例的 N 货币
        """
        # 1. 识别雇主、工人
        # 2. 从 tx.outputs 找到流向雇主的 N UTXO
        # 3. 验证 N_amount >= ψ * external_amount
        pass

    def calculate_n_feasibility(account: AccountState) -> Decimal:
        """
        N 可行性约束: 企业销售规模受限于其 N 货币持有量
        返回该账户当前允许的最大 D 面额销售总额
        """
        # max_sale_volume = account.n_balance / φ
        return account.n_balance / SYSTEM_PARAMS.phi
```

**N 货币生命周期状态**:
```
[NonExistent] --MINT (gov)--> [Active]
[Active] ──────────────────────────► [Transferable]
       │                              │
       ├─ REPLENISH (gov) ──────────► (balance ↑)
       │
       └─ EXPIRE/SLASH ─────────────► [Frozen] --governance--> [Revoked]
```

### 2.6 Network Module (`bcs_network/`)

**职责**: P2P 发现、消息广播、区块/交易同步、离线节点握手。

**协议栈**:

| 层 | 技术 | 用途 |
|---|------|------|
| Transport | TCP + Noise (加密握手) | 可靠传输 + 认证 |
| Discovery | mDNS (局域网) + Bootstrap DHT (公网) | 节点发现 |
| Messaging | Protobuf + gRPC streaming | 结构化消息 |
| Gossip | 自定义 (_tx 和 block 分离传播) | 快速广播 |
| Sync | 批量请求 + Merkle 证明 | 离线节点追赶 |

**消息类型**:
```protobuf
enum MessageType {
    // 交易
    TX_NEW = 0;
    TX_BATCH_SYNC = 1;
    TX_REQUEST = 2;
    
    // 区块
    BLOCK_NEW = 10;
    BLOCK_REQUEST = 11;
    BLOCK_BATCH = 12;
    
    // 状态
    UTXO_SNAPSHOT_REQUEST = 20;
    UTXO_SNAPSHOT_RESPONSE = 21;
    STATE_DELTA = 22;
    
    // 治理
    GOV_PROPOSAL = 30;
    GOV_VOTE = 31;
    GOV_CERT = 32;
}
```

### 2.7 Wallet / Client (`bcs_wallet/`)

**职责**: 用户密钥管理、交易构建、余额查询、离线模式 UI。

**接口类型**:
- **CLI**: Python `click` / Rust `clap`，适合节点运维。
- **REST API**: FastAPI 封装核心功能，适合第三方集成。
- **Library**: Python `bcs-sdk-py`，嵌入式使用。

---

## 3. 数据模型

### 3.1 区块结构

```protobuf
// Block Header
message BlockHeader {
    uint32 version = 1;              // 协议版本 (当前: 1)
    bytes prev_block_hash = 2;     // 32 bytes, SHA3-256
    bytes merkle_root_tx = 3;      // 交易树根
    bytes merkle_root_utxo = 4;    // UTXO 状态树根 (Patricia Trie)
    bytes merkle_root_identity = 5;// 身份状态树根
    uint64 timestamp = 6;          // Unix timestamp (ms)
    uint64 height = 7;             // 区块高度
    uint32 tx_count = 8;           // 交易数量
    bytes validator_pubkey = 9;    // 出块验证者公钥
    bytes signature = 10;          // 验证者对 header 的签名
    bytes extra_data = 11;         // 治理参数变更等 (RLP encoded)
}

// Block Body
message BlockBody {
    repeated Transaction transactions = 1;
}

// Full Block
message Block {
    BlockHeader header = 1;
    BlockBody body = 2;
}
```

### 3.2 交易格式 (UTXO 模型)

```protobuf
message Transaction {
    uint32 version = 1;
    uint32 tx_type = 2;            // 见 TxType 枚举
    repeated TxInput inputs = 3;
    repeated TxOutput outputs = 4;
    uint64 lock_time = 5;          // 0 = 立即，或区块高度
    bytes extra = 6;               // 类型特定数据 (RLP encoded)
    repeated bytes witnesses = 7;    // 签名见证
    
    // ZK 相关 (可选)
    optional ZKProof zk_proof = 8;
}

enum TxType {
    // 基础转移
    TRANSFER = 0;              // 普通 N 转移 (P2PKH)
    
    // BCS 规则交易
    TRANSFER_SALE = 1;         // 销售: 外部金额 + 可选凭证 + N(φ) 结算
    TRANSFER_WAGE = 2;         // 工资: 外部金额 + 可选凭证 + N(ψ) 结算
    
    // N 货币生命周期
    MINT = 10;                 // 初始发放 (gov only)
    REPLENISH = 11;            // 补充 (gov only)
    BURN = 12;                 // 销毁 (gov only)
    
    // 身份
    REGISTER_IDENTITY = 20;    // 注册 DID + VC
    UPDATE_IDENTITY = 21;      // 更新 DID Document
    
    // 治理
    GOV_PARAMETER_CHANGE = 30; // 参数变更提案 (φ, ψ, etc.)
    GOV_VALIDATOR_CHANGE = 31;// 验证者集变更
}

message TxInput {
    bytes tx_hash = 1;         // 引用交易的 hash
    uint32 output_index = 2;   // 引用输出的索引
    bytes unlock_script = 3;     // 解锁脚本 (签名 + 公钥)
}

message TxOutput {
    uint64 amount = 1;         // N 金额 (最小单位: nanoN = 10^-9 N)
    bytes lock_script = 2;     // 锁定脚本 (地址/P2PKH)
    uint32 asset_type = 3;   // 0 = N currency
    bytes metadata = 4;        // 额外约束 (时间锁, 多签等)
}

// ZK 附件
message ZKProof {
    bytes proof_data = 1;      // 序列化的 proof
    bytes public_inputs = 2;   // 公开输入
    uint32 circuit_id = 3;     // 电路版本标识
}
```

### 3.3 脚本系统 (简化版)

使用类似 BTC 的脚本，但简化以提高可审计性:

| Opcode | Hex | 功能 |
|--------|-----|------|
| `OP_DUP` | 0x76 | 复制栈顶 |
| `OP_HASH160` | 0xa9 | RIPEMD160(SHA256(x)) |
| `OP_EQUALVERIFY` | 0x88 | 相等则继续，否则失败 |
| `OP_CHECKSIG` | 0xac | ECDSA (secp256k1) 验签 |
| `OP_CHECKMULTISIG` | 0xae | 多签验证 |
| `OP_CHECKGOVSIG` | 0xb0 | **BCS 专用**: 验证治理委员会多签 |
| `OP_CHECKDID` | 0xb1 | **BCS 专用**: 验证 DID Document 绑定 |

**标准锁定脚本示例**:
```
# P2PKH (Pay-to-Public-Key-Hash)
OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG

# 治理多签 (3-of-5)
OP_3 <pubkey1> <pubkey2> <pubkey3> <pubkey4> <pubkey5> OP_5 OP_CHECKMULTISIG

# DID 绑定输出
OP_CHECKDID <did_hash> OP_CHECKSIG
```

### 3.4 账户模型 (派生状态)

虽然底层是 UTXO，但提供账户视图以便查询:

```protobuf
message AccountState {
    bytes address = 1;              // 公钥哈希 (20 bytes)
    string did = 2;               // 绑定的 DID (可选)
    
    // N 货币状态
    uint64 n_balance = 3;           // 总 N 余额
    uint64 n_locked = 4;            // 锁定中的 N (如时间锁)
    uint64 n_available = 5;         // n_balance - n_locked
    
    // BCS 约束
    uint64 max_sale_capacity = 6;   // 当前允许的最大 D 销售额 = n_available / φ
    uint64 current_sale_volume = 7; // 当前周期已用销售额度 (滑动窗口)
    
    // 身份状态
    IdentityStatus identity_status = 8;  // UNAUTHENTICATED / PENDING / AUTHENTICATED / REVOKED
    uint64 first_auth_height = 9;   // 首次认证区块高度
    uint64 last_replenish_height = 10;// 最近补充区块高度
    
    // 元数据
    uint64 nonce = 11;              // 用于重放保护 (仅限特定 tx 类型)
    uint64 last_activity = 12;      // 最近活跃区块高度
}

enum IdentityStatus {
    UNAUTHENTICATED = 0;
    PENDING = 1;          // 已提交注册，等待验证
    AUTHENTICATED = 2;    // 已认证，可接收 MINT
    SUSPENDED = 3;        // 暂时冻结
    REVOKED = 4;          // 永久撤销
}
```

### 3.5 UTXO vs 账户制选择论证

| 维度 | UTXO (已选) | 账户制 |
|------|------------|--------|
| **离线支持** | 交易自包含，无需全局 nonce，可独立验证 | 需要 nonce 顺序，离线并发易冲突 |
| **双花检测** | 天然通过输入引用消除 | 依赖账户余额原子更新 |
| **并行验证** | 输入无交集的 tx 可完全并行 | 同一账户 tx 需串行 |
| **BCS φ/ψ 规则** | 多输入/多输出可精确建模多流向 | 需要额外日志追踪流向 |
| **隐私 (ZK)** | UTXO commitment + nullifier 是成熟方案 | 需要额外设计 (如 zETH) |
| **存储** | UTXO 集可能膨胀，但 Patricia Trie 可剪枝 | 固定账户数，存储稳定 |
| **复杂度** | 较高 | 较低 |
| **与 BTC 相似度** | 高 | 低 |

**结论**: 选择 UTXO，通过 Patricia Trie + 周期性剪枝管理存储。

---

## 4. API 接口定义

### 4.1 gRPC 服务 (节点间 + 客户端)

```protobuf
syntax = "proto3";
package bcs.v1;

// ============= 节点服务 (Node Service) =============
service NodeService {
    // 交易
    rpc SubmitTransaction(SubmitTxRequest) returns (SubmitTxResponse);
    rpc GetTransaction(GetTxRequest) returns (Transaction);
    rpc GetTransactionStatus(TxHashRequest) returns (TxStatusResponse);
    
    // 区块
    rpc GetBlockByHeight(GetBlockRequest) returns (Block);
    rpc GetBlockByHash(GetBlockByHashRequest) returns (Block);
    rpc GetLatestBlock(Empty) returns (Block);
    rpc GetBlockRange(GetBlockRangeRequest) returns (stream Block);
    
    // UTXO / 账户
    rpc GetUTXOsByAddress(GetUTXOsRequest) returns (GetUTXOsResponse);
    rpc GetAccountState(GetAccountRequest) returns (AccountState);
    rpc GetBalance(GetBalanceRequest) returns (GetBalanceResponse);
    
    // 同步
    rpc SyncUTXOSnapshot(SyncRequest) returns (stream UTXOSnapshotChunk);
    rpc SyncBlocks(SyncRequest) returns (stream Block);
    rpc GetMempoolState(Empty) returns (MempoolInfo);
    
    // 状态证明 (轻客户端)
    rpc GetStateProof(GetStateProofRequest) returns (StateProof);
}

// ============= 离线同步服务 (Offline Sync Service) =============
service OfflineSyncService {
    // 离线节点重连后批量提交
    rpc SubmitOfflineBatch(OfflineBatchRequest) returns (OfflineBatchResponse);
    
    // 获取用于离线验证的轻量证明
    rpc GetLightProof(GetLightProofRequest) returns (LightProof);
    
    // 冲突检测与解决协商
    rpc DetectConflicts(ConflictCheckRequest) returns (ConflictCheckResponse);
    rpc ResolveConflict(ConflictResolutionRequest) returns (ConflictResolutionResponse);
}

// ============= 身份服务 (Identity Service) =============
service IdentityService {
    rpc RegisterDID(RegisterDIDRequest) returns (RegisterDIDResponse);
    rpc ResolveDID(ResolveDIDRequest) returns (DIDDocument);
    rpc VerifyCredential(VerifyCredentialRequest) returns (VerifyCredentialResponse);
    rpc GetAuthenticationStatus(GetAuthStatusRequest) returns (AuthStatusResponse);
    rpc RequestNMint(RequestMintRequest) returns (RequestMintResponse);
}

// ============= 治理服务 (Governance Service) =============
service GovernanceService {
    rpc GetParameters(Empty) returns (SystemParameters);
    rpc ProposeParameterChange(ProposalRequest) returns (ProposalResponse);
    rpc VoteOnProposal(VoteRequest) returns (VoteResponse);
    rpc GetActiveProposals(Empty) returns (ActiveProposalsResponse);
}

// ============= 消息定义 (部分关键消息) =============
message SubmitTxRequest {
    Transaction tx = 1;
    bool wait_confirmation = 2;   // 是否等待区块确认
    uint32 timeout_ms = 3;         // 等待超时
}

message SubmitTxResponse {
    bytes tx_hash = 1;
    TxStatus status = 2;
    uint64 expected_block_height = 3;
}

message TxStatusResponse {
    bytes tx_hash = 1;
    TxStatus status = 2;           // PENDING / MEMPOOL / CONFIRMED / REJECTED
    uint64 confirmed_height = 3;
    string reject_reason = 4;
}

message GetUTXOsRequest {
    bytes address = 1;
    uint64 min_amount = 2;         // 可选过滤
    bool include_spent_in_mempool = 3;
}

message GetUTXOsResponse {
    repeated UTXO utxos = 1;
    uint64 total_amount = 2;
}

message UTXO {
    bytes tx_hash = 1;
    uint32 output_index = 2;
    uint64 amount = 3;
    bytes lock_script = 4;
    uint32 confirmations = 5;
}

message OfflineBatchRequest {
    repeated Transaction txs = 1;
    bytes last_known_block_hash = 2;  // 离线前最后同步的区块
    uint64 sequence_number = 3;       // 离线交易批次序号
}

message OfflineBatchResponse {
    repeated bytes accepted_tx_hashes = 1;
    repeated RejectedTx rejected = 2;
    bytes new_tip_hash = 3;
}

message RejectedTx {
    bytes tx_hash = 1;
    string reason = 2;
    ConflictInfo conflict = 3;
}

message SystemParameters {
    // BCS 核心参数
    bytes phi_numerator = 1;        // φ 分子 (如 3)
    bytes phi_denominator = 2;      // φ 分母 (如 100) => φ = 3%
    bytes psi_numerator = 3;        // ψ 分子
    bytes psi_denominator = 4;      // ψ 分母
    
    // 系统参数
    uint64 block_interval_ms = 5;
    uint64 max_block_size = 6;
    uint64 max_tx_per_block = 7;
    uint64 min_n_mint = 8;          // 初始发放量
    uint64 replenish_threshold = 9; // 补充阈值
    
    // 治理
    repeated bytes validators = 10; // 当前验证者公钥列表
    uint32 required_gov_signatures = 11; // 多签门限
}

message StateProof {
    bytes block_hash = 1;
    bytes utxo_root = 2;
    bytes merkle_proof = 3;         // 特定 UTXO/账户的证明路径
    repeated bytes validator_signatures = 4;
}
```

### 4.2 REST API (Wallet/轻客户端)

```yaml
# OpenAPI 3.0 风格描述
paths:
  /api/v1/tx:
    post:
      summary: 提交交易
      requestBody:
        content:
          application/json:
            schema: { $ref: '#/components/schemas/Transaction' }
      responses:
        202: { description: "Accepted" }
        400: { description: "Validation Error" }

  /api/v1/tx/{tx_hash}:
    get:
      summary: 查询交易
      parameters:
        - name: tx_hash
          in: path
          schema: { type: string, pattern: "^[0-9a-f]{64}$" }
      responses:
        200: { description: Transaction detail }

  /api/v1/account/{address}/balance:
    get:
      summary: 查询余额与 N 可行性
      responses:
        200:
          content:
            application/json:
              schema:
                type: object
                properties:
                  address: { type: string }
                  n_balance: { type: string }      # 大数，字符串化
                  n_available: { type: string }
                  max_sale_capacity: { type: string }
                  current_sale_volume: { type: string }
                  identity_status: { type: string }

  /api/v1/account/{address}/utxos:
    get:
      summary: 获取可用 UTXO 列表
      parameters:
        - name: min_confirms
          in: query
          schema: { type: integer, default: 1 }
      responses:
        200:
          content:
            application/json:
              schema:
                type: array
                items: { $ref: '#/components/schemas/UTXO' }

  /api/v1/offline/prepare:
    post:
      summary: 为离线模式准备 UTXO 证明包
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                address: { type: string }
                max_utxos: { type: integer, default: 100 }
      responses:
        200:
          description: "包含 Merkle proof 的轻量 UTXO 集"

  /api/v1/offline/submit-batch:
    post:
      summary: 离线恢复后批量提交
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                txs: { type: array, items: { type: object } }
                metadata: { type: object }
      responses:
        200:
          content:
            application/json:
              schema:
                type: object
                properties:
                  accepted: { type: integer }
                  rejected: { type: integer }
                  conflicts: { type: array }

  /api/v1/identity/register:
    post:
      summary: 注册 DID 身份
      requestBody:
        content:
          multipart/form-data:   # DID Document + VC 文件
            schema:
              type: object
              properties:
                did_document: { type: string, format: json }
                verifiable_credential: { type: string, format: json }
      responses:
        202: { description: "Registration pending verification" }

  /api/v1/governance/parameters:
    get:
      summary: 获取当前系统参数 (φ, ψ, 验证者列表)
      responses:
        200: { description: SystemParameters }

  /api/v1/zk/shield:
    post:
      summary: 创建隐私保护 (shielded) 交易
      description: "使用 ZK 证明隐藏交易金额和地址"
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                inputs: { type: array }   # UTXO nullifiers
                outputs: { type: array }  # commitments
                proof: { type: string } # base64 encoded ZKProof
      responses:
        202: { description: "Accepted for shielded pool" }
```

---

## 5. 技术栈与文件结构

### 5.1 技术栈

| 层级 | 组件 | 技术选型 | 理由 |
|------|------|---------|------|
| **密码学** | 哈希 | SHA3-256 | Keccak 变体，以太坊兼容 |
| | 签名 | ECDSA secp256k1 | BTC/ETH 标准，库成熟 |
| | ZK | bellman (Rust) + py_ecc (Python) | 生产验证，Python 可调用 FFI |
| | Merkle Tree | 二叉 SHA3 | 简单、可审计 |
| **区块链核心** | 共识引擎 | 自定义 PoA + BFT | 轻量、确定性 |
| | 存储 | LevelDB (blocks) + SQLite (index) | 轻量、可嵌入 |
| | UTXO 集 | Patricia Trie (内存) + 快照 | 快速验证、轻量证明 |
| **网络** | P2P | libp2p (Rust) / py-libp2p | 成熟、NAT 穿透 |
| | RPC | gRPC + Protobuf | 强类型、高效 |
| | REST | FastAPI (Python) | 异步、自动生成文档 |
| **离线** | 缓存 | SQLite | 零配置、事务安全 |
| | 同步 | 自定义协议 | 见 §6.2 |
| **身份** | DID | 自研 `did:bcs` | 轻量、无外部依赖 |
| | VC | W3C VC Data Model 1.1 | 标准兼容 |
| | 解析器 | 自研 | 无区块链锚定需求 |
| **部署** | 容器 | Docker + Docker Compose | 开发/测试 |
| | 编排 | Docker Swarm (小规模) / K8s (大规模) | 渐进 |

### 5.2 项目目录结构

```
bcs-chain/
├── Cargo.toml                          # Rust workspace root
├── pyproject.toml                      # Python package root
├── README.md
├── LICENSE
├── docker/
│   ├── Dockerfile.node                 # 验证者节点
│   ├── Dockerfile.client               # 轻客户端
│   ├── docker-compose.yml              # 多节点开发网络
│   ├── docker-compose.prod.yml         # 生产配置
│   └── config/
│       ├── genesis.json                # 创世区块配置
│       ├── validators.json             # 初始验证者
│       └── network.bootstrap           # 引导节点列表
│
├── crates/                             # Rust 核心模块 (高性能/安全)
│   ├── bcs-crypto/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── hash.rs                 # SHA3, RIPEMD160
│   │   │   ├── ecdsa.rs                # secp256k1 签名/验签
│   │   │   ├── merkle.rs               # Merkle Tree 构建与验证
│   │   │   └── address.rs              # 地址生成 (pubkey_hash)
│   │   └── Cargo.toml
│   │
│   ├── bcs-zk/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── circuits/
│   │   │   │   ├── n_transfer.rs       # N 转移电路
│   │   │   │   ├── ratio_verify.rs     # φ/ψ 比例验证电路
│   │   │   │   └── identity_bind.rs    # DID 绑定电路
│   │   │   ├── prover.rs               # 证明生成
│   │   │   ├── verifier.rs             # 验证 (链上/轻节点)
│   │   │   └── setup.rs                # 可信设置 (或透明参数)
│   │   └── Cargo.toml
│   │
│   ├── bcs-consensus/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── poa.rs                  # PoA 轮转出块
│   │   │   ├── bft.rs                  # BFT 确认层
│   │   │   ├── validator_set.rs        # 验证者管理
│   │   │   └── slashing.rs             # 惩罚逻辑 (简单版)
│   │   └── Cargo.toml
│   │
│   ├── bcs-storage/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── block_store.rs          # LevelDB 区块存储
│   │   │   ├── utxo_trie.rs            # Patricia Trie UTXO 集
│   │   │   ├── state_db.rs             # SQLite 账户状态索引
│   │   │   └── offline_pool.rs         # 离线交易 SQLite 池
│   │   └── Cargo.toml
│   │
│   ├── bcs-p2p/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── transport.rs            # Noise + TCP
│   │   │   ├── discovery.rs            # mDNS / DHT
│   │   │   ├── gossip.rs               # 消息传播
│   │   │   ├── sync.rs                 # 区块/状态同步
│   │   │   └── protocol.rs             # Protobuf 编解码
│   │   └── Cargo.toml
│   │
│   └── bcs-node/
│       ├── src/
│       │   ├── main.rs                 # 验证者节点入口
│       │   ├── config.rs               # TOML 配置解析
│       │   ├── node.rs                 # 节点生命周期
│       │   ├── rpc_server.rs           # gRPC 服务实现
│       │   └── metrics.rs              # Prometheus 指标
│       └── Cargo.toml
│
├── python/                             # Python 模块 (业务逻辑/API)
│   ├── bcs_core/
│   │   ├── __init__.py
│   │   ├── block.py                    # 区块结构 (Python dataclass)
│   │   ├── transaction.py              # 交易类型与验证
│   │   ├── utxo.py                     # UTXO 模型与集管理
│   │   ├── state.py                    # 账户派生状态
│   │   ├── script.py                   # 脚本引擎 (简化)
│   │   ├── validator.py                # 交易验证逻辑
│   │   └── mempool.py                  # 内存池管理
│   │
│   ├── bcs_currency/
│   │   ├── __init__.py
│   │   ├── rules_engine.py             # φ/ψ 规则执行
│   │   ├── n_lifecycle.py              # N 发放/补充/销毁
│   │   ├── feasibility.py              # N 可行性约束计算
│   │   └── params.py                   # 系统参数管理
│   │
│   ├── bcs_offline/
│   │   ├── __init__.py
│   │   ├── tx_builder.py               # 离线交易构建
│   │   ├── cache.py                    # SQLite 交易缓存
│   │   ├── sync.py                     # 重连同步引擎
│   │   ├── conflict_resolver.py        # 冲突解决
│   │   ├── utxo_view.py                # 本地乐观 UTXO 视图
│   │   └── light_client.py             # 轻客户端证明验证
│   │
│   ├── bcs_identity/
│   │   ├── __init__.py
│   │   ├── did.py                      # DID 生成/解析
│   │   ├── vc.py                       # VC 签发/验证
│   │   ├── registry.py               # 身份注册表
│   │   ├── trust_anchor.py             # 信任锚点管理
│   │   └── auth.py                     # 权限控制
│   │
│   ├── bcs_wallet/
│   │   ├── __init__.py
│   │   ├── wallet.py                   # 钱包核心 (密钥/UTXO 管理)
│   │   ├── tx_creator.py               # 交易创建助手
│   │   ├── balance.py                  # 余额查询
│   │   ├── offline_mode.py             # 离线模式管理
│   │   └── exporter.py                 # 交易导出/导入
│   │
│   ├── bcs_api/
│   │   ├── __init__.py
│   │   ├── grpc_server.py              # gRPC 服务 (FastAPI 风格 wrapper)
│   │   ├── rest_server.py              # FastAPI REST 服务
│   │   ├── middleware.py               # 认证/日志/限流
│   │   └── schemas.py                  # Pydantic 模型
│   │
│   ├── bcs_cli/
│   │   ├── __init__.py
│   │   ├── main.py                     # click CLI 入口
│   │   ├── commands/
│   │   │   ├── wallet.py               # 钱包命令
│   │   │   ├── tx.py                   # 交易命令
│   │   │   ├── node.py                 # 节点命令
│   │   │   ├── identity.py             # 身份命令
│   │   │   └── offline.py              # 离线模式命令
│   │   └── utils.py
│   │
│   ├── bcs_sdk/
│   │   ├── __init__.py
│   │   ├── client.py                   # SDK 客户端
│   │   ├── types.py                    # 类型定义
│   │   └── exceptions.py               # 异常定义
│   │
│   └── tests/
│       ├── conftest.py
│       ├── test_blockchain.py
│       ├── test_currency_rules.py
│       ├── test_offline_sync.py
│       ├── test_identity.py
│       └── test_zk.py
│
├── proto/                              # Protobuf 定义 (共享)
│   ├── bcs/
│   │   ├── block.proto
│   │   ├── transaction.proto
│   │   ├── utxo.proto
│   │   ├── identity.proto
│   │   ├── network.proto
│   │   ├── governance.proto
│   │   └── zk.proto
│   └── buf.yaml
│
├── circuits/                           # ZK 电路 (Circom / bellman)
│   ├── n_transfer.circom
│   ├── ratio_verify.circom
│   ├── identity_bind.circom
│   └── compile.sh
│
├── docs/
│   ├── architecture.md                 # 本文档
│   ├── bcs_whitepaper.md
│   ├── api_reference.md
│   ├── offline_sync_protocol.md
│   └── governance.md
│
├── scripts/
│   ├── setup_dev.sh                    # 开发环境初始化
│   ├── genesis_generator.py            # 创世区块生成
│   ├── keygen.py                       # 密钥生成工具
│   └── benchmark.py                    # 性能基准测试
│
└── config/
    ├── node.default.toml
    ├── client.default.toml
    └── testnet/
        ├── node1.toml
        ├── node2.toml
        └── node3.toml
```

---

## 6. 关键算法设计

### 6.1 共识算法: PoA-BFT (Proof of Authority + BFT-like Finality)

**目标**: 轻量、确定性、无需挖矿、低算力。

**角色**:
- **验证者 (Validator)**: 预先授权的节点，轮流出块。
- **观察者 (Observer)**: 同步链、验证但不参与共识。
- **轻客户端 (Light Client)**: 仅同步 header、验证 Merkle proof。

**算法流程**:

```python
class PoABFTConsensus:
    """
    基于轮次的 PoA，附加 BFT-like 确认
    """
    
    # 系统参数
    BLOCK_INTERVAL = 5000           # 5 秒
    VALIDATOR_COUNT = len(validators)
    FINALITY_THRESHOLD = 2/3       # 2/3 验证者签名 = 最终性
    
    def propose_block(self, validator_id: int, height: int) -> Block:
        """
        轮流出块: validator_for_height = height % VALIDATOR_COUNT
        """
        if validator_id != (height % VALIDATOR_COUNT):
            raise NotMyTurnError()
        
        # 1. 从 mempool 选取交易 (按 fee 优先 + 时间先后)
        txs = self.mempool.select_transactions(max_size=MAX_BLOCK_SIZE)
        
        # 2. 构建区块
        block = BlockBuilder.build(
            prev_hash=self.chain_tip.hash,
            txs=txs,
            validator=self.my_pubkey,
            timestamp=current_time_ms()
        )
        
        # 3. 签名 header
        block.header.signature = ecdsa_sign(self.my_privkey, block.header_hash())
        return block
    
    def validate_block(self, block: Block) -> ValidationResult:
        """
        验证者收到新区块后验证
        """
        # 1. 验证轮次正确性
        expected_validator = block.height % VALIDATOR_COUNT
        if block.validator_pubkey != validators[expected_validator]:
            return INVALID("Wrong validator for height")
        
        # 2. 验证时间戳 (不能太旧，不能未来)
        if block.timestamp < prev_block.timestamp:
            return INVALID("Timestamp regression")
        if block.timestamp > now() + CLOCK_DRIFT_TOLERANCE:
            return INVALID("Future timestamp")
        
        # 3. 验证签名
        if not ecdsa_verify(block.validator_pubkey, block.header_hash(), block.signature):
            return INVALID("Invalid block signature")
        
        # 4. 验证 Merkle 根
        if block.header.merkle_root_tx != merkle_root(block.transactions):
            return INVALID("Merkle root mismatch")
        
        # 5. 验证每笔交易
        for tx in block.transactions:
            result = self.tx_validator.validate(tx)
            if not result.valid:
                return INVALID(f"Invalid tx: {result.reason}")
        
        # 6. 验证 UTXO 状态转换
        new_utxo_root = self.utxo_manager.simulate_and_commit(block.transactions)
        if new_utxo_root != block.header.merkle_root_utxo:
            return INVALID("UTXO root mismatch")
        
        return VALID
    
    def commit_block(self, block: Block):
        """
        收集验证者签名，达到门限后最终确认
        """
        # 收集签名 (gossip)
        self.pending_signatures[block.hash].add(block.signature)
        
        # 检查最终性
        if len(self.pending_signatures[block.hash]) >= FINALITY_THRESHOLD * VALIDATOR_COUNT:
            block.is_finalized = True
            self.chain_tip = block
            self.storage.commit_block(block)
            self.mempool.remove_confirmed(block.transactions)
            
            # 通知订阅者
            self.emit(Event.BLOCK_FINALIZED, block)
```

**容错分析**:
- 可容忍 **f** 个拜占庭节点，当 **n = 3f + 1** (经典 BFT)。
- 对于 7 验证者，可容忍 2 个作恶/离线节点。
- 出块间隔 5 秒，确认时间 = 1 个区块 (5s) + 签名收集 (网络延迟)。

### 6.2 同步算法: 离线节点追赶

**场景**: 离线节点重新联网，需要同步缺失的区块和 UTXO 状态。

```python
class OfflineSyncAlgorithm:
    """
    离线节点同步协议
    """
    
    def sync(self, local_tip: Block, peer: Node) -> SyncResult:
        # Phase 1: 找到共同祖先
        common_ancestor = self.find_common_ancestor(local_tip, peer)
        
        # Phase 2: 批量下载缺失区块
        missing_blocks = peer.get_blocks_from(common_ancestor.height + 1)
        
        # Phase 3: 快速验证 (header chain)
        for block in missing_blocks:
            if not self.validate_header_chain(block):
                return SYNC_FAILED("Invalid header chain")
        
        # Phase 4: 下载 UTXO 快照 (可选，如果差距大)
        if len(missing_blocks) > FULL_SYNC_THRESHOLD:
            # 下载状态快照 + 最近区块
            utxo_snapshot = peer.get_utxo_snapshot_at(common_ancestor.height)
            self.utxo_manager.apply_snapshot(utxo_snapshot)
            
            # 只重放最近 N 个区块的交易
            replay_blocks = missing_blocks[-UTXO_REPLAY_WINDOW:]
        else:
            replay_blocks = missing_blocks
        
        # Phase 5: 重放交易
        for block in replay_blocks:
            self.utxo_manager.apply_block(block)
        
        # Phase 6: 提交本地离线交易
        offline_txs = self.offline_pool.get_pending()
        
        # Phase 6a: 检查 UTXO 是否仍有效
        valid_offline, conflicts = self.filter_valid_offline_txs(offline_txs)
        
        # Phase 6b: 提交有效离线交易到 mempool
        for tx in valid_offline:
            self.mempool.add(tx)
        
        # Phase 6c: 处理冲突
        for conflict in conflicts:
            self.resolve_conflict(conflict)
        
        return SyncResult(
            synced_blocks=len(missing_blocks),
            applied_offline=len(valid_offline),
            resolved_conflicts=len(conflicts),
            new_tip=self.chain_tip
        )
    
    def find_common_ancestor(self, local_tip: Block, peer: Node) -> Block:
        """
        二分查找 + header hash 比对找到分叉点
        """
        # 1. 获取 peer 的最新 header
        peer_tip = peer.get_latest_header()
        
        # 2. 如果本地是祖先，直接返回
        if self.is_ancestor(local_tip.hash, peer_tip):
            return local_tip
        
        # 3. 二分搜索共同高度
        low, high = 0, local_tip.height
        while low < high:
            mid = (low + high) // 2
            local_hash = self.get_header_at(mid).hash
            peer_hash = peer.get_header_at(mid).hash
            
            if local_hash == peer_hash:
                low = mid + 1  # 可能是共同祖先或更高
            else:
                high = mid     # 分叉点在 mid 或更低
        
        return self.get_header_at(low - 1)
    
    def filter_valid_offline_txs(self, offline_txs: List[Transaction]) -> Tuple[List, List]:
        """
        检查离线交易引用的 UTXO 是否被新的链上交易花费
        """
        valid = []
        conflicts = []
        
        for tx in offline_txs:
            # 检查所有输入 UTXO 是否仍然存在
            all_utxos_valid = all(
                self.utxo_manager.exists(inp.tx_hash, inp.output_index)
                for inp in tx.inputs
            )
            
            if all_utxos_valid:
                # 额外检查: 离线期间是否有其他规则变化
                if self.currency_rules.still_valid(tx):
                    valid.append(tx)
                else:
                    conflicts.append(Conflict(tx, reason="Rules changed"))
            else:
                # UTXO 已被花费，需要冲突解决
                conflicts.append(Conflict(tx, reason="UTXO already spent"))
        
        return valid, conflicts
```

### 6.3 冲突解决算法

**冲突类型**:
1. **双花冲突**: 离线交易引用的 UTXO 已被他人花费。
2. **规则冲突**: 离线期间系统参数 (φ/ψ) 改变，导致交易不再合规。
3. **余额不足**: 离线期间收到的新 UTXO 被部分花费，余额不足以覆盖离线交易。

**解决策略**:

```python
class ConflictResolver:
    """
    离线交易冲突解决
    """
    
    def resolve(self, conflict: Conflict) -> Resolution:
        if conflict.type == CONFLICT_DOUBLE_SPEND:
            return self.resolve_double_spend(conflict)
        elif conflict.type == CONFLICT_RULE_CHANGE:
            return self.resolve_rule_change(conflict)
        elif conflict.type == CONFLICT_INSUFFICIENT_BALANCE:
            return self.resolve_insufficient_balance(conflict)
    
    def resolve_double_spend(self, conflict: Conflict) -> Resolution:
        """
        双花冲突解决策略 (优先级):
        1. 如果本地交易有更高的 "离线优先级权重" (时间戳 + 序列号)，
           尝试 RBF (Replace-By-Fee) 方式重新提交。
        2. 否则，标记为失败，通知用户。
        3. 提供替代 UTXO 自动重建交易 (如果可能)。
        """
        tx = conflict.tx
        
        # 策略 A: 尝试用新的 UTXO 重建
        new_utxos = self.wallet.get_spendable_utxos(exclude=conflict.spent_utxos)
        if new_utxos.total >= tx.total_output:
            rebuilt_tx = self.wallet.rebuild_tx(tx, new_utxos)
            return Resolution(
                strategy=REBUILD,
                new_tx=rebuilt_tx,
                message="Transaction rebuilt with alternative UTXOs"
            )
        
        # 策略 B: 标记失败
        return Resolution(
            strategy=REJECT,
            new_tx=None,
            message=f"UTXOs already spent: {conflict.spent_utxos}"
        )
    
    def resolve_rule_change(self, conflict: Conflict) -> Resolution:
        """
        规则变化: 尝试根据新规则自动调整交易
        """
        tx = conflict.tx
        
        # 如果 tx 是 SALE 类型，重新计算 φ
        if tx.tx_type == TxType.TRANSFER_SALE:
            new_phi = self.params.current_phi
            required_n = int(tx.d_amount * new_phi)
            
            # 如果现有 N 输出足够，只需调整比例
            if tx.n_outputs[0].amount >= required_n:
                adjusted_tx = self.adjust_ratio(tx, new_phi)
                return Resolution(strategy=ADJUST, new_tx=adjusted_tx)
            else:
                return Resolution(
                    strategy=REJECT,
                    message=f"Insufficient N for new φ={new_phi}"
                )
        
        return Resolution(strategy=REJECT, message="Unsupported rule change")
```

**冲突解决 UI 流程**:
```
[检测到冲突]
    │
    ├─ 自动解决? ──► 尝试 REBUILD / ADJUST
    │                 │
    │                 ├─ 成功 ──► [提交新交易]
    │                 │
    │                 └─ 失败 ──► [通知用户]
    │                               │
    └─ 用户介入 ◄───────────────────┘
          │
          ├─ 放弃交易
          ├─ 手动选择替代 UTXO
          └─ 修改交易参数
```

### 6.4 N 可行性约束算法

```python
class NF feasibilityEngine:
    """
    N 可行性约束: 企业销售规模受限于其 N 货币持有量
    """
    
    def calculate_max_sale_capacity(self, address: bytes, at_height: int = None) -> int:
        """
        计算账户在指定高度的最大允许 D 面额销售总额
        
        公式: max_sale_capacity = available_n_balance / φ
        """
        state = self.get_account_state(address, at_height)
        
        # 获取可用 N 余额
        available_n = state.n_available
        
        # 获取当前 φ 参数
        phi = self.governance.get_parameter("phi", at_height)
        
        # 计算理论上限
        theoretical_max = available_n / phi
        
        # 应用额外约束 (如: 认证时长奖励系数)
        auth_bonus = self.calculate_auth_bonus(state)
        
        return int(theoretical_max * auth_bonus)
    
    def check_sale_feasibility(self, address: bytes, proposed_sale_amount_d: int) -> FeasibilityResult:
        """
        检查提出的销售是否在可行性约束内
        """
        # 获取当前周期已用额度 (滑动窗口)
        current_period_usage = self.get_period_usage(address)
        
        # 获取容量上限
        capacity = self.calculate_max_sale_capacity(address)
        
        # 检查
        if current_period_usage + proposed_sale_amount_d <= capacity:
            return FeasibilityResult(
                feasible=True,
                remaining_capacity=capacity - current_period_usage - proposed_sale_amount_d
            )
        else:
            return FeasibilityResult(
                feasible=False,
                remaining_capacity=capacity - current_period_usage,
                shortfall=proposed_sale_amount_d - (capacity - current_period_usage)
            )
    
    def record_sale_usage(self, address: bytes, sale_amount_d: int, at_height: int):
        """
        在交易确认后记录销售使用量
        """
        self.usage_log.append({
            'address': address,
            'amount': sale_amount_d,
            'height': at_height,
            'timestamp': block_timestamp(at_height)
        })
        
        # 清理过期记录 (滑动窗口外)
        window_start = at_height - SALE_WINDOW_BLOCKS
        self.usage_log = [r for r in self.usage_log if r.height > window_start]
    
    def calculate_auth_bonus(self, state: AccountState) -> Decimal:
        """
        认证时长奖励: 认证时间越长，可获得的销售容量加成
        """
        if state.identity_status != IdentityStatus.AUTHENTICATED:
            return Decimal('0')  # 未认证 = 无销售权限
        
        # 基础奖励随时间增长 (有上限)
        blocks_since_auth = self.current_height - state.first_auth_height
        months_active = blocks_since_auth / BLOCKS_PER_MONTH
        
        # 公式: bonus = 1 + min(0.1 * months_active, 1.0)
        # 即: 最多翻倍
        bonus = Decimal('1') + min(Decimal('0.1') * months_active, Decimal('1'))
        return bonus
```

### 6.5 ZK 验证流程 (Shielded Transaction)

```
Sender (Prover)                          Blockchain (Verifier)
─────────────────────────────────────────────────────────────────
1. 选择输入 UTXO (知晓金额和密钥)
        │
        ▼
2. 计算 Nullifier = PRF_sk(UTXO_id)
        │
        ▼
3. 计算 Commitment = CRH(amount, blinding)
        │
        ▼
4. 生成 ZKProof π:
   公开输入: [root, nullifiers[], commitments[], fee]
   私密输入: [amounts[], sk, paths[], blindings[]]
   电路约束:
     - 每个 nullifier 正确计算
     - 每个 commitment 正确计算
     - 输入金额总和 = 输出金额总和 + fee
     - Merkle path 验证 root
     - 金额非负 (range proof)
        │
        ├────────────────────────────────────►
                                             │
                                             ▼
                                        5. 验证 π:
                                           - Groth16 verify
                                           - 检查 nullifiers 未使用
                                           - 检查 commitments 新
                                             │
                                             ▼
                                        6. 接受交易:
                                           - 记录 nullifiers (防止双花)
                                           - 记录 commitments
                                           - 更新 Merkle root
```

---

## 7. 部署架构

### 7.1 开发环境 (单节点 + 多验证者)

```yaml
# docker-compose.yml (开发网络)
version: '3.8'

services:
  validator-1:
    build:
      context: .
      dockerfile: docker/Dockerfile.node
    ports:
      - "10001:10001"    # P2P
      - "50051:50051"    # gRPC
      - "8080:8080"      # REST / Metrics
    volumes:
      - ./config/testnet/node1.toml:/app/config/node.toml
      - validator1-data:/app/data
    environment:
      - BCS_ROLE=validator
      - BCS_VALIDATOR_ID=0
    networks:
      - bcs-net

  validator-2:
    build:
      context: .
      dockerfile: docker/Dockerfile.node
    ports:
      - "10002:10001"
      - "50052:50051"
    volumes:
      - ./config/testnet/node2.toml:/app/config/node.toml
      - validator2-data:/app/data
    environment:
      - BCS_ROLE=validator
      - BCS_VALIDATOR_ID=1
    networks:
      - bcs-net

  validator-3:
    build:
      context: .
      dockerfile: docker/Dockerfile.node
    ports:
      - "10003:10001"
      - "50053:50051"
    volumes:
      - ./config/testnet/node3.toml:/app/config/node.toml
      - validator3-data:/app/data
    environment:
      - BCS_ROLE=validator
      - BCS_VALIDATOR_ID=2
    networks:
      - bcs-net

  # 观察者节点 (全节点但不参与共识)
  observer:
    build:
      context: .
      dockerfile: docker/Dockerfile.node
    ports:
      - "10004:10001"
      - "50054:50051"
      - "8081:8080"
    volumes:
      - ./config/node.default.toml:/app/config/node.toml
      - observer-data:/app/data
    environment:
      - BCS_ROLE=observer
    networks:
      - bcs-net

  # 轻客户端 (REST API 网关)
  client-api:
    build:
      context: .
      dockerfile: docker/Dockerfile.client
    ports:
      - "3000:3000"
    environment:
      - BCS_NODE_GRPC=observer:50051
      - BCS_OFFLINE_ENABLED=true
    networks:
      - bcs-net
    depends_on:
      - observer

  # 监控
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./docker/config/prometheus.yml:/etc/prometheus/prometheus.yml
    networks:
      - bcs-net

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    networks:
      - bcs-net

volumes:
  validator1-data:
  validator2-data:
  validator3-data:
  observer-data:

networks:
  bcs-net:
    driver: bridge
```

### 7.2 生产环境架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Production Network                              │
│                                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │  Validator 1 │  │  Validator 2 │  │  Validator 3 │  │  Validator N │   │
│  │  (Primary)   │  │              │  │              │  │              │   │
│  │  HSM 签名    │  │  HSM 签名    │  │  HSM 签名    │  │  HSM 签名    │   │
│  │  Multi-AZ    │  │  Multi-AZ    │  │  Multi-AZ    │  │  Multi-AZ    │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│         │                 │                 │                 │             │
│         └─────────────────┴─────────────────┴─────────────────┘               │
│                              P2P Mesh (Noise加密)                            │
│                                    │                                        │
│         ┌──────────────────────────┼──────────────────────────┐             │
│         │                          │                          │             │
│  ┌──────▼───────┐  ┌───────────────▼────────┐  ┌──────────────▼──────┐      │
│  │   Observer   │  │      Observer          │  │     Observer         │      │
│  │   Nodes      │  │      Nodes             │  │     Nodes            │      │
│  │  (Full Sync) │  │  (Full Sync)           │  │  (Full Sync)         │      │
│  └──────┬───────┘  └───────────┬────────────┘  └───────────┬──────────┘      │
│         │                      │                          │                 │
│         └──────────────────────┼──────────────────────────┘                 │
│                                │                                            │
│                    ┌───────────▼────────────┐                              │
│                    │     Load Balancer       │                              │
│                    │     (Nginx/HAProxy)     │                              │
│                    └───────────┬────────────┘                              │
│                                │                                            │
│         ┌──────────────────────┼──────────────────────┐                    │
│         │                      │                      │                    │
│  ┌──────▼───────┐  ┌───────────▼──────────┐  ┌───────▼──────┐             │
│  │  Client API  │  │   Client API         │  │  Client API  │             │
│  │  (REST/gRPC) │  │   (REST/gRPC)        │  │  (REST/gRPC) │             │
│  │  Stateless   │  │   Stateless          │  │  Stateless   │             │
│  └──────┬───────┘  └───────────┬──────────┘  └──────┬───────┘             │
│         │                      │                      │                    │
│         └──────────────────────┼──────────────────────┘                    │
│                                │                                            │
│                    ┌───────────▼────────────┐                              │
│                    │   End Users / Wallets   │                              │
│                    │   (Mobile/Web/Desktop)  │                              │
│                    └─────────────────────────┘                              │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                      Offline Clients                               │     │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │     │
│  │  │ Mobile 1 │  │ Mobile 2 │  │ Mobile N │  │ Desktop  │           │     │
│  │  │ (SQLite) │  │ (SQLite) │  │ (SQLite) │  │ (SQLite) │           │     │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘           │     │
│  │       │             │             │             │                  │     │
│  │       └─────────────┴─────────────┴─────────────┘                  │     │
│  │                    (Periodic Sync to Client API)                   │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.3 节点配置模板

```toml
# node.default.toml
[node]
role = "validator"              # validator | observer | light
id = 0
listen_addr = "0.0.0.0:10001"
data_dir = "/app/data"

[blockchain]
version = 1
block_interval_ms = 5000
max_block_size = 1048576
max_tx_per_block = 2000

[consensus]
type = "poa-bft"
validator_set = ["04a1b2c3...", "04d4e5f6...", "04g7h8i9..."]
required_signatures = 2          # 2-of-3
round_robin = true

[currency]
phi = "0.03"                     # 3%
psi = "0.05"                     # 5%
min_mint_amount = "1000000000"   # 1 N (nanoN 单位)
replenish_period_blocks = 432000 # ~30 天 (按 5s/块)
sale_window_blocks = 8640        # ~12 小时

[identity]
trust_anchors = ["did:bcs:anchor1", "did:bcs:anchor2"]
required_vc_types = ["BCSIdentityCredential"]

[network]
bootstrap_peers = ["/dns/validator-1/tcp/10001", "/dns/validator-2/tcp/10001"]
discovery = "mdns+dht"
max_peers = 50

[storage]
block_engine = "leveldb"
state_engine = "sqlite"
utxo_cache_size = 100000

[rpc]
grpc_bind = "0.0.0.0:50051"
rest_bind = "0.0.0.0:8080"
cors_origins = ["*"]

[offline]
enabled = true
max_cached_tx = 1000
ttl_hours = 72
auto_sync_on_connect = true

[zk]
enabled = true
curve = "bn128"
proving_backend = "rust-ffi"
verification_only = false       # 轻客户端设为 true

[logging]
level = "info"
format = "json"
output = "stdout"

[metrics]
enabled = true
bind = "0.0.0.0:8080"
path = "/metrics"
```

---

## 8. 安全与隐私策略

### 8.1 威胁模型

| 威胁 | 缓解措施 |
|------|---------|
| 双花攻击 | UTXO 集 + 链上确认 |
| 离线双花 | 冲突解决算法 + 最终性确认后不可逆 |
| 验证者作恶 | PoA + BFT: 2/3 签名，可检测并剔除 |
| 女巫攻击 | DID 认证 + VC 验证，非匿名 |
| 隐私泄露 | ZK shielded transactions (可选) |
| 重放攻击 | UTXO 唯一性 + lock_time + 链 ID |
| 量子计算 | 预留 hash/签名算法升级路径 (header.version) |

### 8.2 隐私模式

| 模式 | 公开信息 | 隐藏信息 | 验证方式 |
|------|---------|---------|---------|
| **Public** | 金额、地址、流向 | 无 | 普通脚本验证 |
| **Shielded** | 交易存在性 | 金额、地址、流向 | ZK proof + nullifier |
| **Mixed** | 部分公开，部分 shielded | 混合 | 分段验证 |

### 8.3 密钥管理

- **热钱包**: 软件密钥，用于日常交易 (加密存储于 SQLite)。
- **冷钱包**: HSM / 离线设备，用于治理操作和大额 N 转移。
- **密钥派生**: BIP-39 助记词 + BIP-44 路径 `m/44'/BCS_COIN_TYPE'/0'/0/i`。

---

## 9. 第一阶段里程碑 (MVP)

### 9.1 模块优先级

```
Phase 1 (MVP - 8 weeks):
├── Week 1-2: Blockchain Core
│   ├── Block/Tx 数据结构
│   ├── UTXO 集 (内存 Patricia Trie)
│   ├── 简化 PoA 共识 (单验证者)
│   └── 本地 SQLite 存储
│
├── Week 3-4: Currency + Identity
│   ├── N 货币发放 (MINT)
│   ├── 普通 TRANSFER
│   ├── SALE/WAGE 规则引擎 (φ/ψ)
│   ├── DID 注册 + 认证状态
│   └── N 可行性约束计算
│
├── Week 5-6: Network + Offline
│   ├── P2P 基础 (TCP + 自定义协议)
│   ├── gRPC 服务
│   ├── 离线交易缓存 (SQLite)
│   ├── 重连同步
│   └── 简单冲突解决
│
├── Week 7-8: Client + Integration
│   ├── REST API (FastAPI)
│   ├── CLI 钱包
│   ├── Docker 部署
│   ├── 测试网 (3 节点)
│   └── 文档 + 测试覆盖

Phase 2 (Privacy + Scale - 4 weeks):
├── ZK 电路 (N transfer)
├── Shielded transaction 支持
├── 多签治理
├── 轻客户端 SPV
└── 性能优化

Phase 3 (Production - 4 weeks):
├── HSM 集成
├── 监控/告警
├── 安全审计
├── 主网启动
└── 经济模型校准
```

### 9.2 MVP 裁剪范围

| 特性 | MVP | Phase 2 | Phase 3 |
|------|-----|---------|---------|
| UTXO 模型 | ✅ | ✅ | ✅ |
| PoA 共识 | ✅ (轮转出块) | ✅ + BFT | ✅ + Slashing |
| 普通 TRANSFER | ✅ | ✅ | ✅ |
| SALE/WAGE 规则 | ✅ | ✅ | ✅ |
| N 可行性约束 | ✅ | ✅ | ✅ |
| DID 注册 | ✅ | ✅ | ✅ |
| VC 验证 | ✅ (简化) | ✅ (完整) | ✅ |
| 离线交易缓存 | ✅ | ✅ | ✅ |
| 重连同步 | ✅ | ✅ | ✅ |
| 冲突解决 | ✅ (基础) | ✅ (完整) | ✅ |
| ZK Privacy | ❌ | ✅ | ✅ |
| Shielded Tx | ❌ | ✅ | ✅ |
| 轻客户端 | ❌ | ✅ | ✅ |
| 治理提案 | ❌ | ✅ | ✅ |
| HSM | ❌ | ❌ | ✅ |

---

## 10. 附录：核心代码骨架

### 10.1 Python: 交易验证核心

```python
# python/bcs_core/validator.py
from dataclasses import dataclass
from typing import List, Optional, Tuple
from enum import Enum, auto
import hashlib


class ValidationError(Enum):
    INVALID_SIGNATURE = auto()
    UTXO_NOT_FOUND = auto()
    UTXO_ALREADY_SPENT = auto()
    INSUFFICIENT_BALANCE = auto()
    INVALID_SCRIPT = auto()
    INVALID_PHI = auto()
    INVALID_PSI = auto()
    IDENTITY_NOT_AUTHORIZED = auto()
    ZK_VERIFICATION_FAILED = auto()
    LOCKTIME_NOT_MET = auto()
    DOUBLE_SPEND = auto()


@dataclass
class ValidationResult:
    valid: bool
    error: Optional[ValidationError] = None
    message: str = ""


class TransactionValidator:
    """
    BCS 交易验证器
    """
    
    def __init__(self, utxo_manager, identity_registry, params):
        self.utxo = utxo_manager
        self.identity = identity_registry
        self.params = params
    
    def validate(self, tx: 'Transaction', for_block: bool = False) -> ValidationResult:
        """完整交易验证入口"""
        
        # 1. 基础结构验证
        if len(tx.inputs) == 0 or len(tx.outputs) == 0:
            return ValidationResult(False, ValidationError.INVALID_SCRIPT, "Empty inputs/outputs")
        
        # 2. 验证 lock_time
        if tx.lock_time > current_height():
            return ValidationResult(False, ValidationError.LOCKTIME_NOT_MET)
        
        # 3. 验证 witness (签名)
        sig_result = self._validate_signatures(tx)
        if not sig_result.valid:
            return sig_result
        
        # 4. 验证输入 UTXO 存在且未花费
        utxo_result = self._validate_inputs(tx)
        if not utxo_result.valid:
            return utxo_result
        
        # 5. 验证金额守恒 (输入 >= 输出 + fee)
        conservation_result = self._validate_amount_conservation(tx)
        if not conservation_result.valid:
            return conservation_result
        
        # 6. 根据交易类型执行特定规则
        type_result = self._validate_by_type(tx)
        if not type_result.valid:
            return type_result
        
        # 7. ZK 验证 (如果适用)
        if tx.zk_proof:
            zk_result = self._validate_zk_proof(tx)
            if not zk_result.valid:
                return zk_result
        
        return ValidationResult(True, message="Valid")
    
    def _validate_by_type(self, tx: 'Transaction') -> ValidationResult:
        """根据 BCS 交易类型执行特定规则"""
        
        if tx.tx_type == TxType.TRANSFER:
            return self._validate_transfer(tx)
        
        elif tx.tx_type == TxType.TRANSFER_SALE:
            return self._validate_sale(tx)
        
        elif tx.tx_type == TxType.TRANSFER_WAGE:
            return self._validate_wage(tx)
        
        elif tx.tx_type == TxType.MINT:
            return self._validate_mint(tx)
        
        elif tx.tx_type == TxType.REPLENISH:
            return self._validate_replenish(tx)
        
        elif tx.tx_type == TxType.REGISTER_IDENTITY:
            return self._validate_identity_registration(tx)
        
        else:
            return ValidationResult(False, ValidationError.INVALID_SCRIPT, f"Unknown tx type: {tx.tx_type}")
    
    def _validate_sale(self, tx: 'Transaction') -> ValidationResult:
        """
        销售规则验证:
        - 识别卖家 (input 拥有者) 和买家 (output 接收者)
        - 验证存在从卖家到买家的 N 转移
        - 验证 N_amount >= φ * external_amount
        """
        # 解析 extra 字段获取 external_amount 信息
        sale_info = SaleInfo.decode(tx.extra)
        
        # 识别各方
        seller = tx.inputs[0].owner_address  # 简化: 假设单一卖家
        buyer = sale_info.buyer_address
        
        # 计算 D 面额总额
        total_d = sale_info.denomination_amount
        
        # 查找流向买家的 N 输出
        buyer_n = sum(
            out.amount for out in tx.outputs 
            if out.recipient == buyer and out.asset_type == ASSET_N
        )
        
        # 计算最小所需 N
        required_n = int(total_d * self.params.phi)
        
        if buyer_n < required_n:
            return ValidationResult(
                False, 
                ValidationError.INVALID_PHI,
                f"Sale requires N >= {required_n}, got {buyer_n}"
            )
        
        # 验证卖家有足够 N 余额 (已包含在 conservation 检查中)
        return ValidationResult(True, message="Sale rules satisfied")
    
    def _validate_wage(self, tx: 'Transaction') -> ValidationResult:
        """
        工资规则验证:
        - 识别雇主和工人
        - 验证存在从工人到雇主的 N 转移 (ψ 比例)
        """
        wage_info = WageInfo.decode(tx.extra)
        
        employer = wage_info.employer_address
        worker = tx.inputs[0].owner_address
        
        total_d = wage_info.denomination_amount
        
        # 查找流向雇主的 N 输出
        employer_n = sum(
            out.amount for out in tx.outputs
            if out.recipient == employer and out.asset_type == ASSET_N
        )
        
        required_n = int(total_d * self.params.psi)
        
        if employer_n < required_n:
            return ValidationResult(
                False,
                ValidationError.INVALID_PSI,
                f"Wage requires N >= {required_n}, got {employer_n}"
            )
        
        return ValidationResult(True, message="Wage rules satisfied")
    
    def _validate_mint(self, tx: 'Transaction') -> ValidationResult:
        """N 初始发放验证 - 仅治理节点可执行"""
        # 验证签名包含治理多签
        if not self._check_governance_signature(tx):
            return ValidationResult(False, ValidationError.IDENTITY_NOT_AUTHORIZED, "Gov signature required")
        
        # 验证接收者身份已认证
        recipient = tx.outputs[0].recipient
        if not self.identity.is_authenticated(recipient):
            return ValidationResult(False, ValidationError.IDENTITY_NOT_AUTHORIZED, "Recipient not authenticated")
        
        # 验证发放金额在允许范围内
        if tx.outputs[0].amount > self.params.max_mint_per_account:
            return ValidationResult(False, ValidationError.INVALID_SCRIPT, "Mint amount exceeds limit")
        
        return ValidationResult(True)
```

### 10.2 Rust: 区块验证核心片段

```rust
// crates/bcs-core/src/validation.rs
use bcs_crypto::{sha3_256, ecdsa_verify};
use bcs_storage::UTXOTrie;

pub struct BlockValidator {
    utxo_trie: UTXOTrie,
    validator_set: Vec<[u8; 33]>, // Compressed pubkeys
    params: SystemParams,
}

impl BlockValidator {
    pub fn validate_block(&self, block: &Block, prev_header: &BlockHeader) -> Result<(), BlockError> {
        // 1. 验证版本
        if block.header.version != CURRENT_VERSION {
            return Err(BlockError::VersionMismatch);
        }
        
        // 2. 验证前向引用
        if block.header.prev_block_hash != sha3_256(&prev_header.encode()) {
            return Err(BlockError::PrevHashMismatch);
        }
        
        // 3. 验证时间戳单调性
        if block.header.timestamp <= prev_header.timestamp {
            return Err(BlockError::TimestampRegression);
        }
        
        // 4. 验证轮次
        let expected_validator_idx = (block.header.height % self.validator_set.len() as u64) as usize;
        let expected_validator = self.validator_set[expected_validator_idx];
        if block.header.validator_pubkey != expected_validator {
            return Err(BlockError::WrongValidator);
        }
        
        // 5. 验证签名
        let header_hash = block.header.hash();
        if !ecdsa_verify(&expected_validator, &header_hash, &block.header.signature) {
            return Err(BlockError::InvalidSignature);
        }
        
        // 6. 验证 Merkle 根
        let tx_hashes: Vec<_> = block.body.transactions.iter()
            .map(|tx| tx.hash())
            .collect();
        let expected_merkle_root = merkle_root(&tx_hashes);
        if block.header.merkle_root_tx != expected_merkle_root {
            return Err(BlockError::MerkleRootMismatch);
        }
        
        // 7. 验证每笔交易
        let mut utxo_trie_clone = self.utxo_trie.clone();
        for tx in &block.body.transactions {
            match self.validate_transaction(tx, &mut utxo_trie_clone) {
                Ok(_) => {}
                Err(e) => return Err(BlockError::TransactionInvalid(e)),
            }
        }
        
        // 8. 验证 UTXO 根
        let expected_utxo_root = utxo_trie_clone.root();
        if block.header.merkle_root_utxo != expected_utxo_root {
            return Err(BlockError::UTXORootMismatch);
        }
        
        Ok(())
    }
    
    fn validate_transaction(
        &self, 
        tx: &Transaction, 
        utxo_trie: &mut UTXOTrie
    ) -> Result<(), TxError> {
        // 基础验证...
        
        // UTXO 存在性 + 未花费验证
        for input in &tx.inputs {
            let utxo_key = format!("{}:{}", hex(&input.tx_hash), input.output_index);
            match utxo_trie.get(&utxo_key) {
                Some(utxo) => {
                    // 验证解锁脚本
                    if !self.verify_unlock_script(&utxo.lock_script, &input.unlock_script) {
                        return Err(TxError::InvalidScript);
                    }
                    // 标记为已花费
                    utxo_trie.remove(&utxo_key)?;
                }
                None => return Err(TxError::UTXONotFound),
            }
        }
        
        // 添加新 UTXO
        for (idx, output) in tx.outputs.iter().enumerate() {
            let utxo_key = format!("{}:{}", hex(&tx.hash()), idx);
            utxo_trie.insert(&utxo_key, output.encode())?;
        }
        
        Ok(())
    }
}
```

### 10.3 Python: 离线交易缓存

```python
# python/bcs_offline/cache.py
import sqlite3
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import List, Optional
import threading


@dataclass
class CachedTransaction:
    tx_hash: str
    tx_data: bytes           # 序列化交易
    tx_type: int
    created_at: datetime
    expires_at: datetime
    status: str             # pending | submitted | confirmed | failed | conflicted
    conflict_info: Optional[str] = None
    sequence_number: int = 0


class OfflineTxCache:
    """
    SQLite 离线交易缓存
    线程安全，支持 TTL 和状态管理
    """
    
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS offline_txs (
        tx_hash TEXT PRIMARY KEY,
        tx_data BLOB NOT NULL,
        tx_type INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        status TEXT DEFAULT 'pending',
        conflict_info TEXT,
        sequence_number INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_status ON offline_txs(status);
    CREATE INDEX IF NOT EXISTS idx_expires ON offline_txs(expires_at);
    """
    
    def __init__(self, db_path: str = ":memory:", default_ttl_hours: int = 72):
        self.db_path = db_path
        self.default_ttl = timedelta(hours=default_ttl_hours)
        self._lock = threading.RLock()
        
        self._init_db()
    
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(self.SCHEMA)
            conn.commit()
    
    def cache_tx(self, tx: 'Transaction', sequence_number: int = 0) -> str:
        """缓存新交易"""
        tx_hash = tx.hash_hex()
        now = datetime.utcnow()
        expires = now + self.default_ttl
        
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO offline_txs 
                       (tx_hash, tx_data, tx_type, created_at, expires_at, status, sequence_number)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (tx_hash, tx.encode(), tx.tx_type, now, expires, 'pending', sequence_number)
                )
                conn.commit()
        
        return tx_hash
    
    def get_pending(self, max_age_hours: Optional[int] = None) -> List[CachedTransaction]:
        """获取所有待提交的离线交易"""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                if max_age_hours:
                    cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
                    rows = conn.execute(
                        "SELECT * FROM offline_txs WHERE status = 'pending' AND created_at > ? ORDER BY sequence_number",
                        (cutoff,)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM offline_txs WHERE status = 'pending' ORDER BY sequence_number"
                    ).fetchall()
                
                return [self._row_to_cached(r) for r in rows]
    
    def update_status(self, tx_hash: str, status: str, conflict_info: Optional[str] = None):
        """更新交易状态"""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "UPDATE offline_txs SET status = ?, conflict_info = ? WHERE tx_hash = ?",
                    (status, conflict_info, tx_hash)
                )
                conn.commit()
    
    def clear_expired(self) -> int:
        """清理过期交易，返回清理数量"""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "DELETE FROM offline_txs WHERE expires_at < ?",
                    (datetime.utcnow(),)
                )
                conn.commit()
                return cursor.rowcount
    
    def get_stats(self) -> dict:
        """获取缓存统计"""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM offline_txs").fetchone()[0]
            pending = conn.execute("SELECT COUNT(*) FROM offline_txs WHERE status = 'pending'").fetchone()[0]
            expired = conn.execute(
                "SELECT COUNT(*) FROM offline_txs WHERE expires_at < ?",
                (datetime.utcnow(),)
            ).fetchone()[0]
            return {"total": total, "pending": pending, "expired": expired}
    
    def _row_to_cached(self, row: sqlite3.Row) -> CachedTransaction:
        return CachedTransaction(
            tx_hash=row['tx_hash'],
            tx_data=row['tx_data'],
            tx_type=row['tx_type'],
            created_at=datetime.fromisoformat(row['created_at']),
            expires_at=datetime.fromisoformat(row['expires_at']),
            status=row['status'],
            conflict_info=row['conflict_info'],
            sequence_number=row['sequence_number']
        )
```

### 10.4 Python: N 可行性检查 API

```python
# python/bcs_currency/feasibility.py
from decimal import Decimal, ROUND_DOWN
from dataclasses import dataclass
from typing import Optional


@dataclass
class FeasibilityResult:
    feasible: bool
    max_capacity: Decimal          # 最大允许销售容量 (D 面额)
    current_usage: Decimal         # 当前已用容量
    remaining: Decimal             # 剩余容量
    shortfall: Optional[Decimal] = None  # 缺口 (如果不可行)
    suggested_n: Optional[Decimal] = None  # 建议补充的 N 量


class FeasibilityChecker:
    """
    N 可行性约束检查器
    
    核心约束: 企业销售规模 (D 面额) <= N 持有量 / φ
    """
    
    def __init__(self, params: SystemParams, usage_tracker: 'UsageTracker'):
        self.phi = Decimal(str(params.phi))
        self.psi = Decimal(str(params.psi))
        self.sale_window_blocks = params.sale_window_blocks
        self.usage = usage_tracker
    
    def check_sale(
        self, 
        seller_address: bytes, 
        proposed_d_amount: Decimal,
        current_n_balance: Decimal,
        at_height: int
    ) -> FeasibilityResult:
        """
        检查销售交易是否满足 N 可行性约束
        
        Args:
            seller_address: 卖家地址
            proposed_d_amount: 拟销售的 D 面额金额
            current_n_balance: 当前 N 余额
            at_height: 当前区块高度
        """
        # 1. 计算最大销售容量
        max_capacity = (current_n_balance / self.phi).quantize(
            Decimal('0.01'), rounding=ROUND_DOWN
        )
        
        # 2. 获取当前周期已用容量 (滑动窗口)
        current_usage = self.usage.get_usage_in_window(
            seller_address, 
            from_height=at_height - self.sale_window_blocks,
            to_height=at_height
        )
        
        # 3. 计算剩余容量
        remaining = max_capacity - current_usage
        
        # 4. 检查可行性
        if proposed_d_amount <= remaining:
            return FeasibilityResult(
                feasible=True,
                max_capacity=max_capacity,
                current_usage=current_usage,
                remaining=remaining - proposed_d_amount,
                shortfall=None
            )
        else:
            shortfall = proposed_d_amount - remaining
            # 建议补充的 N = shortfall * φ
            suggested_n = (shortfall * self.phi).quantize(Decimal('0.01'), rounding=ROUND_DOWN)
            
            return FeasibilityResult(
                feasible=False,
                max_capacity=max_capacity,
                current_usage=current_usage,
                remaining=remaining if remaining > 0 else Decimal('0'),
                shortfall=shortfall,
                suggested_n=suggested_n
            )
    
    def get_capacity_report(self, address: bytes, n_balance: Decimal, at_height: int) -> dict:
        """生成完整的容量报告"""
        max_capacity = (n_balance / self.phi).quantize(Decimal('0.01'))
        current_usage = self.usage.get_usage_in_window(
            address,
            from_height=at_height - self.sale_window_blocks,
            to_height=at_height
        )
        
        return {
            "address": address.hex(),
            "n_balance": str(n_balance),
            "phi": str(self.phi),
            "max_sale_capacity": str(max_capacity),
            "current_period_usage": str(current_usage),
            "remaining_capacity": str(max_capacity - current_usage),
            "sale_window_blocks": self.sale_window_blocks,
            "utilization_rate": float(current_usage / max_capacity) if max_capacity > 0 else 0.0
        }
```

---

## 11. 项目审计与优化清单

本节基于当前工程目录 `bcs_chain/`、测试目录、Docker 配置、README 与本文档的一致性审计整理。状态说明: `已改进` 表示本轮已落地到代码或配置；`建议实施` 表示需要后续较大实现或验证闭环。

| # | 优化点 | 风险/收益 | 状态 |
|---|--------|-----------|------|
| 1 | 统一文档中的模块路径，从早期 `bcs_core/`、`bcs_offline/` 调整为实际 `bcs_chain/core/`、`bcs_chain/offline/` | 降低新人按文档找不到代码的成本 | 建议实施 |
| 2 | 为 Python 项目增加 `pyproject.toml`，声明包元数据、依赖、测试入口和 CLI 入口 | 安装、测试、工具链更标准 | 已改进 |
| 3 | 增加 `.gitignore`，排除 `__pycache__`、数据库、运行数据、密钥、日志和本地配置 | 避免提交运行产物和敏感文件 | 已改进 |
| 4 | 增加 `.dockerignore`，减少 Docker 构建上下文中的缓存、测试输出和本地数据 | 提升构建速度，降低泄露风险 | 已改进 |
| 5 | 修复 Docker 镜像内包路径，保持 `/app/bcs_chain` 包目录结构 | 避免 `python -m bcs_chain.node` 在容器内找不到包 | 已改进 |
| 6 | 同步修正 `docker-compose.yml` 的配置挂载路径 | 避免容器读取旧 `/app/config` 路径失败 | 已改进 |
| 7 | 同步修正 `docker-compose.prod.yml` 的配置挂载路径 | 避免生产 compose 与镜像布局不一致 | 已改进 |
| 8 | 在 `bcs_chain/__init__.py` 增加兼容导入路径安装器 | 让包导入和历史脚本式导入同时可用 | 已改进 |
| 9 | 后续将 `from core...`、`from api...` 逐步迁移为显式相对导入 | 减少 `sys.path` 兼容层依赖 | 建议实施 |
| 10 | 离线模块应从 `_core_stubs` 迁移到真实 `core` 数据结构或明确拆分 DTO | 降低原型桩代码与主链模型漂移 | 建议实施 |
| 11 | `_core_stubs.Transaction.serialize()` 使用 `pickle`，应替换为 JSON/msgpack/确定性二进制编码 | 避免反序列化执行风险和跨版本不稳定 | 建议实施 |
| 12 | 当前环境缺少 `pytest`，应在开发环境固定安装 `.[dev]` 或 requirements dev 分组 | 保证测试可复现 | 建议实施 |
| 13 | `requirements.txt` 只有下限，生产应增加锁文件或约束文件 | 避免依赖上游破坏性更新 | 建议实施 |
| 14 | README 的 Docker 命令需与修正后的包路径和构建上下文保持一致 | 降低部署操作误差 | 建议实施 |
| 15 | 默认配置中 `cors_origins = ["*"]` 应仅用于开发，生产使用显式域名 | 降低跨站调用风险 | 建议实施 |
| 16 | 默认监听 `0.0.0.0` 应区分本地开发、容器和生产配置 | 避免本机误暴露 API | 建议实施 |
| 17 | 测试网配置内硬编码 validator 私钥应标记为示例密钥并禁止生产复用 | 降低密钥误用风险 | 建议实施 |
| 18 | 节点启动应校验生产环境中是否使用示例私钥、通配 CORS 或非 TLS API | 防止不安全配置上线 | 建议实施 |
| 19 | gRPC 当前 `add_insecure_port` 仅适合内网，应增加 TLS/mTLS 配置路径 | 提升节点间认证与传输安全 | 建议实施 |
| 20 | REST/gRPC 错误码与拒绝原因应统一错误模型 | 便于钱包和 SDK 处理失败 | 建议实施 |
| 21 | API schema 与 core model 之间应增加版本字段和兼容转换测试 | 避免协议升级破坏客户端 | 建议实施 |
| 22 | 交易哈希需明确是否包含 witness、unlock_script、ZK proof，并为所有模块统一 | 避免签名域不一致 | 建议实施 |
| 23 | UTXO 金额、外部支付金额和比例计算应统一整数/有理数表示 | 避免 Decimal、int 混用产生边界误差 | 建议实施 |
| 24 | φ/ψ 规则引擎应增加边界测试: 四舍五入、0 金额、超大金额、多输出拆分 | 提升经济规则可靠性 | 建议实施 |
| 25 | MINT/REPLENISH/BURN 应统一走治理多签验证，不应仅依赖交易类型 | 防止权限绕过 | 建议实施 |
| 26 | DID/VC 注册交易应绑定链上身份状态变更和可审计事件 | 提升身份生命周期可追踪性 | 建议实施 |
| 27 | 信任锚列表应支持轮换、吊销和生效高度 | 降低长期公钥泄露风险 | 建议实施 |
| 28 | 离线交易缓存应加密敏感字段并支持用户钱包级密钥 | 降低设备丢失后的隐私风险 | 建议实施 |
| 29 | 离线交易 TTL、sequence、priority 应写入协议字段而非仅本地元数据 | 提升多设备同步一致性 | 建议实施 |
| 30 | 冲突解决应输出机器可读原因和用户可读建议 | 改善钱包交互和自动重试 | 建议实施 |
| 31 | Light client state proof 目前仍偏简化，应落地可验证 Merkle/Patricia proof | 支撑真实离线验真 | 建议实施 |
| 32 | ZK 模块当前为教学/原型证明，应明确安全级别并隔离生产开关 | 避免误认为已达到生产零知识安全 | 建议实施 |
| 33 | Pedersen 参数、nullifier 域分隔和 circuit id 应有协议版本登记表 | 防止跨电路重放和参数混淆 | 建议实施 |
| 34 | P2P 消息应增加网络 ID、协议版本、消息 nonce 和过期时间 | 避免跨网污染、重放和 gossip 放大 | 建议实施 |
| 35 | P2P peer reputation 应持久化并设置恢复策略 | 防止重启丢失惩罚状态 | 建议实施 |
| 36 | 共识验证者集变更应明确生效高度和回滚规则 | 降低 validator change 的分叉风险 | 建议实施 |
| 37 | 区块存储应增加 schema migration 和数据版本 | 支撑长期升级 | 建议实施 |
| 38 | `simulation/output` 应作为生成产物，报告模板与原始输出分离 | 避免把一次性结果误当基准 | 建议实施 |
| 39 | CLI 中标注 `stub` 的命令应分为可用、实验、未实现三类并给出退出码 | 改善自动化脚本可判断性 | 建议实施 |
| 40 | 钱包导入私钥和助记词的命令行参数应避免 shell 历史泄露，优先交互输入或文件描述符 | 降低密钥泄露风险 | 建议实施 |
| 41 | 增加最小 smoke test: 包导入、配置加载、Docker compose config、交易序列化 | 快速发现基础破坏 | 建议实施 |
| 42 | 增加端到端离线流程测试: 创建、缓存、重连、冲突、确认 | 覆盖系统核心卖点 | 建议实施 |
| 43 | 增加性能基准: mempool 入池、块验证、UTXO 查询、离线批量同步 | 量化轻量链目标 | 建议实施 |
| 44 | 增加威胁模型文档: 双花、离线欺诈、身份冒用、治理密钥泄露、ZK 参数污染 | 指导安全优先级 | 建议实施 |
| 45 | 生产部署应补充 secrets 管理、备份恢复、监控告警和日志脱敏规范 | 降低运维事故风险 | 建议实施 |

### 本轮已落地改进

1. 新增 `pyproject.toml`，补齐包元数据、依赖、开发依赖、pytest 配置、ruff 基础配置和 `bcs` CLI 入口。
2. 新增 `.gitignore` 与 `.dockerignore`，阻止 Python 缓存、数据库、运行数据、密钥、日志和本地环境文件进入版本库或 Docker 上下文。
3. 修复 Dockerfile 的包复制路径，使节点和客户端镜像保留 `bcs_chain` 包目录，`python -m bcs_chain.node` 与 `python -m bcs_chain.cli.main` 可按模块方式运行。
4. 修复开发与生产 compose 中配置文件挂载路径，匹配新的 `/app/bcs_chain/config/...` 镜像布局。
5. 在包初始化中增加兼容导入路径安装器，缓解当前代码中历史脚本式导入与包式导入混用导致的导入失败。
6. 更新 README 的开发安装和 pytest 命令，避免测试路径与当前仓库布局不一致。
7. 补充 MIT `LICENSE` 文件，使 README 中的许可证声明有实际文件承接。

### 后续优先级建议

优先级 P0: 移除不安全 `pickle` 反序列化、补齐依赖锁定、修复生产不安全默认项、完成 Docker compose config 校验。

优先级 P1: 统一核心数据模型与离线 DTO、补齐交易哈希/签名域规范、补齐治理权限验证、增加离线端到端测试。

优先级 P2: 完善 P2P 协议版本化、ZK 参数登记、light client 可验证状态证明、生产监控和威胁模型文档。

---

## 设计总结

本架构文档完整定义了 BCS (Bidirectional Currency System) 逆向货币系统的技术实现路径，核心设计要点总结如下:

1. **UTXO 模型**: 选择 UTXO 而非账户制，天然支持离线并行交易、精确追踪 N 货币流转、与 BTC 范式一致。

2. **PoA-BFT 共识**: 轻量无需挖矿，5 秒出块，2/3 签名达最终性，适合授权节点网络。

3. **离线优先**: SQLite 本地缓存、乐观 UTXO 视图、重连后批量同步 + 冲突自动解决。

4. **BCS 规则引擎**: φ (销售比例) 和 ψ (工资比例) 在交易验证层强制执行，N 可行性约束实时计算。

5. **身份层**: `did:bcs` 自研方法 + VC 验证，认证用户获得初始 N，支持后续补充。

6. **隐私可选**: ZK 电路支持 shielded transaction，public/shielded 混合模式。

7. **渐进交付**: 三阶段里程碑 (MVP → Privacy → Production)，每阶段有明确裁剪范围。

8. **技术栈**: Python 为主 (业务逻辑/规则/REST API)，Rust 为核 (密码学/共识/存储/网络)。

---

*文档结束。本设计可直接指导工程团队实现 BCS 系统的生产级部署。*
