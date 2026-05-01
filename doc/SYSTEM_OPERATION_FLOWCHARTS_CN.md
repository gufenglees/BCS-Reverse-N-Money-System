# BCS 逆向货币离线支付系统运行流程框图

> 文档类型: 系统运行流程、业务操作流程、链上验证流程、治理流程  
> 适用项目: BCS Chain / 逆向货币离线支付系统  
> 图表格式: Mermaid Markdown  
> 编写日期: 2026-05-01

---

## 1. 系统运行总览

系统整体运行可以理解为五条主线同时协作:

1. 用户侧: 创建钱包、完成身份认证、发起交易、离线缓存、同步确认。
2. 节点侧: 接收交易、验证规则、进入 mempool、出块、提交状态。
3. 经济规则侧: 校验销售 `phi`、工资 `psi`、N 可行性和 N 生命周期。
4. 身份治理侧: DID/VC 认证、信任锚、治理多签、参数变更。
5. 外部支付侧: 现实货币/银行/现金/支付网关/发票/工资单只作为可选凭证引用，链上不处理 D 资产。
5. 网络运维侧: P2P 广播、区块同步、API 查询、监控告警。

```mermaid
flowchart TD
    A[用户/商户/雇主/工人] --> B[钱包/CLI/SDK/业务系统]
    B --> C{是否在线}
    C -- 在线 --> D[REST/gRPC 提交交易]
    C -- 离线 --> E[离线交易构建与本地缓存]
    E --> F[乐观 UTXO 视图更新]
    F --> G[重连后批量同步]
    G --> D

    D --> H[节点 API 层]
    H --> I[交易 Schema 校验]
    I --> J[核心交易验证器]
    J --> K[签名/脚本/UTXO 验证]
    K --> L[BCS 规则验证 phi/psi/N]
    L --> M[身份/治理权限验证]
    M --> N{验证是否通过}
    N -- 否 --> O[返回结构化错误]
    N -- 是 --> P[Mempool 入池]
    P --> Q[P2P 广播交易]
    P --> R[PoA-BFT 共识出块]
    R --> S[区块验证]
    S --> T[提交区块与状态]
    T --> U[更新 UTXO/账户/身份/治理参数]
    U --> V[API/钱包查询确认状态]

    Q --> W[其他节点接收交易]
    W --> J
```

---

## 2. 节点启动与运行流程

节点启动时，需要加载配置、初始化存储、恢复链状态、启动 API、P2P 和共识任务。验证者节点会参与出块，观察者节点只同步和提供查询服务。

```mermaid
flowchart TD
    A[启动节点进程 python -m bcs_chain.node] --> B[读取 TOML 配置]
    B --> C{配置文件是否存在}
    C -- 否 --> D[使用默认配置并输出警告]
    C -- 是 --> E[解析 network/consensus/storage/governance/api]

    D --> F[创建 NodeConfig]
    E --> F
    F --> G[安全配置检查]
    G --> H{是否生产模式}
    H -- 是 --> I[检查 TLS/CORS/示例私钥/数据目录]
    H -- 否 --> J[允许开发默认值]
    I --> K{检查是否通过}
    K -- 否 --> L[拒绝启动并输出原因]
    K -- 是 --> M[初始化数据目录与数据库]
    J --> M

    M --> N[加载区块存储与索引]
    N --> O[恢复最新区块高度]
    O --> P[初始化 UTXOSet/StateManager]
    P --> Q[初始化 CurrencyRulesEngine]
    Q --> R[初始化 IdentityRegistry/TrustAnchor]
    R --> S[初始化 TxCache/Offline Sync]
    S --> T[初始化 Mempool]
    T --> U[初始化 PoA-BFT Consensus]
    U --> V[启动 REST API]
    V --> W[启动 gRPC API]
    W --> X[启动 P2P 网络]
    X --> Y{是否验证者节点}
    Y -- 是 --> Z[启动出块循环]
    Y -- 否 --> AA[启动观察者同步循环]
    Z --> AB[运行中: 接收交易/出块/同步/监控]
    AA --> AB
```

---

## 3. 身份认证流程

身份认证由 DID、VC、信任锚和链上注册交易组成。用户先在本地生成密钥和 DID，再由信任锚签发 VC，最后提交链上身份注册交易。认证成功后，用户才能获得 N 初始发放或参与特定权限交易。

```mermaid
flowchart TD
    A[用户打开钱包] --> B[生成 secp256k1 私钥/公钥]
    B --> C[派生地址与 did:bcs:pubkey_hash]
    C --> D[生成 DID Document]
    D --> E[向信任锚提交身份材料]
    E --> F[信任锚线下/外部审核]
    F --> G{审核是否通过}
    G -- 否 --> H[拒绝认证并返回原因]
    G -- 是 --> I[签发 VC: BCSIdentityCredential]

    I --> J[用户构造 REGISTER_IDENTITY 交易]
    J --> K[先请求 DIDAuth challenge]
    K --> L[钱包本地密码解锁 DID 私钥]
    L --> M[签名 challenge 表示同意注册]
    M --> N[提交 DID Document + VC + signature]
    N --> O[节点验证 DID 控制权]
    O --> P[验证 VC issuer 是否为可信 Trust Anchor]
    P --> P2[验证 VC 签名/过期时间/subject DID]
    P2 --> Q{身份交易是否有效}
    Q -- 否 --> Q2[拒绝: DID/VC/签名错误]
    Q -- 是 --> R[进入 PENDING 身份注册表]
    R --> S[打包进区块]
    S --> T[IdentityRegistry 更新状态]
    T --> U{认证策略}
    U -- 直接认证 --> V[状态 AUTHENTICATED]
    U -- 人工复核 --> W[状态 PENDING]
    W --> X[治理或信任锚复核]
    X --> V
    V --> Y[允许接收 MINT/REPLENISH/权限交易]
```

### 3.1 身份状态流转

```mermaid
stateDiagram-v2
    [*] --> UNAUTHENTICATED: 钱包创建但未注册
    UNAUTHENTICATED --> PENDING: 提交 REGISTER_IDENTITY
    PENDING --> AUTHENTICATED: VC 验证/治理确认
    AUTHENTICATED --> SUSPENDED: 风险控制/临时冻结
    SUSPENDED --> AUTHENTICATED: 解除冻结
    AUTHENTICATED --> REVOKED: 吊销身份
    SUSPENDED --> REVOKED: 风险升级
    REVOKED --> [*]: 不再具备系统权限
```

---

## 4. N 货币发放与补充流程

N 货币的 MINT 和 REPLENISH 必须受身份与治理约束。普通用户不能任意铸造 N。

```mermaid
flowchart TD
    A[用户身份 AUTHENTICATED] --> B[申请初始 N 或补充 N]
    B --> C[钱包/业务系统生成申请]
    C --> D[治理节点/发行模块检查条件]
    D --> E{是否满足发放条件}
    E -- 否 --> F[拒绝: 身份无效/额度不足/周期未到]
    E -- 是 --> G[构造 MINT 或 REPLENISH 交易]
    G --> H[收集治理多签]
    H --> I{签名数是否达到阈值}
    I -- 否 --> J[等待更多治理签名]
    I -- 是 --> K[提交交易到节点]
    K --> L[验证接收者身份状态]
    L --> M[验证治理签名]
    M --> N[验证总供应上限/补充规则]
    N --> O{验证是否通过}
    O -- 否 --> P[拒绝交易]
    O -- 是 --> Q[进入 mempool]
    Q --> R[出块确认]
    R --> S[创建新的 N UTXO]
    S --> T[更新账户 N 余额与供应统计]
```

---

## 5. 治理提案与表决流程

治理用于修改系统参数、验证者集合、信任锚列表和关键权限。治理流程必须具备提案、投票、阈值判断、等待期和生效高度。

```mermaid
flowchart TD
    A[治理成员/治理合约发起提案] --> B[定义 Proposal]
    B --> C[提案内容: 参数/验证者/信任锚/N 供应]
    C --> D[设置 voting_period 与 effective_height]
    D --> E[提交 GOV_PROPOSAL 交易]
    E --> F[节点验证提案发起权限]
    F --> G{提案是否合法}
    G -- 否 --> H[拒绝提案]
    G -- 是 --> I[提案上链并进入 ACTIVE]

    I --> J[治理成员查看提案]
    J --> K[提交 GOV_VOTE 交易]
    K --> L[验证投票者身份与权重]
    L --> M[累计赞成/反对/弃权]
    M --> N{投票期是否结束}
    N -- 否 --> J
    N -- 是 --> O{是否达到通过阈值}
    O -- 否 --> P["提案状态 REJECTED/EXPIRED"]
    O -- 是 --> Q[生成 GOV_CERT 治理证书]
    Q --> R[等待 effective_height]
    R --> S[到达生效高度]
    S --> T[应用参数/验证者/信任锚变更]
    T --> U[记录治理事件与审计日志]
```

### 5.1 治理提案状态机

```mermaid
stateDiagram-v2
    [*] --> DRAFT: 本地创建
    DRAFT --> ACTIVE: GOV_PROPOSAL 上链
    ACTIVE --> PASSED: 达到赞成阈值
    ACTIVE --> REJECTED: 反对超过阈值
    ACTIVE --> EXPIRED: 投票期结束未达阈值
    PASSED --> QUEUED: 等待生效高度
    QUEUED --> EXECUTED: 到达生效高度并应用
    REJECTED --> [*]
    EXPIRED --> [*]
    EXECUTED --> [*]
```

### 5.2 参数变更时序

```mermaid
sequenceDiagram
    participant G as 治理成员
    participant API as 节点 API
    participant C as 共识节点
    participant S as 状态存储
    participant W as 钱包/离线节点

    G->>API: 提交 phi/psi 参数变更提案
    API->>C: 验证提案权限并广播
    C->>S: 提案上链: ACTIVE
    G->>API: 多个治理成员提交投票
    API->>C: 验证投票权与签名
    C->>S: 统计投票
    C->>S: 提案通过，设置 effective_height
    W->>API: 同步参数变更通知
    C->>S: 到达生效高度，切换参数版本
    W->>W: 离线交易按新参数检测冲突
```

---

## 6. 在线普通 N 转账流程

普通 N 转账不涉及外部支付金额，也不触发 `phi` 或 `psi` 规则，但仍需验证 UTXO、签名、金额和手续费。

```mermaid
flowchart TD
    A[付款方钱包] --> B[查询可用 UTXO]
    B --> C[选择输入]
    C --> D[构造输出: 收款方 + 找零]
    D --> E[估算手续费]
    E --> F{输入金额是否足够}
    F -- 否 --> G[提示余额不足]
    F -- 是 --> H[生成交易签名]
    H --> I[提交节点 API]
    I --> J[验证交易格式]
    J --> K[验证输入 UTXO 存在]
    K --> L[验证 unlock_script/签名]
    L --> M["验证输入总额 >= 输出总额 + fee"]
    M --> N{是否有效}
    N -- 否 --> O[返回错误码]
    N -- 是 --> P[进入 mempool]
    P --> Q[共识出块]
    Q --> R[区块提交]
    R --> S[删除已花费 UTXO]
    S --> T[创建新 UTXO]
    T --> U[钱包查询交易确认]
```

---

## 7. 销售交易流程 `TRANSFER_SALE`

销售交易是 BCS 的核心流程。买方可通过现实货币、现金、银行或支付网关完成付款；这些凭证引用是可选 metadata。链上只要求交易提供 `external_amount` 作为 `phi` 的计算基数，并结算对应 N。卖方必须按 `phi` 向买方转移 N。

```mermaid
flowchart TD
    A[买方发起购买订单] --> B[业务系统生成外部支付金额与订单哈希]
    B --> C[卖方钱包读取当前 phi]
    C --> D["计算最低 N 回馈: ceil(external_amount * phi)"]
    D --> E[查询卖方 N UTXO]
    E --> F{卖方 N 是否足够}
    F -- 否 --> G["交易失败: N 不足/销售容量不足"]
    F -- 是 --> H[构造 TRANSFER_SALE 交易]
    H --> I[输入: 卖方 N UTXO]
    H --> J[输出: 买方 N 回馈]
    H --> K[输出: 卖方找零]
    H --> L["extra: seller/buyer/external_amount/optional_payment_ref/params_version"]
    I --> M[卖方签名]
    J --> M
    K --> M
    L --> M
    M --> N[提交节点]

    N --> O[基础交易验证]
    O --> P[UTXO 与签名验证]
    P --> Q[读取当前 phi 参数]
    Q --> R[从 extra 解析外部支付金额/凭证与角色]
    R --> S[汇总流向买方的 N 输出]
    S --> T{"N_to_buyer >= ceil(external_amount * phi)"}
    T -- 否 --> U[拒绝: SALE_RATIO_TOO_LOW]
    T -- 是 --> V["检查卖方 N 可行性/销售窗口"]
    V --> W{容量是否足够}
    W -- 否 --> X[拒绝: SALE_CAPACITY_EXCEEDED]
    W -- 是 --> Y[进入 mempool]
    Y --> Z[出块确认并更新 UTXO]
```

### 7.1 销售交易参与方时序

```mermaid
sequenceDiagram
    participant Buyer as 买方
    participant SellerWallet as 卖方钱包
    participant API as 节点 API
    participant Validator as 交易验证器
    participant Chain as 区块链状态

    Buyer->>SellerWallet: 下单并确认外部支付金额
    SellerWallet->>API: 查询 phi 与卖方 UTXO
    API-->>SellerWallet: 返回参数与 UTXO
    SellerWallet->>SellerWallet: 计算最低 N 回馈
    SellerWallet->>SellerWallet: 构造并签名 TRANSFER_SALE
    SellerWallet->>API: 提交交易
    API->>Validator: 校验 schema 与交易
    Validator->>Chain: 查询 UTXO/身份/参数
    Chain-->>Validator: 返回状态
    Validator-->>API: 验证通过
    API->>Chain: 进入 mempool 等待出块
    Chain-->>Buyer: 买方查询到 N 回馈确认
```

---

## 8. 工资交易流程 `TRANSFER_WAGE`

工资交易中，雇主可通过现实支付系统、银行、现金或工资单流程发薪；工资单/流水/支付网关引用是可选 metadata。链上只要求 `external_amount` 作为 `psi` 的计算基数，并结算对应 N。工人必须按 `psi` 向雇主转移 N。

```mermaid
flowchart TD
    A[雇主确认工资业务] --> B[确定 external_amount]
    B --> C[工人钱包读取当前 psi]
    C --> D["计算最低 N 回馈: ceil(external_amount * psi)"]
    D --> E[查询工人 N UTXO]
    E --> F{工人 N 是否足够}
    F -- 否 --> G[交易失败: 工人 N 不足]
    F -- 是 --> H[构造 TRANSFER_WAGE 交易]
    H --> I[输入: 工人 N UTXO]
    H --> J[输出: 雇主 N 回馈]
    H --> K[输出: 工人找零]
    H --> L["extra: employer/worker/external_amount/optional_payroll_ref/params_version"]
    I --> M[工人签名]
    J --> M
    K --> M
    L --> M
    M --> N[提交节点]
    N --> O[基础验证 + UTXO + 签名]
    O --> P[读取 psi 参数]
    P --> Q[解析工资外部支付金额与角色]
    Q --> R[汇总流向雇主的 N 输出]
    R --> S{"N_to_employer >= ceil(external_amount * psi)"}
    S -- 否 --> T[拒绝: WAGE_RATIO_TOO_LOW]
    S -- 是 --> U[进入 mempool]
    U --> V[出块确认]
    V --> W[更新双方 N 余额]
```

---

## 9. 离线支付创建、缓存与同步流程

离线支付是系统的重点能力。离线交易先在本地构建和缓存，重连后再同步到链上。

```mermaid
flowchart TD
    A[钱包处于离线状态] --> B[读取最近同步的 UTXO 快照]
    B --> C[用户输入收款方/金额/交易类型]
    C --> D[本地规则预校验]
    D --> E{本地 UTXO 是否足够}
    E -- 否 --> F[提示余额不足]
    E -- 是 --> G[构造离线交易]
    G --> H[用户本地签名]
    H --> I[写入 SQLite TxCache]
    I --> J[状态: CACHED]
    J --> K[更新乐观 UTXO 视图]
    K --> L[本地显示: 待同步]

    L --> M[网络恢复]
    M --> N[SyncEngine 获取最新区块头]
    N --> O[寻找共同祖先/下载缺失区块]
    O --> P[更新本地链上 UTXO 视图]
    P --> Q[逐笔检查缓存交易]
    Q --> R{输入是否仍未花费}
    R -- 否 --> S[标记 DOUBLE_SPEND 冲突]
    R -- 是 --> T{参数/身份/TTL 是否仍有效}
    T -- 否 --> U[标记 RULE_CHANGE/TIMEOUT/IDENTITY 冲突]
    T -- 是 --> V[提交交易到节点]
    V --> W{节点是否接受}
    W -- 否 --> X[记录拒绝原因]
    W -- 是 --> Y[状态: PENDING_NETWORK]
    Y --> Z[区块确认后状态: CONFIRMED]
    S --> AA[ConflictResolver 尝试解决]
    U --> AA
    X --> AA
```

### 9.1 离线交易状态机

```mermaid
stateDiagram-v2
    [*] --> DRAFT: 用户创建交易草稿
    DRAFT --> SIGNED_LOCAL: 本地签名
    SIGNED_LOCAL --> CACHED: 写入本地缓存
    CACHED --> PENDING_NETWORK: 重连后提交节点
    PENDING_NETWORK --> CONFIRMED: 区块确认
    CACHED --> CONFLICTED: 重连检测冲突
    PENDING_NETWORK --> REJECTED: 节点拒绝
    CONFLICTED --> RESOLVED: 重建/调整成功
    CONFLICTED --> REJECTED: 无法解决
    RESOLVED --> PENDING_NETWORK: 重新提交
    CONFIRMED --> [*]
    REJECTED --> [*]
```

### 9.2 离线冲突处理流程

```mermaid
flowchart TD
    A[检测到离线交易冲突] --> B{冲突类型}
    B -- DOUBLE_SPEND --> C[检查是否有替代 UTXO]
    C --> D{是否可重建}
    D -- 是 --> E[重建交易并请求用户重新签名]
    D -- 否 --> F[拒绝交易并提示余额不足]

    B -- RULE_CHANGE --> G[读取新 phi/psi]
    G --> H[重新计算最低 N]
    H --> I{找零是否足够补差额}
    I -- 是 --> J[调整输出并重新签名]
    I -- 否 --> K[拒绝或提示补充 N]

    B -- TIMEOUT --> L[检查是否允许刷新 TTL]
    L --> M{是否允许}
    M -- 是 --> N[重建交易并更新过期时间]
    M -- 否 --> O[拒绝: 已过期]

    B -- IDENTITY_CHANGE --> P[查询身份当前状态]
    P --> Q{身份是否恢复有效}
    Q -- 是 --> R[重新提交]
    Q -- 否 --> S[拒绝: 身份无效]

    E --> T[提交新交易]
    J --> T
    N --> T
    R --> T
    T --> U{提交是否成功}
    U -- 是 --> V[状态 RESOLVED/PENDING_NETWORK]
    U -- 否 --> W[保留冲突并等待用户处理]
```

---

## 10. ZK 隐私交易流程

ZK 当前适合作为隐私扩展原型。隐私交易通过 commitment 隐藏金额，通过 nullifier 防双花，通过 proof 证明规则成立。

```mermaid
flowchart TD
    A[用户选择隐私模式] --> B[钱包读取私有 UTXO/note]
    B --> C[生成输入 nullifier]
    C --> D[生成输出 commitment]
    D --> E[构造 ZK witness]
    E --> F[Prover 生成 proof]
    F --> G[交易携带 proof/public_inputs/circuit_id]
    G --> H[提交节点]
    H --> I[验证 circuit_id 是否支持]
    I --> J[验证 nullifier 未使用]
    J --> K[Verifier 验证 proof]
    K --> L{证明是否有效}
    L -- 否 --> M[拒绝 ZK_PROOF_INVALID]
    L -- 是 --> N[记录 nullifier]
    N --> O[写入新 commitment]
    O --> P[交易进入 mempool/出块]
```

---

## 11. API 请求处理流程

```mermaid
flowchart TD
    A[客户端请求 REST/gRPC] --> B[网关/反向代理]
    B --> C[API 服务]
    C --> D[中间件: 日志/限流/CORS]
    D --> E[Schema 校验]
    E --> F{请求是否合法}
    F -- 否 --> G[返回 4xx 结构化错误]
    F -- 是 --> H{请求类型}
    H -- 查询 --> I[读取存储/状态/索引]
    H -- 提交交易 --> J[转换为 Core Transaction]
    H -- 离线批次 --> K[批量解析交易]
    H -- 身份注册 --> L[解析 DID/VC 请求]
    H -- 治理操作 --> M[解析 Proposal/Vote]

    I --> N[返回数据]
    J --> O[调用交易验证器]
    K --> O
    L --> O
    M --> O
    O --> P{验证是否通过}
    P -- 否 --> Q[返回错误码与原因]
    P -- 是 --> R[写入 mempool/状态机]
    R --> S[返回 tx_hash/status]
```

---

## 12. 实际用户使用流程

### 12.1 普通用户首次使用

```mermaid
flowchart TD
    A[下载安装钱包/CLI] --> B[创建钱包密码]
    B --> C[生成私钥/地址/DID]
    C --> D[备份助记词或密钥]
    D --> E[提交身份认证材料]
    E --> F[获得 VC]
    F --> G[提交链上身份注册]
    G --> H[等待确认]
    H --> I{身份是否认证}
    I -- 否 --> J[查看失败原因或等待复核]
    I -- 是 --> K[接收初始 N 发放]
    K --> L[查询余额]
    L --> M[发起在线或离线交易]
```

### 12.2 商户实际收款与销售

```mermaid
flowchart TD
    A[商户后台创建商品订单] --> B[买家通过现实支付系统付款]
    B --> C[商户系统可选记录支付凭证哈希]
    C --> D[商户钱包检查 N 余额与销售容量]
    D --> E{容量是否足够}
    E -- 否 --> F[提示补充 N/降低订单金额]
    E -- 是 --> G[构造销售交易]
    G --> H[商户签名]
    H --> I[提交链上]
    I --> J[等待确认]
    J --> K{交易是否确认}
    K -- 否 --> L[展示错误或重试]
    K -- 是 --> M[订单完成]
    M --> N[买家收到 N 回馈]
    M --> O[商户更新销售容量报表]
```

### 12.3 雇主发薪

```mermaid
flowchart TD
    A[雇主生成工资批次] --> B[计算每位工人的 D 工资]
    B --> C[通知工人钱包准备 N 回馈]
    C --> D[工人钱包检查 N 余额]
    D --> E{N 是否足够}
    E -- 否 --> F[提示工人补充 N 或人工处理]
    E -- 是 --> G[构造工资交易]
    G --> H[工人签名确认]
    H --> I[提交节点]
    I --> J[验证 psi 比例]
    J --> K{是否通过}
    K -- 否 --> L[工资交易异常]
    K -- 是 --> M[交易确认]
    M --> N[雇主收到 N 回馈]
    M --> O[工资批次完成]
```

### 12.4 用户离线支付

```mermaid
flowchart TD
    A[用户无网络] --> B[打开钱包离线模式]
    B --> C[选择收款方与金额]
    C --> D[钱包基于本地 UTXO 构建交易]
    D --> E[用户签名]
    E --> F[生成离线交易文件/二维码/本地缓存]
    F --> G[收款方标记为待结算]
    G --> H[用户恢复网络]
    H --> I[钱包自动同步]
    I --> J{交易是否上链}
    J -- 是 --> K[收款方状态变为已确认]
    J -- 否 --> L[展示冲突原因]
    L --> M[重建交易/人工处理/取消]
```

---

## 13. 运维监控与故障处理流程

```mermaid
flowchart TD
    A[监控系统采集指标] --> B[区块高度/peer/mempool/API/磁盘/错误率]
    B --> C{是否触发告警}
    C -- 否 --> D[持续监控]
    C -- 是 --> E[告警通知运维]
    E --> F{故障类型}
    F -- 节点停止 --> G[检查进程/容器/日志]
    F -- 高度落后 --> H[检查 P2P/共识/数据库]
    F -- API 错误率高 --> I[检查网关/限流/异常请求]
    F -- 磁盘不足 --> J[扩容/归档/清理日志]
    F -- 验证者异常 --> K[切换/重启/治理处理]
    G --> L[恢复服务]
    H --> L
    I --> L
    J --> L
    K --> L
    L --> M[复盘并记录事件]
```

---

## 14. 系统完整闭环流程

下面的流程把身份、N 发放、交易、治理、离线和运维放到一个闭环中。

```mermaid
flowchart TD
    A[系统部署多节点网络] --> B[治理初始化参数 phi/psi/验证者/信任锚]
    B --> C[用户创建钱包与 DID]
    C --> D[信任锚签发 VC]
    D --> E[用户注册身份上链]
    E --> F[治理多签发放初始 N]
    F --> G[用户开始普通转账/销售/工资交易]
    G --> H[节点验证 UTXO/签名/身份/BCS 规则]
    H --> I[PoA-BFT 出块确认]
    I --> J[钱包与业务系统查询状态]
    J --> K{是否发生离线场景}
    K -- 是 --> L[离线缓存交易]
    L --> M[重连同步与冲突解决]
    M --> G
    K -- 否 --> N[正常在线使用]
    N --> O{是否需要治理调整}
    O -- 是 --> P[发起提案与投票]
    P --> Q[参数或验证者在指定高度生效]
    Q --> G
    O -- 否 --> R[持续运行]
    R --> S[监控/审计/备份]
    S --> T{是否发现风险}
    T -- 是 --> U[暂停/吊销/参数调整/恢复]
    U --> P
    T -- 否 --> R
```

---

## 15. 流程中的关键检查点

| 流程 | 关键检查点 | 失败处理 |
|---|---|---|
| 身份认证 | DID 控制权、VC 签名、issuer 可信、凭证未过期 | 拒绝注册，返回身份错误码 |
| N 发放 | 身份有效、治理多签、供应上限、发放周期 | 拒绝 MINT/REPLENISH |
| 普通转账 | UTXO 存在、签名有效、金额守恒 | 拒绝交易 |
| 销售交易 | `N_to_buyer >= ceil(external_amount * phi)`、销售容量足够；外部凭证引用可选 | 拒绝并提示 N 不足或比例不足 |
| 工资交易 | `N_to_employer >= ceil(external_amount * psi)`；工资单/支付引用可选 | 拒绝并提示工资规则不满足 |
| 治理投票 | 投票者权限、签名、投票期、阈值 | 提案失败或等待更多投票 |
| 离线同步 | 输入未花费、参数未变、TTL 未过期、身份有效 | 标记冲突并尝试解决 |
| ZK 交易 | proof 有效、nullifier 未使用、circuit_id 支持 | 拒绝隐私交易 |
| 运维运行 | 高度同步、peer 正常、API 健康、磁盘充足 | 告警并进入故障处理 |

---

## 16. 推荐落地顺序

实际实施时建议按以下顺序落地和验收:

1. 节点启动流程与配置加载。
2. 钱包创建、DID 创建和身份注册。
3. 治理初始化参数和信任锚。
4. MINT 初始 N 发放。
5. 普通 N 转账。
6. 销售交易 `TRANSFER_SALE`。
7. 工资交易 `TRANSFER_WAGE`。
8. 离线交易创建和缓存。
9. 重连同步和冲突解决。
10. 治理提案、投票和参数生效。
11. 多节点 P2P 同步和 PoA-BFT 出块。
12. API 网关、监控、备份和生产安全校验。
13. ZK 隐私交易实验模式。

---

## 17. 总结

BCS 系统的运行不是单一“提交交易并出块”的流程，而是身份、治理、经济规则、离线同步和节点共识共同组成的闭环。身份认证决定用户是否具备参与资格，治理决定系统参数和权限边界，交易流程只结算 N，并用 `external_amount` 计算 N 义务；现实支付凭证引用是可选审计信息。离线同步保证弱网络场景下的可用性，运维监控保证节点网络长期稳定。

在实际实现中，最重要的是把每条流程的状态、输入、输出和失败原因做成可验证、可审计、可恢复的机制。只有这样，系统才能从架构原型变成可演示、可测试、可试点运行的完整 BCS 离线支付系统。
