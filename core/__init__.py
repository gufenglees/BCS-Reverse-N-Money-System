"""
BCS Blockchain Core Package
=============================
Core blockchain modules for the Bidirectional Currency System (BCS).

Modules:
    block        – Block, BlockHeader, BlockBody structures
    transaction  – Transaction, TxInput, TxOutput, TxType, ZKProof
    utxo         – UTXO, UTXOSet, SimplePatriciaTrie
    state        – IdentityStatus, AccountState, StateManager
    script       – ScriptEngine, StandardScripts, Opcode
    validator    – TxValidator, BlockValidator, SystemParams, ValidationResult
    mempool      – Mempool, MempoolEntry
    storage      – BlockStore, IndexStore
    consensus    – PoABFTConsensus, ValidatorSet, ValidatorInfo
"""

__version__ = "0.1.0"
