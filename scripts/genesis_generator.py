"""
BCS Genesis Block Generator
===========================
Generates the genesis block (height=0) for a new BCS blockchain.

Features:
    • Creates a genesis Block with configurable validator set
    • Embeds initial governance parameters (φ, ψ, corridor bounds)
    • Optional: pre-allocates initial N to authenticated accounts
    • Outputs JSON file for distribution to all network participants

Usage:
    $ python genesis_generator.py --validators 3 --output ./genesis.json
    $ python genesis_generator.py --config node.default.toml --alloc alloc.csv
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Insert parent so core imports work when called from scripts/
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.block import Block, BlockBody, BlockHeader, compute_merkle_root
from core.transaction import Transaction, TxInput, TxOutput, TxType
from core.consensus import ValidatorInfo, ValidatorSet
from core.utxo import UTXO
from core.script import StandardScripts
from currency.params import SystemParameters
from identity.did import DIDDocument


# --------------------------------------------------------------------------- #
#  Data models
# --------------------------------------------------------------------------- #

@dataclass
class GenesisAlloc:
    """Pre-allocation entry for genesis N distribution."""
    address: str
    amount: int  # nanoN
    identity_did: str = ""
    label: str = ""


@dataclass
class GenesisConfig:
    """Complete genesis configuration."""
    network_id: str = "bcs-testnet"
    chain_name: str = "BCS Testnet"
    timestamp: int = field(default_factory=lambda: int(time.time() * 1000))
    validators: List[ValidatorInfo] = field(default_factory=list)
    system_params: SystemParameters = field(default_factory=SystemParameters)
    allocations: List[GenesisAlloc] = field(default_factory=list)
    extra_message: str = "BCS Genesis Block"


# --------------------------------------------------------------------------- #
#  Genesis Builder
# --------------------------------------------------------------------------- #

class GenesisBuilder:
    """Builds a genesis block and its accompanying metadata."""

    def __init__(self, config: GenesisConfig) -> None:
        self.config = config

    def build(self) -> Block:
        """
        Construct the genesis block.

        Returns:
            Block at height=0 with embedded allocations and validator set.
        """
        # Build allocation transactions
        alloc_txs: List[Transaction] = []
        for alloc in self.config.allocations:
            if alloc.amount <= 0:
                continue
            lock_script = self._address_to_lock_script(alloc.address)
            tx = Transaction(
                version=1,
                tx_type=TxType.MINT,
                inputs=[],  # No inputs for genesis mint
                outputs=[TxOutput(amount=alloc.amount, lock_script=lock_script)],
                extra=json.dumps({
                    "label": alloc.label,
                    "did": alloc.identity_did,
                }).encode("utf-8"),
            )
            alloc_txs.append(tx)

        # Build genesis block
        validator_pubkey = (
            self.config.validators[0].pubkey_hex
            if self.config.validators
            else "0" * 66
        )
        header = BlockHeader(
            version=1,
            prev_block_hash="0" * 64,
            merkle_root_tx=compute_merkle_root([tx.hash() for tx in alloc_txs]),
            merkle_root_utxo="0" * 64,
            merkle_root_identity="0" * 64,
            timestamp=self.config.timestamp,
            height=0,
            tx_count=len(alloc_txs),
            validator_pubkey=validator_pubkey,
            signature="",  # Genesis block is unsigned
            extra_data=self.config.extra_message.encode("utf-8"),
        )
        return Block(header=header, body=BlockBody(transactions=alloc_txs))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the full genesis package (block + config)."""
        block = self.build()
        return {
            "network_id": self.config.network_id,
            "chain_name": self.config.chain_name,
            "timestamp": self.config.timestamp,
            "block": block.to_dict(),
            "validators": [v.to_dict() for v in self.config.validators],
            "system_params": self.config.system_params.to_dict(),
            "allocations": [
                {
                    "address": a.address,
                    "amount": a.amount,
                    "identity_did": a.identity_did,
                    "label": a.label,
                }
                for a in self.config.allocations
            ],
            "extra_message": self.config.extra_message,
        }

    def save(self, path: str) -> None:
        """Save genesis package to a JSON file."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        print(f"[GENESIS] Saved to {path}")

    @staticmethod
    def load(path: str) -> "GenesisBuilder":
        """Load a genesis package from a JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        config = GenesisConfig(
            network_id=data["network_id"],
            chain_name=data["chain_name"],
            timestamp=data["timestamp"],
            validators=[
                ValidatorInfo(
                    validator_id=v["validator_id"],
                    pubkey_hex=v["pubkey_hex"],
                    name=v.get("name", ""),
                    weight=v.get("weight", 1),
                )
                for v in data["validators"]
            ],
            system_params=SystemParameters.from_dict(data["system_params"]),
            allocations=[
                GenesisAlloc(
                    address=a["address"],
                    amount=a["amount"],
                    identity_did=a.get("identity_did", ""),
                    label=a.get("label", ""),
                )
                for a in data.get("allocations", [])
            ],
            extra_message=data.get("extra_message", ""),
        )
        return GenesisBuilder(config)

    @staticmethod
    def _address_to_lock_script(address: str) -> bytes:
        """Convert a 40-char hex address to a standard P2PKH lock script."""
        pk_hash = bytes.fromhex(address.replace("0x", ""))
        if len(pk_hash) != 20:
            # Pad or hash if not exactly 20 bytes
            pk_hash = bytes.fromhex(hashlib.sha256(address.encode()).hexdigest()[:40])
        return StandardScripts.p2pkh_lock_script(pk_hash)


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def _parse_alloc_csv(path: str) -> List[GenesisAlloc]:
    """Parse a CSV of allocations: address,amount,identity_did,label."""
    allocs: List[GenesisAlloc] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            addr = parts[0].strip()
            amount = int(parts[1].strip()) if len(parts) > 1 else 0
            did = parts[2].strip() if len(parts) > 2 else ""
            label = parts[3].strip() if len(parts) > 3 else ""
            allocs.append(GenesisAlloc(address=addr, amount=amount, identity_did=did, label=label))
    return allocs


def main() -> None:
    parser = argparse.ArgumentParser(description="BCS Genesis Block Generator")
    parser.add_argument("--validators", type=int, default=3, help="Number of validators to generate")
    parser.add_argument("--network-id", type=str, default="bcs-testnet", help="Network identifier")
    parser.add_argument("--phi-num", type=int, default=3, help="φ numerator")
    parser.add_argument("--phi-den", type=int, default=100, help="φ denominator")
    parser.add_argument("--psi-num", type=int, default=5, help="ψ numerator")
    parser.add_argument("--psi-den", type=int, default=100, help="ψ denominator")
    parser.add_argument("--alloc", type=str, default="", help="Path to allocation CSV")
    parser.add_argument("--output", type=str, default="genesis.json", help="Output JSON path")
    parser.add_argument("--config", type=str, default="", help="Optional TOML config to merge")
    args = parser.parse_args()

    # Generate validator keypairs
    import secrets
    from ecdsa import SECP256k1
    from ecdsa.keys import SigningKey

    validators: List[ValidatorInfo] = []
    print("[GENESIS] Generating validator keys...")
    for i in range(args.validators):
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.get_verifying_key()
        pubkey_hex = vk.to_string("compressed").hex()
        validators.append(
            ValidatorInfo(
                validator_id=i,
                pubkey_hex=pubkey_hex,
                name=f"validator-{i}",
                weight=1,
            )
        )
        print(f"  Validator {i}: pubkey={pubkey_hex[:20]}...")
        # Optionally print private key for node config
        priv_hex = sk.to_string().hex()
        print(f"           privkey={priv_hex[:20]}... (SAVE THIS!)")

    # Allocations
    allocations: List[GenesisAlloc] = []
    if args.alloc and os.path.exists(args.alloc):
        allocations = _parse_alloc_csv(args.alloc)
        print(f"[GENESIS] Loaded {len(allocations)} allocations from {args.alloc}")

    # System params
    params = SystemParameters(
        phi_numerator=args.phi_num,
        phi_denominator=args.phi_den,
        psi_numerator=args.psi_num,
        psi_denominator=args.psi_den,
        validators=tuple(v.pubkey_hex for v in validators),
    )

    config = GenesisConfig(
        network_id=args.network_id,
        validators=validators,
        system_params=params,
        allocations=allocations,
    )

    builder = GenesisBuilder(config)
    block = builder.build()
    print(f"[GENESIS] Block hash: {block.hash}")
    print(f"[GENESIS] Tx count:   {len(block.body.transactions)}")
    print(f"[GENESIS] Validator:  {validators[0].pubkey_hex[:20]}...")

    builder.save(args.output)
    print(f"[GENESIS] Done. Output: {args.output}")


if __name__ == "__main__":
    main()
