"""
BCS Key Generator
=================
Generates secp256k1 keypairs, DID Documents, and governance multi-sig configurations.

Outputs:
    • secp256k1 private key (hex)
    • Compressed public key (hex)
    • P2PKH address (RIPEMD160(SHA256(pubkey)))
    • DID Document (did:bcs:<address>)
    • BIP39 mnemonic (optional)

Usage:
    $ python keygen.py --count 3 --output ./keys.json
    $ python keygen.py --mnemonic --did
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from ecdsa import SECP256k1
from ecdsa.keys import SigningKey, VerifyingKey


# --------------------------------------------------------------------------- #
#  Data models
# --------------------------------------------------------------------------- #

@dataclass
class KeyPair:
    """A generated BCS keypair with derived artifacts."""
    private_key_hex: str
    public_key_hex: str
    address: str
    did: str
    mnemonic: str = ""
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "public_key_hex": self.public_key_hex,
            "address": self.address,
            "did": self.did,
            "label": self.label,
        }
        # Include secrets only if non-empty
        if self.private_key_hex:
            d["private_key_hex"] = self.private_key_hex
        if self.mnemonic:
            d["mnemonic"] = self.mnemonic
        return d


@dataclass
class MultiSigConfig:
    """Governance multi-signature configuration."""
    threshold: int
    signers: List[str]  # list of addresses
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threshold": self.threshold,
            "signers": self.signers,
            "description": self.description,
        }


# --------------------------------------------------------------------------- #
#  Generator
# --------------------------------------------------------------------------- #

class BCSKeyGenerator:
    """Generates BCS-compatible keys and identity documents."""

    @staticmethod
    def generate_keypair(label: str = "", with_mnemonic: bool = False) -> KeyPair:
        """Generate a single keypair with optional BIP39 mnemonic."""
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.get_verifying_key()

        privkey_hex = sk.to_string().hex()
        pubkey_hex = vk.to_string("compressed").hex()

        # P2PKH address: RIPEMD160(SHA256(pubkey))
        try:
            sha = hashlib.sha256(bytes.fromhex(pubkey_hex)).digest()
            addr = "1" + hashlib.new("ripemd160", sha).hexdigest()[:20]
        except Exception:
            # Fallback if ripemd160 unavailable
            addr = hashlib.sha256(pubkey_hex.encode()).hexdigest()[:20]

        did = f"did:bcs:{addr}"

        mnemonic = ""
        if with_mnemonic:
            try:
                from mnemonic import Mnemonic
                mnemo = Mnemonic("english")
                entropy = sk.to_string()
                mnemonic = mnemo.to_mnemonic(entropy)
            except ImportError:
                mnemonic = "(mnemonic unavailable: install 'mnemonic' package)"

        return KeyPair(
            private_key_hex=privkey_hex,
            public_key_hex=pubkey_hex,
            address=addr,
            did=did,
            mnemonic=mnemonic,
            label=label,
        )

    @classmethod
    def generate_many(
        cls,
        count: int,
        with_mnemonic: bool = False,
    ) -> List[KeyPair]:
        """Generate multiple keypairs."""
        return [cls.generate_keypair(label=f"key-{i}", with_mnemonic=with_mnemonic) for i in range(count)]

    @staticmethod
    def create_multisig_config(
        keypairs: List[KeyPair],
        threshold: int,
        description: str = "Governance Multi-Sig",
    ) -> MultiSigConfig:
        """Create a multi-sig configuration from a list of keypairs."""
        return MultiSigConfig(
            threshold=threshold,
            signers=[kp.address for kp in keypairs],
            description=description,
        )

    @staticmethod
    def build_did_document(keypair: KeyPair) -> Dict[str, Any]:
        """Build a DID Document for a keypair."""
        return {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": keypair.did,
            "controller": keypair.did,
            "verificationMethod": [
                {
                    "id": f"{keypair.did}#keys-1",
                    "type": "EcdsaSecp256k1VerificationKey2019",
                    "controller": keypair.did,
                    "publicKeyHex": keypair.public_key_hex,
                }
            ],
            "authentication": [f"{keypair.did}#keys-1"],
            "assertionMethod": [f"{keypair.did}#keys-1"],
            "serviceEndpoints": [],
            "created": int(time.time()),
            "updated": int(time.time()),
        }


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(description="BCS Key Generator")
    parser.add_argument("--count", type=int, default=1, help="Number of keypairs to generate")
    parser.add_argument("--mnemonic", action="store_true", help="Generate BIP39 mnemonic")
    parser.add_argument("--did", action="store_true", help="Output DID Documents")
    parser.add_argument("--multisig", type=int, default=0, help="Create multi-sig with N-of-M threshold")
    parser.add_argument("--output", type=str, default="bcs_keys.json", help="Output JSON file")
    parser.add_argument("--stdout", action="store_true", help="Print to stdout instead of file")
    args = parser.parse_args()

    gen = BCSKeyGenerator()
    keypairs = gen.generate_many(args.count, with_mnemonic=args.mnemonic)

    result: Dict[str, Any] = {
        "generated_at": int(time.time()),
        "keypairs": [kp.to_dict() for kp in keypairs],
    }

    # DID Documents
    if args.did:
        result["did_documents"] = [gen.build_did_document(kp) for kp in keypairs]

    # Multi-sig config
    if args.multisig > 0 and args.count >= args.multisig:
        ms = gen.create_multisig_config(keypairs, threshold=args.multisig)
        result["multisig"] = ms.to_dict()
        print(f"[KEYGEN] Multi-sig config: {args.multisig}-of-{args.count}")

    # Print summary
    for i, kp in enumerate(keypairs):
        print(f"[KEYGEN] Keypair {i}:")
        print(f"  Address: {kp.address}")
        print(f"  DID:     {kp.did}")
        print(f"  Pubkey:  {kp.public_key_hex[:20]}...")
        if kp.mnemonic:
            print(f"  Mnemonic: {kp.mnemonic[:30]}...")

    # Output
    if args.stdout:
        print(json.dumps(result, indent=2))
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"[KEYGEN] Saved to {args.output}")


if __name__ == "__main__":
    main()
