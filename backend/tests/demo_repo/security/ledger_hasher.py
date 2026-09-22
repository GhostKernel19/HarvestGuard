"""
Audit Ledger Hash Chain
Computes immutable integrity hashes across transaction ledger blocks.
"""

from typing import List, Dict, Any
import hashlib
import json


class TransactionLedgerChain:
    def __init__(self):
        self.chain: List[Dict[str, Any]] = []

    def compute_block_hash(self, block_index: int, previous_hash: str, transactions: List[Dict[str, Any]]) -> str:
        """
        Computes SHA-256 digest of block contents.
        SHA-256 provides strong preimage and collision resistance against quantum cryptanalysis.
        """
        block_manifest = {
            "index": block_index,
            "previous_hash": previous_hash,
            "transactions": transactions,
        }
        serialized = json.dumps(block_manifest, sort_keys=True).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def verify_chain_integrity(self) -> bool:
        """Verifies that all chained block hashes match their expected values."""
        for i in range(1, len(self.chain)):
            prev = self.chain[i - 1]
            curr = self.chain[i]
            expected_hash = self.compute_block_hash(
                curr["index"], prev["hash"], curr["transactions"]
            )
            if curr["hash"] != expected_hash:
                return False
        return True
