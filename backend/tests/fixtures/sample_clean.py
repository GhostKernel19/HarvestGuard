"""
sample_clean.py - Clean Cryptographic Module with Post-Quantum Design

Note: This file contains comments and strings referring to legacy algorithms
such as RSA, ECC, Diffie-Hellman, and SECP256K1 to ensure the AST parser
does NOT produce false positives from non-executable comments and descriptions.
"""

import hashlib
import os

# We explicitly deprecated RSA.generate and ec.generate_private_key here.
# Classical Diffie-Hellman (DH) key exchange has been replaced by ML-KEM-768.
# Also TLS_RSA_WITH_AES_256_CBC_SHA is banned in our architecture.

class CleanQuantumSafeModule:
    """
    Documentation discussing why RSA-2048 and ECDSA secp256k1 are vulnerable
    under Shor's algorithm, whereas lattice-based cryptography is resilient.
    """

    def __init__(self):
        self.algorithm_name = "ML-KEM-768 / AES-256-GCM"
        self.legacy_notes = "RSA and DH are disabled."

    def hash_payload(self, data: bytes) -> bytes:
        # Standard SHA-256 hash is considered quantum-resistant for preimage resistance
        return hashlib.sha256(data).digest()

    def generate_symmetric_key(self) -> bytes:
        # 256-bit symmetric keys provide 128-bit quantum security against Grover's algorithm
        return os.urandom(32)

    def explain_migration(self) -> str:
        return "Migration completed: 0 legacy RSA or SECP256K1 keys in use."
