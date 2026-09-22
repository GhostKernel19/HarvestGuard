"""
Database Column Vault
Protects sensitive PII and account balances at rest using authenticated symmetric encryption.
"""

from typing import Optional
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DatabaseFieldVault:
    def __init__(self, master_key: Optional[bytes] = None):
        # 256-bit symmetric key: quantum-resistant against Grover's algorithm
        self.master_key = master_key or os.urandom(32)
        self.aesgcm = AESGCM(self.master_key)

    def encrypt_field(self, plaintext: str) -> bytes:
        """
        Encrypts plaintext string with AES-256-GCM authenticated encryption.
        96-bit unique nonce prepended to ciphertext.
        """
        nonce = os.urandom(12)
        data_bytes = plaintext.encode("utf-8")
        ciphertext = self.aesgcm.encrypt(nonce, data_bytes, None)
        return nonce + ciphertext

    def decrypt_field(self, payload: bytes) -> str:
        """
        Extracts nonce, verifies GCM authentication tag, and decrypts ciphertext.
        """
        nonce = payload[:12]
        ciphertext = payload[12:]
        decrypted_bytes = self.aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode("utf-8")
