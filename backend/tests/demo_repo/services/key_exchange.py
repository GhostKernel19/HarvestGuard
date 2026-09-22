"""
Secure Channel Key Exchange Service
Negotiates ephemeral session keys between microservice peers using classical Diffie-Hellman.
"""

from typing import Any
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class DiffieHellmanKeyExchange:
    def __init__(self, dh_private_key: Any):
        self.dh_private_key = dh_private_key

    def derive_shared_symmetric_key(self, peer_public_key: Any) -> bytes:
        """
        Computes shared secret via classical Diffie-Hellman key exchange.
        Vulnerability: Quantum computers solve finite-field discrete logs (HNDL risk).
        """
        raw_shared_key = self.dh_private_key.exchange(peer_public_key)

        # Derive 256-bit symmetric session key via HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"fintech-channel-session-v1"
        ).derive(raw_shared_key)

        return derived_key
