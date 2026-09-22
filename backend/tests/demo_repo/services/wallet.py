"""
Custodial Digital Wallet Service
Generates cryptographic addresses and signs blockchain settlements.
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


class CustodialWallet:
    def __init__(self, account_index: int = 0):
        self.account_index = account_index
        # ECDSA curve SECP256K1 used across EVM and Bitcoin networks
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.private_key.public_key()

    def sign_transaction_hash(self, tx_hash: bytes) -> bytes:
        """
        Signs transaction hash with the ECDSA private key.
        Vulnerability: Shor's discrete logarithm solves elliptic curve keys.
        """
        return self.private_key.sign(
            tx_hash,
            ec.ECDSA(hashes.SHA256())
        )
