"""
Payment Processing Gateway
Dispatches merchant transactions and signs authorization manifests.
"""

from typing import Dict, Any
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


class PaymentGatewayClient:
    def __init__(self, merchant_id: str, modulus_bits: int = 2048):
        self.merchant_id = merchant_id
        # Generates dedicated merchant signing key pair
        self.keypair = RSA.generate(modulus_bits)
        self.public_key = self.keypair.publickey()

    def sign_transaction(self, tx_data: Dict[str, Any]) -> str:
        """
        Signs settlement payload to guarantee non-repudiation between merchant and banking network.
        """
        raw_message = json.dumps(tx_data, sort_keys=True).encode("utf-8")
        hasher = SHA256.new(raw_message)
        signer = pkcs1_15.new(self.keypair)
        raw_sig = signer.sign(hasher)
        return base64.b64encode(raw_sig).decode("utf-8")

    def get_merchant_public_key_der(self) -> bytes:
        """Returns DER-encoded public key for banking gateway registration."""
        return self.public_key.export_key(format="DER")
