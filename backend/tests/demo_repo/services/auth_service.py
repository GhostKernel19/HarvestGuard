"""
Authentication Microservice
Handles user session token generation and JWT signing.
"""

from typing import Dict, Any, Tuple
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


class AuthenticationService:
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self._private_key = None
        self._public_key = None
        self._rotate_service_keys()

    def _rotate_service_keys(self) -> None:
        """
        Generates a new RSA private key for JWT and session authorization.
        Vulnerability: Shor's algorithm polynomial-time integer factorization.
        """
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        self._public_key = self._private_key.public_key()

    def sign_jwt_payload(self, claims: Dict[str, Any]) -> bytes:
        """
        Signs token payload with the server RSA private key using PSS padding.
        """
        claims["iat"] = datetime.datetime.now(datetime.timezone.utc).timestamp()
        serialized_payload = str(claims).encode("utf-8")

        signature = self._private_key.sign(
            serialized_payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def export_public_key_pem(self) -> str:
        """Exports public key in PEM format for downstream gateway verification."""
        pem_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode("utf-8")
