"""
Session Security Manager
Generates cryptographically random authentication tokens and validates HMAC signatures.
"""

from typing import Optional
import secrets
import hmac
import hashlib


class SessionTokenManager:
    def __init__(self, signing_secret: Optional[bytes] = None):
        # 32-byte high-entropy symmetric secret
        self.signing_secret = signing_secret or secrets.token_bytes(32)

    def issue_session_token(self, user_id: str) -> str:
        """
        Issues CSPRNG token with an attached HMAC-SHA256 integrity tag.
        """
        random_entropy = secrets.token_hex(24)
        token_body = f"{user_id}:{random_entropy}"
        signature = hmac.new(
            self.signing_secret,
            token_body.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        return f"{token_body}:{signature}"

    def validate_session_token(self, full_token: str) -> bool:
        """
        Validates token structure and performs constant-time HMAC comparison.
        """
        parts = full_token.split(":")
        if len(parts) != 3:
            return False
        user_id, entropy, signature = parts
        expected_body = f"{user_id}:{entropy}".encode("utf-8")
        expected_sig = hmac.new(
            self.signing_secret,
            expected_body,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected_sig)
