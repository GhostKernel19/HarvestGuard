# ApexPay Microservices Platform

Core fintech payment, settlement, and customer vault microservices backend.

## Services
- `services/auth_service.py` - User authorization and token signing.
- `services/payment_gateway.py` - Banking network settlement and merchant authorization.
- `services/wallet.py` - Custodial digital wallet management.
- `services/key_exchange.py` - Inter-service peer key agreement.
- `storage/database_vault.py` - AES-256-GCM encrypted database vault.
- `security/ledger_hasher.py` - SHA-256 audit ledger hash chaining.
- `security/session_manager.py` - CSPRNG session token issuance and HMAC validation.
- `config/tls_gateway.yaml` - Reverse proxy TLS cipher configuration.
