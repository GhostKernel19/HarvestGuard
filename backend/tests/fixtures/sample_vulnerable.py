# sample_vulnerable.py - Quantum Vulnerable Python Cryptography Sample

# Bare imports (Severity: Low)
import ecdsa
import rsa
from cryptography.hazmat.primitives.asymmetric import rsa as hazmat_rsa, ec, dh
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.primitives import hashes
from Crypto.PublicKey import RSA

def generate_legacy_rsa():
    # RSA Key Generation (Severity: High)
    pycryptodome_rsa = RSA.generate(2048)
    hazmat_key = hazmat_rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # RSA Signing (Severity: Medium)
    signature = hazmat_key.sign(
        b"legacy-transaction-data",
        PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return hazmat_key, signature

def generate_legacy_ecc():
    # ECC Key Generation & SECP256R1 / SECP256K1 Curve (Severity: High)
    curve = ec.SECP256R1()
    ecc_private_key = ec.generate_private_key(curve)
    backup_curve = ec.SECP256K1()
    return ecc_private_key

def setup_diffie_hellman():
    # Diffie-Hellman Parameter Generation (Severity: High)
    dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
    dh_key = dh_parameters.generate_private_key()
    return dh_key

# Weak TLS Cipher Suite Configuration (Severity: Medium)
TLS_CIPHERS = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA"
