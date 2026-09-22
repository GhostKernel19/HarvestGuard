// sample_vulnerable.java - Quantum Vulnerable Java Cryptography Sample

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import javax.crypto.KeyAgreement;

public class VulnerableCryptoService {

    // 1. RSA Key Pair Generation (Severity: High)
    public KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        return rsaGen.generateKeyPair();
    }

    // 2. ECC / ECDSA Key Pair Generation (Severity: High)
    public KeyPair generateECCKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        return ecGen.generateKeyPair();
    }

    // 3. Diffie-Hellman Key Agreement (Severity: High)
    public KeyAgreement setupDiffieHellman() throws NoSuchAlgorithmException {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        return keyAgree;
    }

    // 4. Weak TLS / Cipher Suites Configuration (Severity: Medium)
    public static final String[] WEAK_CIPHERS = new String[] {
        "TLS_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    };
}
