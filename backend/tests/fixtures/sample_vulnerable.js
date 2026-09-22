// sample_vulnerable.js - Quantum Vulnerable Node.js Cryptography Sample

const crypto = require("crypto");
const elliptic = require("elliptic");

// 1. RSA Key Generation (Severity: High)
function generateRSA() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  return { publicKey, privateKey };
}

// 2. ECC Key Generation (Severity: High)
function generateECC() {
  const ec = new elliptic.ec("secp256k1");
  const key = ec.genKeyPair();
  const nodeECDH = crypto.createECDH("secp256k1");
  return { key, nodeECDH };
}

// 3. Diffie-Hellman Key Exchange (Severity: High)
function setupDH() {
  const aliceDH = crypto.createDiffieHellman(2048);
  aliceDH.generateKeys();
  return aliceDH;
}

// 4. Weak TLS Cipher Configuration (Severity: Medium)
const tlsOptions = {
  minVersion: "TLSv1.2",
  ciphers: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_CBC_SHA256",
};

module.exports = { generateRSA, generateECC, setupDH, tlsOptions };
