import os
import json
import logging
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient

from inference import QwenInferenceEngine, FindingExplanation
from main import app

client = TestClient(app)


def test_rule_based_fallback_direct():
    """Verify the deterministic rule-based explainer produces the expected schema across all vulnerability types."""
    engine = QwenInferenceEngine(model_path="nonexistent_path_for_testing.bin")
    assert engine.active_mode == "rule_based_stub"

    # 1. RSA Key Generation (High -> HNDL risk True)
    rsa_finding = {
        "file_path": "crypto.py",
        "line_number": 12,
        "code_snippet": "RSA.generate(2048)",
        "vulnerability_type": "RSA",
        "severity": "high",
        "description": "Quantum-vulnerable RSA key generation",
    }
    rsa_res = engine.explain_finding(rsa_finding)
    assert isinstance(rsa_res, FindingExplanation)
    assert rsa_res.vulnerability_type == "RSA"
    assert rsa_res.mode_used == "rule_based_stub"
    assert rsa_res.harvest_now_risk.is_risk is True
    assert "Shor" in rsa_res.explanation or "factorization" in rsa_res.explanation
    assert "ML-KEM" in rsa_res.suggested_migration or "Kyber" in rsa_res.suggested_migration

    # 2. ECC Key Generation (High -> HNDL risk True)
    ecc_finding = {
        "file_path": "keys.py",
        "line_number": 25,
        "code_snippet": "ec.generate_private_key(ec.SECP256R1())",
        "vulnerability_type": "ECC",
        "severity": "high",
    }
    ecc_res = engine.explain_finding(ecc_finding)
    assert ecc_res.vulnerability_type == "ECC"
    assert ecc_res.harvest_now_risk.is_risk is True
    assert "ML-DSA" in ecc_res.suggested_migration or "Dilithium" in ecc_res.suggested_migration

    # 3. Diffie-Hellman (High -> HNDL risk True)
    dh_finding = {
        "file_path": "handshake.py",
        "line_number": 88,
        "code_snippet": "dh.generate_parameters(2, 2048)",
        "vulnerability_type": "DH",
        "severity": "high",
    }
    dh_res = engine.explain_finding(dh_finding)
    assert dh_res.vulnerability_type == "DH"
    assert dh_res.harvest_now_risk.is_risk is True
    assert "ML-KEM" in dh_res.suggested_migration or "Kyber" in dh_res.suggested_migration

    # 4. Weak TLS Cipher (Medium -> HNDL risk True)
    tls_finding = {
        "file_path": "server.conf",
        "line_number": 4,
        "code_snippet": "ciphers = TLS_RSA_WITH_AES_256_CBC_SHA",
        "vulnerability_type": "weak-TLS-config",
        "severity": "medium",
    }
    tls_res = engine.explain_finding(tls_finding)
    assert tls_res.vulnerability_type == "weak-TLS-config"
    assert tls_res.harvest_now_risk.is_risk is True
    assert "TLS 1.3" in tls_res.suggested_migration


def test_qnn_npu_mode_mocked():
    """Verify that when QNNExecutionProvider is available, the engine activates qnn_npu mode."""
    with patch("os.path.isfile", return_value=True), \
         patch("onnxruntime.get_available_providers", return_value=["QNNExecutionProvider", "CPUExecutionProvider"]), \
         patch("onnxruntime.InferenceSession") as mock_session_cls:

        mock_instance = MagicMock()
        mock_input = MagicMock()
        mock_input.name = "input_text"
        mock_instance.get_inputs.return_value = [mock_input]
        mock_instance.run.return_value = [
            [
                json.dumps({
                    "explanation": "QNN NPU accelerated explanation: RSA is broken by Shor's algorithm.",
                    "harvest_now_risk": {"is_risk": True, "reason": "NPU-detected historical capture risk."},
                    "suggested_migration": "Migrate to ML-KEM-768."
                })
            ]
        ]
        mock_session_cls.return_value = mock_instance

        engine = QwenInferenceEngine(model_path="dummy_qnn_model.bin")
        assert engine.active_mode == "qnn_npu"

        finding = {
            "vulnerability_type": "RSA",
            "severity": "high",
            "code_snippet": "RSA.generate(2048)",
        }
        res = engine.explain_finding(finding)
        assert res.mode_used == "qnn_npu"
        assert res.explanation == "QNN NPU accelerated explanation: RSA is broken by Shor's algorithm."
        assert res.harvest_now_risk.is_risk is True


def test_cpu_fallback_mode_mocked(caplog):
    """Verify fallback to CPUExecutionProvider when QNN is unavailable, logging the required warning."""
    with patch("os.path.isfile", return_value=True), \
         patch("onnxruntime.get_available_providers", return_value=["CPUExecutionProvider"]), \
         patch("onnxruntime.InferenceSession") as mock_session_cls, \
         caplog.at_level(logging.WARNING):

        mock_instance = MagicMock()
        mock_input = MagicMock()
        mock_input.name = "input_text"
        mock_instance.get_inputs.return_value = [mock_input]
        mock_instance.run.return_value = [
            [
                json.dumps({
                    "explanation": "CPU fallback explanation.",
                    "harvest_now_risk": {"is_risk": True, "reason": "Classical key exchange captured."},
                    "suggested_migration": "Use ML-KEM."
                })
            ]
        ]
        mock_session_cls.return_value = mock_instance

        engine = QwenInferenceEngine(model_path="dummy_cpu_model.bin")
        assert engine.active_mode == "cpu_fallback"

        # Check required warning message
        expected_warning = "QNN unavailable, using CPU fallback — swap to Snapdragon hardware for NPU inference."
        assert expected_warning in caplog.text


def test_api_health_reports_active_mode():
    """Verify GET /api/health reports the correct active inference mode and provider."""
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert "inference_mode" in data
    assert data["inference_mode"] in ("qnn_npu", "cpu_fallback", "rule_based_stub")
    assert "execution_provider" in data


def test_api_inference_single_finding():
    """Test POST /api/inference with a single finding object."""
    payload = {
        "file_path": "legacy_service.py",
        "line_number": 33,
        "code_snippet": "Crypto.PublicKey.RSA.generate(2048)",
        "vulnerability_type": "RSA",
        "severity": "high",
        "description": "Legacy RSA key generation"
    }
    res = client.post("/api/inference", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["vulnerability_type"] == "RSA"
    assert "explanation" in data
    assert "harvest_now_risk" in data
    assert data["harvest_now_risk"]["is_risk"] is True
    assert "suggested_migration" in data
    assert "mode_used" in data


def test_api_inference_batch_mode_preserves_order():
    """Test POST /api/inference with a batch list of findings, verifying identical ordering."""
    findings = [
        {"vulnerability_type": "RSA", "severity": "high", "code_snippet": "RSA.generate(2048)"},
        {"vulnerability_type": "ECC", "severity": "high", "code_snippet": "ec.generate_private_key()"},
        {"vulnerability_type": "DH", "severity": "medium", "code_snippet": "dh.exchange()"},
    ]
    res = client.post("/api/inference", json={"findings": findings})
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 3
    results = data["results"]
    assert len(results) == 3

    # Check exact order
    assert results[0]["vulnerability_type"] == "RSA"
    assert results[1]["vulnerability_type"] == "ECC"
    assert results[2]["vulnerability_type"] == "DH"


def test_api_inference_direct_list_batch():
    """Test POST /api/inference when sending a JSON array directly."""
    findings = [
        {"vulnerability_type": "DH", "severity": "high"},
        {"vulnerability_type": "weak-TLS-config", "severity": "medium"},
    ]
    res = client.post("/api/inference", json=findings)
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["vulnerability_type"] == "DH"
    assert data[1]["vulnerability_type"] == "weak-TLS-config"
