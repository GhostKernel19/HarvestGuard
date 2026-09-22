import os
import io
import zipfile
import pytest
from fastapi.testclient import TestClient

from scanner import CodebaseScanner
from main import app

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
VULN_PY = os.path.join(FIXTURES_DIR, "sample_vulnerable.py")
VULN_JS = os.path.join(FIXTURES_DIR, "sample_vulnerable.js")
VULN_JAVA = os.path.join(FIXTURES_DIR, "sample_vulnerable.java")
CLEAN_PY = os.path.join(FIXTURES_DIR, "sample_clean.py")

client = TestClient(app)
scanner = CodebaseScanner()


def test_python_vulnerable_findings():
    """Verify sample_vulnerable.py flags RSA, ECC, DH, and weak-TLS with accurate severities."""
    findings = scanner.scan_file(VULN_PY)
    assert len(findings) > 0, "Expected findings in sample_vulnerable.py"

    vuln_types = {f.vulnerability_type for f in findings}
    assert "RSA" in vuln_types, "Expected RSA finding in Python fixture"
    assert "ECC" in vuln_types, "Expected ECC finding in Python fixture"
    assert "DH" in vuln_types, "Expected DH finding in Python fixture"
    assert "weak-TLS-config" in vuln_types, "Expected weak-TLS finding in Python fixture"

    # Verify severity distribution
    severities = {f.severity for f in findings}
    assert "high" in severities, "Expected high severity (key generation)"
    assert "medium" in severities, "Expected medium severity (signing or weak TLS)"
    assert "low" in severities, "Expected low severity (bare imports)"

    # Verify specific key generation calls are high severity
    rsa_keygen = [f for f in findings if f.vulnerability_type == "RSA" and f.severity == "high"]
    assert len(rsa_keygen) >= 1, "Expected RSA keygen with high severity"

    ecc_keygen = [f for f in findings if f.vulnerability_type == "ECC" and f.severity == "high"]
    assert len(ecc_keygen) >= 1, "Expected ECC keygen with high severity"

    dh_gen = [f for f in findings if f.vulnerability_type == "DH" and f.severity == "high"]
    assert len(dh_gen) >= 1, "Expected DH parameter generation with high severity"


def test_javascript_vulnerable_findings():
    """Verify sample_vulnerable.js flags Node crypto RSA, ECC, DH, and TLS cipher suites."""
    findings = scanner.scan_file(VULN_JS)
    assert len(findings) > 0, "Expected findings in sample_vulnerable.js"

    vuln_types = {f.vulnerability_type for f in findings}
    assert "RSA" in vuln_types, "Expected RSA in JS"
    assert "ECC" in vuln_types, "Expected ECC in JS"
    assert "DH" in vuln_types, "Expected DH in JS"
    assert "weak-TLS-config" in vuln_types, "Expected weak-TLS in JS"

    rsa_high = [f for f in findings if f.vulnerability_type == "RSA" and f.severity == "high"]
    assert len(rsa_high) >= 1, "Expected Node RSA key generation to be high severity"


def test_java_vulnerable_findings():
    """Verify sample_vulnerable.java flags KeyPairGenerator and KeyAgreement calls."""
    findings = scanner.scan_file(VULN_JAVA)
    assert len(findings) > 0, "Expected findings in sample_vulnerable.java"

    vuln_types = {f.vulnerability_type for f in findings}
    assert "RSA" in vuln_types, "Expected RSA in Java"
    assert "ECC" in vuln_types, "Expected ECC in Java"
    assert "DH" in vuln_types, "Expected DH in Java"
    assert "weak-TLS-config" in vuln_types, "Expected weak-TLS in Java"


def test_clean_file_produces_zero_findings():
    """
    Ensure sample_clean.py produces zero findings.
    AST parsing must ignore comments, docstrings, and string descriptions of classical algorithms.
    """
    findings = scanner.scan_file(CLEAN_PY)
    assert len(findings) == 0, f"Expected 0 findings in clean file, found: {findings}"


def test_scan_directory_summary():
    """Verify scan_directory aggregates findings and computes accurate summary statistics."""
    result = scanner.scan_directory(FIXTURES_DIR)
    assert result["status"] == "completed"
    assert result["files_scanned"] >= 4

    summary = result["summary"]
    assert summary["total"] >= 10
    assert summary["high"] >= 3
    assert summary["medium"] >= 3
    assert summary["low"] >= 1

    by_type = summary["by_type"]
    assert by_type["RSA"] >= 1
    assert by_type["ECC"] >= 1
    assert by_type["DH"] >= 1
    assert by_type["weak-TLS-config"] >= 1


def test_api_scan_target_path():
    """Test POST /api/scan endpoint with a local repository/fixture path."""
    response = client.post("/api/scan", json={"target_path": FIXTURES_DIR})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["files_scanned"] >= 4
    assert len(data["findings"]) > 0
    assert "summary" in data


def test_api_scan_inline_snippet():
    """Test POST /api/scan endpoint with an inline Python snippet."""
    snippet = "from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)"
    response = client.post(
        "/api/scan",
        json={"code_snippet": snippet, "language": "python"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["total"] >= 1
    assert any(f["vulnerability_type"] == "RSA" for f in data["findings"])


def test_api_scan_zip_upload():
    """Test POST /api/scan endpoint with an uploaded zip archive."""
    # Create an in-memory zip archive containing vulnerable and clean sample files
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(VULN_PY, arcname="src/legacy.py")
        zf.write(CLEAN_PY, arcname="src/secure.py")

    zip_buffer.seek(0)
    files = {"file": ("test_repo.zip", zip_buffer, "application/zip")}

    response = client.post("/api/scan", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["files_scanned"] == 2
    assert data["summary"]["total"] > 0
