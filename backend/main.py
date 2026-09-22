from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import tempfile
import zipfile
import shutil

from scanner import CodebaseScanner, Finding, ScanSummary
from inference import engine, FindingExplanation, InferenceBatchResponse

app = FastAPI(
    title="HarvestGuard API",
    description="Static Analysis & Local QNN Inference Engine for Security Auditing",
    version="0.1.0",
)

# Production-ready CORS configuration
# Supports FRONTEND_ORIGIN env var (comma-separated or single domain)
frontend_origin_env = os.environ.get("FRONTEND_ORIGIN", "")
allowed_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

if frontend_origin_env:
    for orig in frontend_origin_env.split(","):
        clean_orig = orig.strip().rstrip("/")
        if clean_orig and clean_orig not in allowed_origins:
            allowed_origins.append(clean_orig)

if "*" in allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

scanner = CodebaseScanner()


class ScanRequest(BaseModel):
    target_path: Optional[str] = None
    code_snippet: Optional[str] = None
    language: Optional[str] = "python"


@app.get("/")
def read_root():
    return {
        "service": "HarvestGuard Backend",
        "status": "online",
        "version": "0.1.0",
        "docs_url": "/docs",
    }


@app.get("/api/health")
def health_check():
    provider_name = {
        "qnn_npu": "QNNExecutionProvider",
        "cpu_fallback": "CPUExecutionProvider",
        "rule_based_stub": "RuleBasedStub",
    }.get(engine.active_mode, "RuleBasedStub")

    return {
        "status": "healthy",
        "engine": "HarvestGuard Core",
        "model_architecture": "Qwen3-1.7B",
        "execution_provider": provider_name,
        "inference_mode": engine.active_mode,
        "model_binary_present": os.path.isfile(engine.model_path),
    }


def _scan_zip_stream(file_bytes: bytes) -> Dict[str, Any]:
    """Safely extracts and scans an uploaded zip archive in a temporary directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "archive.zip")
        with open(zip_path, "wb") as f:
            f.write(file_bytes)

        if not zipfile.is_zipfile(zip_path):
            raise HTTPException(status_code=400, detail="Uploaded file is not a valid zip archive")

        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            # Prevent zip slip path traversal
            for member in zip_ref.namelist():
                dest_path = os.path.abspath(os.path.join(extract_dir, member))
                if not dest_path.startswith(os.path.abspath(extract_dir)):
                    raise HTTPException(status_code=400, detail="Zip file contains unsafe path traversal")
            zip_ref.extractall(extract_dir)

        results = scanner.scan_directory(extract_dir)
        results["target"] = "uploaded_zip_archive"
        return results


@app.post("/api/scan")
async def run_scan(request: Request):
    """
    Static analysis scanning engine.
    Scans a local repository directory, uploaded zip file, or raw code snippet for quantum-vulnerable cryptography.
    Accepts application/json or multipart/form-data.
    """
    content_type = request.headers.get("content-type", "")

    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        target_path = form.get("target_path")

        if uploaded_file and hasattr(uploaded_file, "file"):
            content = await uploaded_file.read()
            return _scan_zip_stream(content)
        elif target_path:
            target_str = str(target_path)
            if not os.path.exists(target_str):
                raise HTTPException(status_code=404, detail=f"Target path does not exist: {target_str}")
            if os.path.isfile(target_str):
                findings = scanner.scan_file(target_str)
                summary = scanner.calculate_summary(findings)
                return {
                    "status": "completed",
                    "target": target_str,
                    "files_scanned": 1,
                    "summary": summary.to_dict(),
                    "findings": [f.to_dict() for f in findings],
                }
            results = scanner.scan_directory(target_str)
            results["target"] = target_str
            return results
        else:
            raise HTTPException(status_code=400, detail="Either 'file' (zip) or 'target_path' must be provided in form data")

    # JSON Request
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body or missing Content-Type")

    target_path = body.get("target_path")
    code_snippet = body.get("code_snippet")
    language = body.get("language", "python")

    if code_snippet:
        results = scanner.scan_code_snippet(code_snippet, language=language)
        results["target"] = "inline_snippet"
        return results
    elif target_path:
        if not os.path.exists(target_path):
            raise HTTPException(status_code=404, detail=f"Target path does not exist: {target_path}")
        if os.path.isfile(target_path):
            findings = scanner.scan_file(target_path)
            summary = scanner.calculate_summary(findings)
            return {
                "status": "completed",
                "target": target_path,
                "files_scanned": 1,
                "summary": summary.to_dict(),
                "findings": [f.to_dict() for f in findings],
            }
        results = scanner.scan_directory(target_path)
        results["target"] = target_path
        return results
    else:
        raise HTTPException(status_code=400, detail="Either 'target_path' or 'code_snippet' must be provided")


@app.post("/api/scan/upload")
async def run_scan_upload(file: UploadFile = File(...)):
    """Dedicated endpoint for zip file uploads."""
    content = await file.read()
    return _scan_zip_stream(content)


@app.post("/api/inference")
async def run_inference(request: Request):
    """
    Explains quantum vulnerabilities using Qwen3-1.7B (QNN/CPU) or rule-based fallback.
    Accepts either a single finding object or a batch list of findings.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Check if payload is a list (direct batch)
    if isinstance(payload, list):
        results = engine.explain_batch(payload)
        return [r.model_dump() for r in results]

    # Check if payload contains 'findings' list
    if "findings" in payload and isinstance(payload["findings"], list):
        results = engine.explain_batch(payload["findings"])
        return {
            "mode": engine.active_mode,
            "count": len(results),
            "results": [r.model_dump() for r in results],
        }

    # Single finding wrapped in 'finding' or directly passed as object
    finding = payload.get("finding", payload)
    if not isinstance(finding, dict) or ("vulnerability_type" not in finding and "prompt" not in finding):
        if "prompt" in finding:
            finding = {"vulnerability_type": "RSA", "description": finding["prompt"], "severity": "high"}
        else:
            raise HTTPException(
                status_code=400,
                detail="Invalid finding format. Must contain 'vulnerability_type'"
            )

    explanation = engine.explain_finding(finding)
    return explanation.model_dump()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
