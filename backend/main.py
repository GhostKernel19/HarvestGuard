from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import tempfile
import zipfile
import shutil

from scanner import CodebaseScanner, Finding, ScanSummary

app = FastAPI(
    title="HarvestGuard API",
    description="Static Analysis & Local QNN Inference Engine for Security Auditing",
    version="0.1.0",
)

# Enable CORS for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = CodebaseScanner()


class ScanRequest(BaseModel):
    target_path: Optional[str] = None
    code_snippet: Optional[str] = None
    language: Optional[str] = "python"


class InferenceRequest(BaseModel):
    prompt: str
    max_tokens: int = 512
    temperature: float = 0.7


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
    qnn_available = os.environ.get("QNN_AVAILABLE", "stub")
    model_binary_path = os.environ.get("MODEL_PATH", "../models/qwen3_1.7b_qnn.bin")
    model_present = os.path.isfile(model_binary_path)

    return {
        "status": "healthy",
        "engine": "HarvestGuard Core",
        "model_architecture": "Qwen3-1.7B",
        "execution_provider": "QNNExecutionProvider",
        "model_binary_present": model_present,
        "qnn_status": qnn_available,
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
def run_inference(request: InferenceRequest):
    """
    Local model inference endpoint calling Qwen3-1.7B via ONNX Runtime with QNN EP.
    """
    return {
        "model": "Qwen3-1.7B",
        "provider": "QNNExecutionProvider",
        "prompt": request.prompt,
        "response": f"[HarvestGuard QNN Stub] Model response for: {request.prompt[:50]}...",
        "tokens_generated": 16,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
