from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os

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


class ScanRequest(BaseModel):
    target_path: Optional[str] = None
    code_snippet: Optional[str] = None
    ruleset: str = "default-pq-audit"


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


@app.post("/api/scan")
def run_scan(request: ScanRequest):
    """
    Static analysis scanning engine stub.
    Evaluates source code against post-quantum readiness & security rules.
    """
    return {
        "status": "completed",
        "target": request.target_path or "inline_snippet",
        "ruleset": request.ruleset,
        "findings": [
            {
                "rule_id": "PQ-001",
                "severity": "INFO",
                "message": "HarvestGuard static analysis engine initialized. Ready to inspect algorithms.",
            }
        ],
    }


@app.post("/api/inference")
def run_inference(request: InferenceRequest):
    """
    Local model inference endpoint calling Qwen3-1.7B via ONNX Runtime with QNN EP.
    """
    # Placeholder for QNN Execution Provider session logic
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
