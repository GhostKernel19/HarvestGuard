# HarvestGuard 🛡️

HarvestGuard is a full-stack security and post-quantum static-analysis auditing platform. It combines static-analysis code scanners with local inference powered by a local Qwen3-1.7B model accelerated via ONNX Runtime with Qualcomm Neural Network (QNN) Execution Provider.

## Project Structure

```
HarvestGuard/
├── backend/            # FastAPI service (Static analysis & QNN inference endpoints)
├── frontend/           # Next.js 15 (App Router, Tailwind CSS v4, shadcn/ui)
├── models/             # Compiled QNN model binaries & ONNX graph definitions
├── docker-compose.yml  # Container orchestration stub
└── README.md
```

## Getting Started

### Prerequisites
- **Node.js**: v20+ (v24 recommended)
- **Python**: 3.11+
- **ONNX Runtime**: ONNX Runtime with QNN EP enabled (for hardware-accelerated local inference)

### 1. Backend Setup (FastAPI)
```bash
cd backend
python -m venv venv

# Windows (PowerShell)
.\venv\Scripts\Activate.ps1
# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
API will be live at: [http://localhost:8000](http://localhost:8000)
- Health check: `GET http://localhost:8000/api/health`
- Static Analysis: `POST http://localhost:8000/api/scan`
- QNN Inference: `POST http://localhost:8000/api/inference`
- Interactive Docs: `http://localhost:8000/docs`

### 2. Frontend Setup (Next.js 15)
```bash
cd frontend
npm install
npm run dev
```
Web app will be live at: [http://localhost:3000](http://localhost:3000)

### 3. Docker Compose
```bash
docker compose up --build
```
