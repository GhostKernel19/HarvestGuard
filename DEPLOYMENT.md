# HarvestGuard Deployment Guide 🚀

This guide provides step-by-step instructions for deploying the **HarvestGuard** full-stack platform:
- **Backend (Python / FastAPI)** $\to$ **Render** (as a Web Service)
- **Frontend (Next.js 15 / App Router)** $\to$ **Vercel** (recommended) or **Render**

---

## Architecture Overview

```
┌─────────────────────────────────┐           ┌──────────────────────────────────┐
│   Frontend (Vercel / Render)    │           │      Backend (Render Web Svc)    │
│   Next.js 15 + Tailwind CSS v4  │  ──────>  │      Python 3 + FastAPI          │
│   Reads:                        │  HTTPS    │      Reads:                      │
│   NEXT_PUBLIC_API_BASE_URL      │  REST API │      FRONTEND_ORIGIN (CORS)      │
└─────────────────────────────────┘           └──────────────────────────────────┘
```

---

## Part 1: Deploy Backend to Render

### 1. Create a New Web Service
1. Sign in to your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** in the top navigation bar and select **Web Service**.
3. Under **Connect a repository**, select `GhostKernel19/HarvestGuard` (or connect your GitHub account if not already linked).

### 2. Configure Service Settings
Fill in the following fields in the Render creation form:

| Setting | Value | Notes |
| :--- | :--- | :--- |
| **Name** | `harvestguard-backend` | Or any unique name you prefer |
| **Region** | Closest to your users (e.g. `Frankfurt` or `Ohio`) | |
| **Branch** | `main` | Production branch |
| **Root Directory** | `backend` | **Crucial:** Render must build inside `/backend` |
| **Runtime** | `Python 3` | |
| **Build Command** | `pip install -r requirements.txt` | Installs pinned FastAPI, Uvicorn, ONNX, etc. |
| **Start Command** | `uvicorn main:app --host 0.0.0.0 --port $PORT` | Uses Render's dynamic `$PORT` |
| **Instance Type** | `Free` (or Starter for higher memory) | |

### 3. Configure Environment Variables (Render)
Scroll down to **Environment Variables** (or navigate to the **Environment** tab of your service) and add:

| Key | Example Value | Description |
| :--- | :--- | :--- |
| `PYTHON_VERSION` | `3.11.9` | Ensures a stable Python runtime matching prebuilt wheels |
| `FRONTEND_ORIGIN` | `https://your-frontend.vercel.app,http://localhost:3000` | Allowed origin(s) for CORS. *(Set to `*` initially if you don't have your frontend URL yet)* |
| `MODEL_PATH` | `models/qwen3_1.7b_qnn.bin` | Optional. If absent, backend automatically uses deterministic rule-based explainer |

### 4. Deploy and Verify
1. Click **Create Web Service**.
2. Once deployed, Render will display your service URL (e.g., `https://harvestguard-backend.onrender.com`).
3. Verify backend health in your browser or terminal:
   ```bash
   curl https://harvestguard-backend.onrender.com/api/health
   ```
   **Expected Response**:
   ```json
   {
     "status": "healthy",
     "engine": "HarvestGuard Core",
     "model_architecture": "Qwen3-1.7B",
     "execution_provider": "RuleBasedStub",
     "inference_mode": "rule_based_stub",
     "model_binary_present": false
   }
   ```

---

## Part 2: Deploy Frontend

### Option A: Deploy to Vercel (Recommended)

Vercel provides zero-configuration support for Next.js 15 and Turbopack builds.

#### 1. Import Project
1. Log in to [Vercel](https://vercel.com/new).
2. Under **Import Git Repository**, select `GhostKernel19/HarvestGuard`.

#### 2. Configure Project Settings
1. **Project Name**: `harvestguard` (or your preferred name).
2. **Framework Preset**: `Next.js`.
3. **Root Directory**: Click **Edit** and choose `frontend`.
4. **Build & Output Settings**: Leave as default (`npm run build`).

#### 3. Add Environment Variables
Expand the **Environment Variables** section and add:

| Key | Value | Description |
| :--- | :--- | :--- |
| `NEXT_PUBLIC_API_BASE_URL` | `https://harvestguard-backend.onrender.com` | **No trailing slash.** Points to your live Render backend URL. |

#### 4. Deploy
1. Click **Deploy**.
2. Once the build finishes, Vercel will assign your domain (e.g., `https://harvestguard.vercel.app`).

#### 5. Update Backend CORS
Return to your **Render Dashboard** $\to$ `harvestguard-backend` $\to$ **Environment**:
- Update `FRONTEND_ORIGIN` to match your Vercel domain:
  ```env
  FRONTEND_ORIGIN=https://harvestguard.vercel.app
  ```
- Render will automatically re-deploy with the updated CORS policy.

---

### Option B: Deploy Frontend to Render (Alternative)

If you prefer keeping both services on Render:

1. Click **New +** $\to$ **Web Service** on Render.
2. Select `GhostKernel19/HarvestGuard`.
3. Configure settings:
   - **Name**: `harvestguard-frontend`
   - **Root Directory**: `frontend`
   - **Environment**: `Node`
   - **Build Command**: `npm install && npm run build`
   - **Start Command**: `npm start`
4. Add Environment Variable:
   - `NEXT_PUBLIC_API_BASE_URL`: `https://harvestguard-backend.onrender.com`
5. Deploy and update `FRONTEND_ORIGIN` on the backend.

---

## Part 3: Post-Deployment Verification Checklist

- [ ] **Health Check**: Open `https://<your-backend>.onrender.com/api/health` and verify HTTP 200 with JSON status.
- [ ] **API Documentation**: Open `https://<your-backend>.onrender.com/docs` to test Swagger UI.
- [ ] **Frontend Live Status**: Open `https://<your-frontend>.vercel.app`. The top bar should show:
  ```
  ENGINE: RULE_BASED_STUB
  ```
  with an active status indicator.
- [ ] **Run Sample Scan**:
  - In the "Code Snippet" tab, click **SCAN_CODE_SNIPPET**.
  - Verify the MultiStepLoader progress animation runs.
  - Verify findings appear in the results dashboard.
  - Click **AI_EXPLAIN** on a finding to confirm the neural explanation, HNDL risk, and PQC migration target load properly.
  - Click **EXPLAIN_ALL_WITH_AI** to verify batch inference.
- [ ] **Zip Upload Scan**: Upload a sample zip archive to confirm the file-upload pipeline works in production.
