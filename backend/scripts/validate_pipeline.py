"""
HarvestGuard Pipeline Validation Script
Validates the end-to-end static-analysis and inference pipeline against target repositories.
Features explicit timeout handling, output flushing, pre-flight server checks, and full error tracebacks.
"""

import os
import sys
import time
import json
import traceback
import httpx

API_BASE = "http://127.0.0.1:8000"
DEFAULT_TARGET = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "tests", "demo_repo")
)
TARGET_DIR = os.environ.get("TARGET_DIR", DEFAULT_TARGET)

# Explicit timeouts for fail-fast behavior
CLIENT_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=5.0, pool=5.0)


def check_server_running(client: httpx.Client) -> dict:
    """Verifies that the backend server is reachable before initiating scans."""
    print(f"[*] Checking backend connectivity at {API_BASE}/api/health...", flush=True)
    try:
        res = client.get(f"{API_BASE}/api/health")
        if res.status_code != 200:
            print(f"[!] Server returned non-200 status code: {res.status_code} - {res.text}", flush=True)
            sys.exit(1)
        data = res.json()
        print(f"[+] Backend server is ACTIVE and HEALTHY.", flush=True)
        print(f"    - Engine:             {data.get('engine')}", flush=True)
        print(f"    - Execution Provider: {data.get('execution_provider')}", flush=True)
        print(f"    - Active Mode:        {data.get('inference_mode')}", flush=True)
        print(f"    - Model Binary:       {'Present' if data.get('model_binary_present') else 'Not Found (Using Rule-Based Explainer)'}", flush=True)
        return data
    except httpx.ConnectError:
        print(f"[!] FATAL: Backend server is NOT running at {API_BASE}.", flush=True)
        print(f"    Please start the server first in backend/:", flush=True)
        print(f"    .\\venv\\Scripts\\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000", flush=True)
        sys.exit(1)
    except httpx.TimeoutException:
        print(f"[!] FATAL: Health check timed out after 5.0 seconds connecting to {API_BASE}.", flush=True)
        sys.exit(1)


def run_pipeline_validation():
    print("=" * 78, flush=True)
    print(" HARVESTGUARD END-TO-END PIPELINE VALIDATION", flush=True)
    print("=" * 78, flush=True)
    print(f"Target Directory: {TARGET_DIR}", flush=True)
    print(f"Directory Exists: {os.path.exists(TARGET_DIR)}", flush=True)

    if not os.path.exists(TARGET_DIR):
        print(f"[!] Target directory does not exist: {TARGET_DIR}", flush=True)
        sys.exit(1)

    with httpx.Client(timeout=CLIENT_TIMEOUT) as client:
        # Step 1: Pre-flight check
        health_data = check_server_running(client)

        # Step 2: Static Analysis Scan
        print("\n" + "-" * 78, flush=True)
        print(f"[*] Step 1: Triggering POST /api/scan against {TARGET_DIR}...", flush=True)
        t0_scan = time.perf_counter()
        try:
            scan_res = client.post(
                f"{API_BASE}/api/scan",
                json={"target_path": TARGET_DIR}
            )
        except httpx.TimeoutException:
            print(f"[!] FATAL: POST /api/scan timed out after 30.0 seconds.", flush=True)
            sys.exit(1)
        except httpx.RequestError as exc:
            print(f"[!] FATAL: Network request failed during /api/scan: {exc}", flush=True)
            sys.exit(1)

        t1_scan = time.perf_counter()
        scan_duration = t1_scan - t0_scan

        if scan_res.status_code != 200:
            print(f"[!] POST /api/scan failed with status {scan_res.status_code}:", flush=True)
            print(scan_res.text, flush=True)
            sys.exit(1)

        scan_data = scan_res.json()
        files_scanned = scan_data.get("files_scanned", 0)
        summary = scan_data.get("summary", {})
        findings = scan_data.get("findings", [])

        print(f"[+] Static Analysis Completed in {scan_duration:.4f} s ({scan_duration * 1000:.2f} ms)", flush=True)
        print(f"    - Files Scanned:      {files_scanned}", flush=True)
        print(f"    - Total Findings:     {summary.get('total', 0)}", flush=True)
        print(f"    - High Severity:      {summary.get('high', 0)}", flush=True)
        print(f"    - Medium Severity:    {summary.get('medium', 0)}", flush=True)
        print(f"    - Low Severity:       {summary.get('low', 0)}", flush=True)
        print(f"    - Breakdown by Type:  {summary.get('by_type', {})}", flush=True)

        if not findings:
            print("\n[!] Zero quantum-vulnerable findings detected in target repository.", flush=True)
            print("=" * 78, flush=True)
            return

        print("\n[*] Detected Findings Breakdown:", flush=True)
        for idx, f in enumerate(findings, start=1):
            rel_file = f.get("file_path", "unknown")
            line = f.get("line_number", 0)
            vuln_type = f.get("vulnerability_type", "unknown")
            sev = f.get("severity", "unknown").upper()
            snippet = f.get("code_snippet", "").strip()
            print(f"    [{idx}] [{sev}] {vuln_type.ljust(15)} {rel_file}:{line}", flush=True)
            print(f"        Code: {snippet}", flush=True)

        # Step 3: Neural Explanation Inference (Batch Mode)
        print("\n" + "-" * 78, flush=True)
        print(f"[*] Step 2: Triggering POST /api/inference in batch mode ({len(findings)} findings)...", flush=True)
        t0_inf = time.perf_counter()
        try:
            inf_res = client.post(
                f"{API_BASE}/api/inference",
                json={"findings": findings}
            )
        except httpx.TimeoutException:
            print(f"[!] FATAL: POST /api/inference batch call timed out after 30.0 seconds.", flush=True)
            sys.exit(1)
        except httpx.RequestError as exc:
            print(f"[!] FATAL: Network request failed during /api/inference: {exc}", flush=True)
            sys.exit(1)

        t1_inf = time.perf_counter()
        inference_duration = t1_inf - t0_inf

        if inf_res.status_code != 200:
            print(f"[!] POST /api/inference failed with status {inf_res.status_code}:", flush=True)
            print(inf_res.text, flush=True)
            sys.exit(1)

        inf_data = inf_res.json()
        results = inf_data if isinstance(inf_data, list) else inf_data.get("results", [])
        mode_used = inf_data.get("mode") if isinstance(inf_data, dict) else (results[0].get("mode_used") if results else "unknown")

        print(f"[+] Batch Inference Completed in {inference_duration:.4f} s ({inference_duration * 1000:.2f} ms)", flush=True)
        print(f"    - Mode Used:          {mode_used}", flush=True)
        print(f"    - Explanations Count: {len(results)}", flush=True)

        # Step 4: Audit Explanations
        print("\n[*] Neural Explanation & Migration Audit:", flush=True)
        for idx, exp in enumerate(results, start=1):
            vuln_type = exp.get("vulnerability_type")
            explanation = exp.get("explanation")
            hndl = exp.get("harvest_now_risk", {})
            migration = exp.get("suggested_migration")
            is_risk = hndl.get("is_risk", False)
            hndl_reason = hndl.get("reason", "")

            print(f"\n--- Finding #{idx} ({vuln_type}) ---", flush=True)
            print(f"Assessment:  {explanation}", flush=True)
            print(f"HNDL Risk:   {'[ACTIVE EXPOSURE]' if is_risk else '[MINIMAL/NONE]'} - {hndl_reason}", flush=True)
            print(f"PQC Target:  {migration}", flush=True)

        # Total Pipeline Summary
        total_duration = scan_duration + inference_duration
        print("\n" + "=" * 78, flush=True)
        print(" PIPELINE PERFORMANCE SUMMARY", flush=True)
        print("=" * 78, flush=True)
        print(f"Static Analysis Scan: {scan_duration:.4f} s ({scan_duration * 1000:.2f} ms)", flush=True)
        print(f"Batch Inference:      {inference_duration:.4f} s ({inference_duration * 1000:.2f} ms)", flush=True)
        print(f"Total E2E Pipeline:   {total_duration:.4f} s ({total_duration * 1000:.2f} ms)", flush=True)
        print("=" * 78, flush=True)


if __name__ == "__main__":
    try:
        run_pipeline_validation()
    except Exception as e:
        print("\n[!] UNHANDLED RUNTIME EXCEPTION IN VALIDATION PIPELINE:", flush=True)
        traceback.print_exc()
        sys.exit(1)
