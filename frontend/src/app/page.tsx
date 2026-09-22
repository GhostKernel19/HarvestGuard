"use client";

import React, { useState, useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { MultiStepLoader } from "@/components/ui/multi-step-loader";
import { BackgroundBeams } from "@/components/ui/background-beams";
import { CardSpotlight } from "@/components/ui/card-spotlight";
import {
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Terminal,
  FolderOpen,
  UploadCloud,
  ChevronDown,
  ChevronUp,
  Sparkles,
  AlertTriangle,
  FileCode2,
  RefreshCw,
  Search,
  ExternalLink,
  Code,
  ArrowRight,
  Layers,
  Clock,
  KeyRound,
} from "lucide-react";

// API Base URL
const API_BASE = "http://127.0.0.1:8000";

// Standard demo path for one-click judge testing
const DEFAULT_SAMPLE_PATH = "tests/fixtures";

interface HealthData {
  status: string;
  engine: string;
  model_architecture: string;
  execution_provider: string;
  inference_mode: "qnn_npu" | "cpu_fallback" | "rule_based_stub" | string;
  model_binary_present: boolean;
}

interface Finding {
  file_path: string;
  line_number: number;
  code_snippet: string;
  vulnerability_type: "RSA" | "ECC" | "DH" | "weak-TLS-config" | string;
  severity: "high" | "medium" | "low" | string;
  description: string;
}

interface ScanSummary {
  total: number;
  high: number;
  medium: number;
  low: number;
  by_type: {
    RSA: number;
    ECC: number;
    DH: number;
    "weak-TLS-config": number;
    [key: string]: number;
  };
}

interface ScanResult {
  status: string;
  target?: string;
  files_scanned: number;
  summary: ScanSummary;
  findings: Finding[];
}

interface HarvestNowRisk {
  is_risk: boolean;
  reason: string;
}

interface FindingExplanation {
  vulnerability_type: string;
  explanation: string;
  harvest_now_risk: HarvestNowRisk;
  suggested_migration: string;
  mode_used: string;
}

const SCAN_STEPS = [
  { text: "Initializing AST parser for cryptographic primitives..." },
  { text: "Traversing syntax tree for integer factorization calls (RSA)..." },
  { text: "Detecting elliptic curve discrete logarithm usage (ECC)..." },
  { text: "Evaluating Diffie-Hellman parameter generation (DH)..." },
  { text: "Scanning configurations for weak TLS cipher suites..." },
  { text: 'Calculating "Harvest Now, Decrypt Later" exposure surface...' },
  { text: "Generating structured post-quantum risk report..." },
];

export default function HarvestGuardDashboard() {
  // Backend health status
  const [health, setHealth] = useState<HealthData | null>(null);
  const [healthLoading, setHealthLoading] = useState<boolean>(false);

  // Scan input states
  const [activeTab, setActiveTab] = useState<"path" | "upload" | "snippet">("path");
  const [targetPath, setTargetPath] = useState<string>(DEFAULT_SAMPLE_PATH);
  const [codeSnippet, setCodeSnippet] = useState<string>(
    `from Crypto.PublicKey import RSA\nfrom cryptography.hazmat.primitives.asymmetric import ec\n\n# Classical asymmetric keys vulnerable to Shor's algorithm\nrsa_key = RSA.generate(2048)\necc_key = ec.generate_private_key(ec.SECP256R1())\nCIPHERS = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"`
  );
  const [snippetLanguage, setSnippetLanguage] = useState<string>("python");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  // Scanning & results states
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Filter states
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [typeFilter, setTypeFilter] = useState<string>("all");

  // Explanations cache: key = `${file_path}:${line_number}:${vulnerability_type}`
  const [explanations, setExplanations] = useState<Record<string, FindingExplanation>>({});
  const [loadingExplanations, setLoadingExplanations] = useState<Record<string, boolean>>({});
  const [expandedCards, setExpandedCards] = useState<Record<string, boolean>>({});
  const [isExplainingAll, setIsExplainingAll] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Fetch backend health
  const fetchHealth = async () => {
    setHealthLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/health`);
      if (res.ok) {
        const data = await res.json();
        setHealth(data);
      }
    } catch {
      // Backend not reached
    } finally {
      setHealthLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  // Unique finding key helper
  const getFindingKey = (finding: Finding, index: number) => {
    return `${finding.file_path || "inline"}-${finding.line_number}-${finding.vulnerability_type}-${index}`;
  };

  // Run Scan
  const handleStartScan = async () => {
    setIsScanning(true);
    setScanError(null);
    setExpandedCards({});
    setExplanations({});

    try {
      let res: Response;

      if (activeTab === "path") {
        if (!targetPath.trim()) {
          throw new Error("Please specify a target repository or directory path.");
        }
        res = await fetch(`${API_BASE}/api/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target_path: targetPath.trim() }),
        });
      } else if (activeTab === "upload") {
        if (!selectedFile) {
          throw new Error("Please select a .zip archive of the codebase to upload.");
        }
        const formData = new FormData();
        formData.append("file", selectedFile);
        res = await fetch(`${API_BASE}/api/scan`, {
          method: "POST",
          body: formData,
        });
      } else {
        if (!codeSnippet.trim()) {
          throw new Error("Please enter a code snippet to scan.");
        }
        res = await fetch(`${API_BASE}/api/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            code_snippet: codeSnippet,
            language: snippetLanguage,
          }),
        });
      }

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || `Scan request failed with HTTP ${res.status}`);
      }

      const data: ScanResult = await res.json();
      setScanResult(data);
    } catch (err: unknown) {
      setScanError(err instanceof Error ? err.message : "An unexpected scan error occurred.");
    } finally {
      setIsScanning(false);
    }
  };

  // Fetch explanation for a single finding
  const handleExplainFinding = async (finding: Finding, key: string) => {
    // Toggle expansion
    const isCurrentlyExpanded = !!expandedCards[key];
    setExpandedCards((prev) => ({ ...prev, [key]: !isCurrentlyExpanded }));

    // If already cached or expanding closing, return
    if (explanations[key] || isCurrentlyExpanded) return;

    setLoadingExplanations((prev) => ({ ...prev, [key]: true }));
    try {
      const res = await fetch(`${API_BASE}/api/inference`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(finding),
      });

      if (res.ok) {
        const data: FindingExplanation = await res.json();
        setExplanations((prev) => ({ ...prev, [key]: data }));
      }
    } catch {
      // Failed to fetch explanation
    } finally {
      setLoadingExplanations((prev) => ({ ...prev, [key]: false }));
    }
  };

  // Batch "Explain All"
  const handleExplainAll = async () => {
    if (!scanResult || scanResult.findings.length === 0) return;

    setIsExplainingAll(true);
    // Expand all cards immediately
    const allExpanded: Record<string, boolean> = {};
    scanResult.findings.forEach((f, i) => {
      allExpanded[getFindingKey(f, i)] = true;
    });
    setExpandedCards(allExpanded);

    try {
      const res = await fetch(`${API_BASE}/api/inference`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findings: scanResult.findings }),
      });

      if (res.ok) {
        const data = await res.json();
        const results: FindingExplanation[] = Array.isArray(data)
          ? data
          : data.results || [];

        const newExplanations: Record<string, FindingExplanation> = { ...explanations };
        scanResult.findings.forEach((f, i) => {
          if (results[i]) {
            newExplanations[getFindingKey(f, i)] = results[i];
          }
        });
        setExplanations(newExplanations);
      }
    } catch {
      // Batch failure
    } finally {
      setIsExplainingAll(false);
    }
  };

  // Filtered findings list
  const filteredFindings = (scanResult?.findings || []).filter((f) => {
    const matchesSeverity =
      severityFilter === "all" || f.severity.toLowerCase() === severityFilter.toLowerCase();
    const matchesType =
      typeFilter === "all" || f.vulnerability_type.toLowerCase() === typeFilter.toLowerCase();
    return matchesSeverity && matchesType;
  });

  return (
    <div className="min-h-screen bg-[#090d16] text-zinc-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* Aceternity MultiStepLoader for Scan In-Flight State */}
      <MultiStepLoader
        loading={isScanning}
        loadingStates={SCAN_STEPS}
        duration={1100}
        loop={false}
      />

      {/* Top Terminal Bar */}
      <header className="border-b border-zinc-800/80 bg-[#090d16]/90 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-lg bg-cyan-950/50 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.2)]">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <span className="font-mono font-bold text-lg tracking-wider text-white flex items-center gap-1.5">
                HARVEST<span className="text-cyan-400">GUARD</span>
              </span>
              <span className="text-[11px] text-zinc-500 font-mono tracking-tight block -mt-1">
                POST_QUANTUM_SECURITY_SCANNER
              </span>
            </div>
          </div>

          {/* Live Backend Status Badge */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2.5 px-3 py-1.5 rounded-full bg-zinc-900 border border-zinc-800 text-xs font-mono">
              <span
                className={`h-2 w-2 rounded-full ${
                  health
                    ? health.inference_mode === "qnn_npu"
                      ? "bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)] animate-pulse"
                      : "bg-cyan-500"
                    : "bg-zinc-600"
                }`}
              />
              <span className="text-zinc-400">
                {health ? (
                  <span>
                    ENGINE:{" "}
                    <span className="text-cyan-400 font-semibold uppercase">
                      {health.inference_mode}
                    </span>
                  </span>
                ) : (
                  <span className="text-zinc-500">BACKEND_DISCONNECTED</span>
                )}
              </span>
              <button
                onClick={fetchHealth}
                disabled={healthLoading}
                className="text-zinc-500 hover:text-cyan-400 transition-colors"
                title="Refresh health status"
              >
                <RefreshCw className={`h-3 w-3 ${healthLoading ? "animate-spin" : ""}`} />
              </button>
            </div>

            <a
              href={`${API_BASE}/docs`}
              target="_blank"
              rel="noreferrer"
              className="hidden sm:inline-flex"
            >
              <Button
                variant="outline"
                size="sm"
                className="border-zinc-800 bg-zinc-900/60 hover:bg-zinc-800 hover:border-cyan-500/40 text-zinc-300 gap-1.5 font-mono text-xs"
              >
                SWAGGER_DOCS <ExternalLink className="h-3 w-3 text-cyan-400" />
              </Button>
            </a>
          </div>
        </div>
      </header>

      {/* Main Section */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-10 flex flex-col gap-10 relative">
        {/* Background Beams Pattern */}
        <BackgroundBeams />

        {/* Hero Section */}
        <section className="relative z-10 flex flex-col gap-4 text-center sm:text-left pt-2 pb-6 border-b border-zinc-800/80">
          <div className="inline-flex items-center gap-2 self-start px-3 py-1 rounded-full bg-cyan-950/40 border border-cyan-500/30 text-cyan-400 text-xs font-mono">
            <KeyRound className="h-3.5 w-3.5" />
            NIST FIPS 203 / 204 POST-QUANTUM COMPLIANCE
          </div>

          <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white font-mono">
            Find quantum-vulnerable cryptography before someone else{" "}
            <span className="text-cyan-400 underline decoration-cyan-500/40 underline-offset-8">
              harvests your data
            </span>{" "}
            to decrypt later.
          </h1>

          <p className="text-zinc-400 text-base sm:text-lg max-w-3xl leading-relaxed font-sans">
            Static analysis engine paired with a local Qwen3-1.7B neural auditor running via ONNX
            Runtime with Qualcomm QNN Execution Provider. Inspects RSA, ECC, Diffie-Hellman, and
            weak TLS cipher suites for Harvest Now, Decrypt Later (HNDL) exposure.
          </p>

          {/* Quick Engine Meta Bar */}
          {health && (
            <div className="flex flex-wrap items-center gap-3 pt-2 text-xs font-mono text-zinc-400">
              <span className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-800">
                PROVIDER: <span className="text-cyan-400">{health.execution_provider}</span>
              </span>
              <span className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-800">
                MODEL: <span className="text-zinc-200">{health.model_architecture}</span>
              </span>
              <span className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-800">
                NPU CONTEXT:{" "}
                <span className={health.model_binary_present ? "text-cyan-400" : "text-zinc-500"}>
                  {health.model_binary_present ? "ACTIVE_BIN" : "RULE_BASED_STUB"}
                </span>
              </span>
            </div>
          )}
        </section>

        {/* Primary CTA: Scan Input Console */}
        <section className="relative z-10">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-6 flex flex-col gap-6 shadow-xl shadow-cyan-950/10">
            {/* Tabs */}
            <div className="flex items-center gap-2 border-b border-zinc-800 pb-4">
              <button
                onClick={() => setActiveTab("path")}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg font-mono text-xs font-medium transition-all ${
                  activeTab === "path"
                    ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/40"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-850"
                }`}
              >
                <FolderOpen className="h-4 w-4" />
                LOCAL_REPO_PATH
              </button>
              <button
                onClick={() => setActiveTab("upload")}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg font-mono text-xs font-medium transition-all ${
                  activeTab === "upload"
                    ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/40"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-850"
                }`}
              >
                <UploadCloud className="h-4 w-4" />
                ZIP_FILE_UPLOAD
              </button>
              <button
                onClick={() => setActiveTab("snippet")}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg font-mono text-xs font-medium transition-all ${
                  activeTab === "snippet"
                    ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/40"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-850"
                }`}
              >
                <Code className="h-4 w-4" />
                CODE_SNIPPET
              </button>
            </div>

            {/* Tab 1: Local Path Input */}
            {activeTab === "path" && (
              <div className="flex flex-col gap-3">
                <label className="text-xs font-mono text-zinc-400 flex items-center justify-between">
                  <span>DIRECTORY OR REPO PATH:</span>
                  <button
                    onClick={() => setTargetPath(DEFAULT_SAMPLE_PATH)}
                    className="text-cyan-400 hover:underline text-[11px]"
                  >
                    Load Sample Test Fixtures (Demo)
                  </button>
                </label>
                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="relative flex-1">
                    <Terminal className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
                    <input
                      type="text"
                      value={targetPath}
                      onChange={(e) => setTargetPath(e.target.value)}
                      placeholder="e.g. tests/fixtures or D:/MyProject"
                      className="w-full bg-zinc-950 border border-zinc-800 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/50 rounded-lg pl-10 pr-4 py-2.5 font-mono text-sm text-zinc-200 placeholder:text-zinc-600 outline-none transition-all"
                    />
                  </div>
                  <Button
                    onClick={handleStartScan}
                    disabled={isScanning}
                    className="bg-cyan-500 hover:bg-cyan-400 text-zinc-950 font-mono font-semibold px-6 py-2.5 rounded-lg gap-2 shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all shrink-0"
                  >
                    {isScanning ? (
                      <>
                        <RefreshCw className="h-4 w-4 animate-spin" />
                        SCANNING...
                      </>
                    ) : (
                      <>
                        EXECUTE_SCAN <ArrowRight className="h-4 w-4" />
                      </>
                    )}
                  </Button>
                </div>
              </div>
            )}

            {/* Tab 2: Zip Upload Dropzone */}
            {activeTab === "upload" && (
              <div className="flex flex-col gap-3">
                <input
                  type="file"
                  ref={fileInputRef}
                  accept=".zip"
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      setSelectedFile(e.target.files[0]);
                    }
                  }}
                  className="hidden"
                />
                <div
                  onClick={() => fileInputRef.current?.click()}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    e.preventDefault();
                    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                      setSelectedFile(e.dataTransfer.files[0]);
                    }
                  }}
                  className="border-2 border-dashed border-zinc-800 hover:border-cyan-500/50 rounded-xl p-8 flex flex-col items-center justify-center gap-3 cursor-pointer bg-zinc-950/60 transition-all group"
                >
                  <div className="h-12 w-12 rounded-full bg-cyan-950/40 border border-cyan-500/30 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
                    <UploadCloud className="h-6 w-6" />
                  </div>
                  <div className="text-center font-mono">
                    <p className="text-sm text-zinc-300 font-medium">
                      {selectedFile ? (
                        <span className="text-cyan-400 font-bold">{selectedFile.name}</span>
                      ) : (
                        "Click to browse or drag & drop a codebase .zip archive"
                      )}
                    </p>
                    <p className="text-xs text-zinc-500 mt-1">
                      Archives are extracted securely in sandboxed memory for AST analysis
                    </p>
                  </div>
                </div>

                <Button
                  onClick={handleStartScan}
                  disabled={!selectedFile || isScanning}
                  className="bg-cyan-500 hover:bg-cyan-400 text-zinc-950 font-mono font-semibold px-6 py-2.5 rounded-lg gap-2 self-end shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all disabled:opacity-50"
                >
                  {isScanning ? "UPLOADING & SCANNING..." : "SCAN_ZIP_ARCHIVE"}
                </Button>
              </div>
            )}

            {/* Tab 3: Code Snippet */}
            {activeTab === "snippet" && (
              <div className="flex flex-col gap-3">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-mono text-zinc-400">INLINE CODE SNIPPET:</label>
                  <select
                    value={snippetLanguage}
                    onChange={(e) => setSnippetLanguage(e.target.value)}
                    className="bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1 text-xs font-mono text-cyan-400 outline-none"
                  >
                    <option value="python">Python (AST Parsed)</option>
                    <option value="javascript">JavaScript / Node</option>
                    <option value="java">Java</option>
                  </select>
                </div>
                <textarea
                  rows={6}
                  value={codeSnippet}
                  onChange={(e) => setCodeSnippet(e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/50 rounded-lg p-3 font-mono text-xs text-zinc-300 outline-none leading-relaxed"
                />
                <Button
                  onClick={handleStartScan}
                  disabled={isScanning}
                  className="bg-cyan-500 hover:bg-cyan-400 text-zinc-950 font-mono font-semibold px-6 py-2.5 rounded-lg gap-2 self-end shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all"
                >
                  {isScanning ? "SCANNING SNIPPET..." : "SCAN_CODE_SNIPPET"}
                </Button>
              </div>
            )}

            {scanError && (
              <div className="p-4 rounded-lg bg-rose-950/20 border border-rose-900/60 text-rose-300 font-mono text-xs flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
                <span>SCAN_ERROR: {scanError}</span>
              </div>
            )}
          </div>
        </section>

        {/* Results Dashboard Section */}
        {scanResult && (
          <section className="relative z-10 flex flex-col gap-8 pt-4">
            {/* Summary Cards Header */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-zinc-800/80 pb-4">
              <div>
                <h2 className="text-xl font-bold font-mono text-white flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5 text-cyan-400" />
                  AUDIT_RESULTS
                </h2>
                <p className="text-xs text-zinc-500 font-mono mt-0.5">
                  TARGET: {scanResult.target || "inline_snippet"} • SCANNED:{" "}
                  {scanResult.files_scanned} FILE(S)
                </p>
              </div>

              {/* Explain All Primary Action */}
              <div className="flex items-center gap-3">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleExplainAll}
                  disabled={isExplainingAll || scanResult.findings.length === 0}
                  className="border-cyan-500/40 bg-cyan-950/30 hover:bg-cyan-950/60 text-cyan-300 font-mono text-xs gap-1.5 shadow-[0_0_12px_rgba(6,182,212,0.15)]"
                >
                  <Sparkles
                    className={`h-3.5 w-3.5 text-cyan-400 ${
                      isExplainingAll ? "animate-spin" : ""
                    }`}
                  />
                  {isExplainingAll ? "EXPLAINING ALL FINDINGS..." : "EXPLAIN_ALL_WITH_AI"}
                </Button>
              </div>
            </div>

            {/* Summary Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {/* Total Findings Card */}
              <CardSpotlight className="flex flex-col justify-between">
                <span className="text-xs font-mono text-zinc-400">TOTAL FINDINGS</span>
                <div className="text-3xl font-extrabold font-mono text-white mt-2">
                  {scanResult.summary.total}
                </div>
                <div className="mt-3 pt-2 border-t border-zinc-800/60 text-[11px] font-mono text-zinc-500">
                  ATTACK SURFACE DETECTED
                </div>
              </CardSpotlight>

              {/* High Severity */}
              <CardSpotlight className="flex flex-col justify-between border-cyan-500/30">
                <span className="text-xs font-mono text-cyan-400 flex items-center justify-between">
                  <span>HIGH (KEYGEN / DH)</span>
                  <span className="h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#06b6d4]"></span>
                </span>
                <div className="text-3xl font-extrabold font-mono text-cyan-300 mt-2">
                  {scanResult.summary.high}
                </div>
                <div className="mt-3 pt-2 border-t border-zinc-800/60 text-[11px] font-mono text-cyan-500/70">
                  IMMEDIATE HNDL RISK
                </div>
              </CardSpotlight>

              {/* Medium Severity */}
              <CardSpotlight className="flex flex-col justify-between">
                <span className="text-xs font-mono text-zinc-300">MEDIUM (SIG / TLS)</span>
                <div className="text-3xl font-extrabold font-mono text-zinc-200 mt-2">
                  {scanResult.summary.medium}
                </div>
                <div className="mt-3 pt-2 border-t border-zinc-800/60 text-[11px] font-mono text-zinc-500">
                  FORGERY & WEAK SUITES
                </div>
              </CardSpotlight>

              {/* Low Severity */}
              <CardSpotlight className="flex flex-col justify-between">
                <span className="text-xs font-mono text-zinc-400">LOW (BARE IMPORTS)</span>
                <div className="text-3xl font-extrabold font-mono text-zinc-400 mt-2">
                  {scanResult.summary.low}
                </div>
                <div className="mt-3 pt-2 border-t border-zinc-800/60 text-[11px] font-mono text-zinc-500">
                  LEGACY DEPENDENCIES
                </div>
              </CardSpotlight>
            </div>

            {/* Type Breakdown Bar */}
            <div className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/40 flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
              <span className="text-zinc-400 flex items-center gap-1.5 font-semibold">
                <Layers className="h-4 w-4 text-cyan-400" />
                VULNERABILITY_BREAKDOWN:
              </span>
              <div className="flex flex-wrap items-center gap-4">
                <span className="px-2.5 py-1 rounded bg-zinc-950 border border-zinc-800 text-zinc-300">
                  RSA:{" "}
                  <span className="text-cyan-400 font-bold">
                    {scanResult.summary.by_type.RSA || 0}
                  </span>
                </span>
                <span className="px-2.5 py-1 rounded bg-zinc-950 border border-zinc-800 text-zinc-300">
                  ECC:{" "}
                  <span className="text-cyan-400 font-bold">
                    {scanResult.summary.by_type.ECC || 0}
                  </span>
                </span>
                <span className="px-2.5 py-1 rounded bg-zinc-950 border border-zinc-800 text-zinc-300">
                  DH:{" "}
                  <span className="text-cyan-400 font-bold">
                    {scanResult.summary.by_type.DH || 0}
                  </span>
                </span>
                <span className="px-2.5 py-1 rounded bg-zinc-950 border border-zinc-800 text-zinc-300">
                  WEAK_TLS:{" "}
                  <span className="text-cyan-400 font-bold">
                    {scanResult.summary.by_type["weak-TLS-config"] || 0}
                  </span>
                </span>
              </div>
            </div>

            {/* Filters Bar */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pt-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-mono text-zinc-500 mr-1">SEVERITY:</span>
                {["all", "high", "medium", "low"].map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`px-3 py-1 rounded text-xs font-mono uppercase transition-all ${
                      severityFilter === sev
                        ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 font-bold"
                        : "bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-mono text-zinc-500 mr-1">TYPE:</span>
                {["all", "RSA", "ECC", "DH", "weak-TLS-config"].map((t) => (
                  <button
                    key={t}
                    onClick={() => setTypeFilter(t)}
                    className={`px-3 py-1 rounded text-xs font-mono transition-all ${
                      typeFilter === t
                        ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 font-bold"
                        : "bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            {/* Findings List */}
            <div className="flex flex-col gap-4">
              {filteredFindings.length === 0 ? (
                <div className="p-12 text-center border border-zinc-800 rounded-xl bg-zinc-900/30 font-mono text-sm text-zinc-500">
                  No findings match current filter criteria.
                </div>
              ) : (
                filteredFindings.map((finding, index) => {
                  const key = getFindingKey(finding, index);
                  const isExpanded = !!expandedCards[key];
                  const explanation = explanations[key];
                  const isLoading = !!loadingExplanations[key];

                  // Monochromatic cyan severity styling
                  const isHigh = finding.severity.toLowerCase() === "high";
                  const isMedium = finding.severity.toLowerCase() === "medium";

                  const severityBadgeStyle = isHigh
                    ? "bg-cyan-950/80 text-cyan-300 border-cyan-500/60 shadow-[0_0_8px_rgba(6,182,212,0.3)]"
                    : isMedium
                    ? "bg-cyan-950/30 text-cyan-400/90 border-cyan-800/60"
                    : "bg-zinc-900 text-zinc-400 border-zinc-700/60";

                  const cardBorderStyle = isHigh
                    ? "border-cyan-500/40 hover:border-cyan-500/70"
                    : "border-zinc-800 hover:border-zinc-700";

                  return (
                    <div
                      key={key}
                      className={`rounded-xl border ${cardBorderStyle} bg-zinc-900/50 transition-all duration-200 overflow-hidden`}
                    >
                      {/* Card Header Summary */}
                      <div
                        onClick={() => handleExplainFinding(finding, key)}
                        className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer hover:bg-zinc-850/50 transition-colors"
                      >
                        <div className="flex flex-col gap-1.5 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            {/* Severity Badge */}
                            <span
                              className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold uppercase border ${severityBadgeStyle}`}
                            >
                              {finding.severity}
                            </span>

                            {/* Vulnerability Type Badge */}
                            <span className="px-2.5 py-0.5 rounded text-[11px] font-mono bg-zinc-950 border border-zinc-800 text-zinc-300">
                              {finding.vulnerability_type}
                            </span>

                            {/* File Path & Line */}
                            <span className="font-mono text-xs text-zinc-400 flex items-center gap-1">
                              <FileCode2 className="h-3.5 w-3.5 text-zinc-500" />
                              <span className="text-zinc-200">{finding.file_path}</span>
                              <span className="text-cyan-400">:{finding.line_number}</span>
                            </span>
                          </div>

                          <p className="text-sm text-zinc-300 font-sans mt-0.5">
                            {finding.description}
                          </p>
                        </div>

                        {/* Expand / Explain Trigger */}
                        <div className="flex items-center gap-3 shrink-0">
                          <Button
                            variant="outline"
                            size="sm"
                            className="border-zinc-800 bg-zinc-900 hover:border-cyan-500/40 text-cyan-400 font-mono text-xs gap-1.5"
                          >
                            <Sparkles className="h-3 w-3 text-cyan-400" />
                            {isExpanded ? "HIDE_ANALYSIS" : "AI_EXPLAIN"}
                            {isExpanded ? (
                              <ChevronUp className="h-3.5 w-3.5 text-zinc-400" />
                            ) : (
                              <ChevronDown className="h-3.5 w-3.5 text-zinc-400" />
                            )}
                          </Button>
                        </div>
                      </div>

                      {/* Code Snippet Preview */}
                      <div className="px-5 pb-4">
                        <div className="p-2.5 rounded bg-zinc-950 border border-zinc-850 font-mono text-xs text-zinc-300 overflow-x-auto flex items-center justify-between">
                          <code className="text-cyan-300/90">{finding.code_snippet}</code>
                          <span className="text-[10px] text-zinc-600 font-mono shrink-0 ml-3">
                            L{finding.line_number}
                          </span>
                        </div>
                      </div>

                      {/* Expandable Explanation Area */}
                      {isExpanded && (
                        <div className="border-t border-zinc-800 bg-zinc-950/70 p-6 flex flex-col gap-4 font-mono">
                          {isLoading ? (
                            <div className="py-6 flex items-center justify-center gap-3 text-cyan-400 text-xs font-mono">
                              <RefreshCw className="h-4 w-4 animate-spin text-cyan-400" />
                              <span>QUERYING LOCAL QWEN3-1.7B NEURAL ENGINE...</span>
                            </div>
                          ) : explanation ? (
                            <div className="flex flex-col gap-5">
                              {/* 1. Plain-Language Explanation */}
                              <div className="flex flex-col gap-1.5">
                                <span className="text-xs text-zinc-400 uppercase tracking-wider flex items-center gap-1.5">
                                  <Terminal className="h-3.5 w-3.5 text-cyan-400" />
                                  QUANTUM_VULNERABILITY_ASSESSMENT:
                                </span>
                                <p className="text-sm text-zinc-200 font-sans leading-relaxed">
                                  {explanation.explanation}
                                </p>
                              </div>

                              {/* 2. Harvest Now, Decrypt Later (HNDL) Risk */}
                              <div className="p-3.5 rounded-lg border border-cyan-500/30 bg-cyan-950/20 flex flex-col gap-1.5">
                                <div className="flex items-center justify-between">
                                  <span className="text-xs text-cyan-400 font-bold flex items-center gap-1.5">
                                    <Clock className="h-3.5 w-3.5" />
                                    HARVEST NOW, DECRYPT LATER (HNDL) THREAT:
                                  </span>
                                  <span
                                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                      explanation.harvest_now_risk.is_risk
                                        ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                                        : "bg-zinc-800 text-zinc-400"
                                    }`}
                                  >
                                    {explanation.harvest_now_risk.is_risk
                                      ? "ACTIVE_EXPOSURE"
                                      : "MINIMAL_EXPOSURE"}
                                  </span>
                                </div>
                                <p className="text-xs text-zinc-300 font-sans mt-0.5">
                                  {explanation.harvest_now_risk.reason}
                                </p>
                              </div>

                              {/* 3. Concrete Suggested PQC Migration */}
                              <div className="flex flex-col gap-1.5">
                                <span className="text-xs text-zinc-400 uppercase tracking-wider flex items-center gap-1.5">
                                  <KeyRound className="h-3.5 w-3.5 text-cyan-400" />
                                  RECOMMENDED_PQC_MIGRATION:
                                </span>
                                <p className="text-xs text-cyan-300 font-sans bg-zinc-900/80 p-3 rounded border border-zinc-800 leading-relaxed">
                                  {explanation.suggested_migration}
                                </p>
                              </div>

                              {/* Engine Mode Footer */}
                              <div className="pt-2 border-t border-zinc-850 flex items-center justify-between text-[11px] text-zinc-500">
                                <span>
                                  INFERENCE_PROVIDER:{" "}
                                  <span className="text-cyan-400 uppercase font-semibold">
                                    {explanation.mode_used}
                                  </span>
                                </span>
                                <span>CACHED_IN_SESSION</span>
                              </div>
                            </div>
                          ) : (
                            <div className="text-xs text-zinc-500">
                              Unable to generate explanation for this finding.
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </section>
        )}
      </main>

      {/* Terminal Footer */}
      <footer className="border-t border-zinc-800/80 py-6 text-center text-xs font-mono text-zinc-500 mt-auto">
        HARVESTGUARD v0.1.0 • QUALCOMM QNN EP & ONNX RUNTIME • NIST FIPS 203/204
      </footer>
    </div>
  );
}
