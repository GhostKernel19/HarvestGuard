"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { 
  ShieldCheck, 
  Cpu, 
  Code2, 
  Terminal, 
  CheckCircle2, 
  AlertCircle, 
  RefreshCw,
  ExternalLink,
  Layers
} from "lucide-react";

interface HealthStatus {
  status: string;
  engine: string;
  model_architecture: string;
  execution_provider: string;
  model_binary_present: boolean;
  qnn_status: string;
}

export default function Home() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const checkHealth = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("http://localhost:8000/api/health");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setHealth(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to reach backend");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkHealth();
  }, []);

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col font-sans">
      {/* Top Navigation */}
      <header className="border-b border-zinc-800 bg-zinc-900/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <span className="font-bold text-lg tracking-tight text-white">HarvestGuard</span>
              <span className="text-xs text-zinc-400 block -mt-1 font-mono">v0.1.0-scaffold</span>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-full bg-zinc-850 border border-zinc-800 text-xs text-zinc-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
              FastAPI + Next.js 15
            </div>
            <a
              href="http://localhost:8000/docs"
              target="_blank"
              rel="noreferrer"
            >
              <Button variant="outline" size="sm" className="border-zinc-700 bg-zinc-800/80 hover:bg-zinc-800 text-zinc-200 gap-1.5">
                API Docs <ExternalLink className="h-3.5 w-3.5 text-zinc-400" />
              </Button>
            </a>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-12 flex flex-col gap-10">
        {/* Hero Section */}
        <section className="text-center sm:text-left flex flex-col gap-4 border-b border-zinc-800 pb-10">
          <div className="inline-flex items-center gap-2 self-start px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-medium">
            <Layers className="h-3.5 w-3.5" />
            Post-Quantum Static Analysis & Local QNN Inference
          </div>
          <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white max-w-3xl">
            HarvestGuard Security Auditor Skeleton
          </h1>
          <p className="text-zinc-400 text-base sm:text-lg max-w-2xl leading-relaxed">
            Full-stack auditing architecture with a Python FastAPI static-analysis engine, Qualcomm Neural Network (QNN) execution provider pipeline for local Qwen3-1.7B, and a Next.js 15 App Router frontend.
          </p>
        </section>

        {/* Modules Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Card 1: Static Engine */}
          <div className="p-6 rounded-xl border border-zinc-800/80 bg-zinc-900/40 flex flex-col justify-between">
            <div className="flex flex-col gap-3">
              <div className="h-10 w-10 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
                <Code2 className="h-5 w-5" />
              </div>
              <h3 className="font-semibold text-white text-lg">Static-Analysis Engine</h3>
              <p className="text-sm text-zinc-400 leading-relaxed">
                Python FastAPI engine with endpoints for inspecting algorithms, crypto primitives, and post-quantum migration vulnerabilities.
              </p>
            </div>
            <div className="mt-6 pt-4 border-t border-zinc-800 font-mono text-xs text-zinc-500 flex justify-between">
              <span>Endpoint:</span>
              <span className="text-blue-400">POST /api/scan</span>
            </div>
          </div>

          {/* Card 2: QNN Inference */}
          <div className="p-6 rounded-xl border border-zinc-800/80 bg-zinc-900/40 flex flex-col justify-between">
            <div className="flex flex-col gap-3">
              <div className="h-10 w-10 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
                <Cpu className="h-5 w-5" />
              </div>
              <h3 className="font-semibold text-white text-lg">Local QNN Inference</h3>
              <p className="text-sm text-zinc-400 leading-relaxed">
                Qwen3-1.7B local model execution via ONNX Runtime accelerated with the Qualcomm Neural Network (QNN) Execution Provider.
              </p>
            </div>
            <div className="mt-6 pt-4 border-t border-zinc-800 font-mono text-xs text-zinc-500 flex justify-between">
              <span>Model Binary:</span>
              <span className="text-purple-400">models/qwen3_1.7b_qnn.bin</span>
            </div>
          </div>

          {/* Card 3: Next.js Frontend */}
          <div className="p-6 rounded-xl border border-zinc-800/80 bg-zinc-900/40 flex flex-col justify-between">
            <div className="flex flex-col gap-3">
              <div className="h-10 w-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                <Terminal className="h-5 w-5" />
              </div>
              <h3 className="font-semibold text-white text-lg">Next.js 15 + shadcn/ui</h3>
              <p className="text-sm text-zinc-400 leading-relaxed">
                Modern responsive interface using Next.js App Router, Tailwind CSS v4, and initialized shadcn/ui component primitives.
              </p>
            </div>
            <div className="mt-6 pt-4 border-t border-zinc-800 font-mono text-xs text-zinc-500 flex justify-between">
              <span>UI Framework:</span>
              <span className="text-emerald-400">Next.js 15 + Tailwind v4</span>
            </div>
          </div>
        </div>

        {/* Backend Connectivity Status Box */}
        <div className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/80 flex flex-col gap-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              {loading ? (
                <RefreshCw className="h-5 w-5 text-yellow-400 animate-spin" />
              ) : health ? (
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
              ) : (
                <AlertCircle className="h-5 w-5 text-rose-400" />
              )}
              <div>
                <h4 className="font-medium text-white">Backend Connection Status</h4>
                <p className="text-xs text-zinc-400">
                  {loading
                    ? "Connecting to http://localhost:8000/api/health..."
                    : health
                    ? "Connected to FastAPI Backend"
                    : error || "Disconnected"}
                </p>
              </div>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={checkHealth}
              disabled={loading}
              className="border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-200"
            >
              {loading ? "Checking..." : "Recheck Health"}
            </Button>
          </div>

          {health && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4 border-t border-zinc-800 text-xs">
              <div>
                <span className="text-zinc-500 block">Engine:</span>
                <span className="font-mono text-zinc-200">{health.engine}</span>
              </div>
              <div>
                <span className="text-zinc-500 block">Model Target:</span>
                <span className="font-mono text-zinc-200">{health.model_architecture}</span>
              </div>
              <div>
                <span className="text-zinc-500 block">Execution Provider:</span>
                <span className="font-mono text-zinc-200">{health.execution_provider}</span>
              </div>
              <div>
                <span className="text-zinc-500 block">Model Context:</span>
                <span className="font-mono text-yellow-400">
                  {health.model_binary_present ? "Binary Loaded" : "Placeholder Pending"}
                </span>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-zinc-800 py-6 text-center text-xs text-zinc-500">
        HarvestGuard Skeleton • Full-Stack Auditing Platform
      </footer>
    </div>
  );
}
