"use client";

import { cn } from "@/lib/utils";
import { AnimatePresence, motion } from "framer-motion";
import React, { useState, useEffect } from "react";
import { CheckCircle2, Loader2 } from "lucide-react";

export interface LoadingStep {
  text: string;
}

interface MultiStepLoaderProps {
  loadingStates: LoadingStep[];
  loading?: boolean;
  duration?: number;
  loop?: boolean;
}

export function MultiStepLoader({
  loadingStates,
  loading = false,
  duration = 1800,
  loop = true,
}: MultiStepLoaderProps) {
  const [currentState, setCurrentState] = useState(0);

  useEffect(() => {
    if (!loading) {
      setCurrentState(0);
      return;
    }
    const timeout = setTimeout(() => {
      setCurrentState((prevState) =>
        loop
          ? prevState === loadingStates.length - 1
            ? 0
            : prevState + 1
          : Math.min(prevState + 1, loadingStates.length - 1)
      );
    }, duration);

    return () => clearTimeout(timeout);
  }, [currentState, loading, loop, loadingStates.length, duration]);

  return (
    <AnimatePresence mode="wait">
      {loading && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="w-full h-full fixed inset-0 z-[100] flex items-center justify-center backdrop-blur-md bg-zinc-950/80"
        >
          <div className="h-96 relative flex flex-col justify-center items-start max-w-lg w-full p-8 rounded-2xl border border-zinc-800 bg-zinc-900/90 shadow-2xl shadow-cyan-950/30">
            {/* Terminal header */}
            <div className="w-full pb-4 mb-4 border-b border-zinc-800 flex items-center justify-between font-mono text-xs text-zinc-400">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full bg-cyan-400 animate-pulse"></span>
                <span>HARVESTGUARD_ANALYSIS_ENGINE</span>
              </div>
              <span className="text-zinc-500 font-mono">AST_RUNNING</span>
            </div>

            <div className="flex flex-col gap-4 w-full">
              {loadingStates.map((loadingState, index) => {
                const distance = Math.abs(index - currentState);
                const opacity = Math.max(1 - distance * 0.25, 0.2);
                const isPassed = index < currentState;
                const isCurrent = index === currentState;

                return (
                  <motion.div
                    key={index}
                    className={cn(
                      "flex items-center gap-3 text-left transition-all duration-300 font-mono text-sm",
                      isCurrent && "text-cyan-400 font-semibold",
                      isPassed && "text-zinc-400",
                      !isPassed && !isCurrent && "text-zinc-600"
                    )}
                    style={{ opacity }}
                  >
                    {isPassed ? (
                      <CheckCircle2 className="h-4 w-4 text-cyan-400 shrink-0" />
                    ) : isCurrent ? (
                      <Loader2 className="h-4 w-4 text-cyan-400 animate-spin shrink-0" />
                    ) : (
                      <div className="h-2 w-2 rounded-full bg-zinc-700 mx-1 shrink-0" />
                    )}
                    <span className="tracking-tight">{loadingState.text}</span>
                  </motion.div>
                );
              })}
            </div>

            <div className="mt-6 pt-4 border-t border-zinc-800/80 w-full flex justify-between items-center text-xs font-mono text-zinc-500">
              <span>Scanning syntax tree...</span>
              <span className="text-cyan-400 font-mono">
                {Math.round(((currentState + 1) / loadingStates.length) * 100)}%
              </span>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
