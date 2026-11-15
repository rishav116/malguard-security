"use client";

import React from "react";
import { CheckCircle2, Loader2, Shield, Binary, Hash, Cpu, AlertCircle } from "lucide-react";

export type StageStatus = "pending" | "processing" | "completed" | "error";

export interface ScanStage {
  id: string;
  name: string;
  description: string;
  icon: React.ElementType;
  status: StageStatus;
}

interface InspectionProgressProps {
  stages: ScanStage[];
  currentStepIndex: number;
}

export default function InspectionProgress({
  stages,
  currentStepIndex,
}: InspectionProgressProps) {
  return (
    <div className="w-full p-5 sm:p-6 rounded-2xl bg-[#071120]/90 border border-white/[0.08] backdrop-blur-xl shadow-xl">
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-white/[0.06]">
        <div className="flex items-center gap-2.5">
          <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#22d3ee]" />
          <span className="text-xs font-mono font-bold tracking-wider text-white uppercase">
            Binary Inspection Pipeline
          </span>
        </div>
        <span className="text-xs font-mono text-cyan-300">
          Step {Math.min(currentStepIndex + 1, stages.length)} of {stages.length}
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 sm:gap-3">
        {stages.map((stage, idx) => {
          const Icon = stage.icon;
          const isDone = stage.status === "completed";
          const isProcessing = stage.status === "processing";
          const isError = stage.status === "error";

          return (
            <div
              key={stage.id}
              className={`p-3.5 rounded-xl border transition-all ${
                isProcessing
                  ? "bg-cyan-950/40 border-cyan-400/50 shadow-[0_0_15px_rgba(34,211,238,0.2)]"
                  : isDone
                  ? "bg-[#09172e]/60 border-cyan-500/20"
                  : isError
                  ? "bg-rose-950/40 border-rose-500/30"
                  : "bg-slate-900/30 border-white/[0.04] opacity-50"
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <div
                  className={`w-7 h-7 rounded-lg flex items-center justify-center ${
                    isDone
                      ? "bg-cyan-500/20 text-cyan-400"
                      : isProcessing
                      ? "bg-cyan-400 text-slate-950 animate-pulse"
                      : isError
                      ? "bg-rose-500/20 text-rose-400"
                      : "bg-slate-800 text-slate-500"
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                </div>

                <div>
                  {isDone && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                  {isProcessing && <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />}
                  {isError && <AlertCircle className="w-4 h-4 text-rose-400" />}
                </div>
              </div>

              <div className="text-xs font-bold text-white font-display truncate">
                {stage.name}
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5 truncate">
                {stage.description}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

