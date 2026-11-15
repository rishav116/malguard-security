"use client";

import React, { useState } from "react";
import { 
  FileCode2, 
  ShieldCheck, 
  Copy, 
  Check, 
  Binary, 
  Cpu, 
  Clock, 
  Layers, 
  BarChart3, 
  Terminal, 
  FileText,
  AlertCircle
} from "lucide-react";
import { PEInspectionResult } from "@/lib/scanner/peParser";

interface FileInspectionCardProps {
  inspection: PEInspectionResult;
  onReset: () => void;
}

export default function FileInspectionCard({
  inspection,
  onReset,
}: FileInspectionCardProps) {
  const [copied, setCopied] = useState(false);

  const handleCopyHash = () => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(inspection.sha256);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  // Determine entropy level note
  const getEntropyBadge = (entropy: number) => {
    if (entropy > 7.2) {
      return {
        label: "High Entropy (Possible Packing / Compression)",
        color: "text-amber-400 bg-amber-950/60 border-amber-500/30",
        barColor: "bg-amber-400",
      };
    } else if (entropy > 6.0) {
      return {
        label: "Normal Binary Code Distribution",
        color: "text-cyan-300 bg-cyan-950/60 border-cyan-500/30",
        barColor: "bg-cyan-400",
      };
    } else {
      return {
        label: "Low Entropy (Unpacked / Text / Plain Code)",
        color: "text-emerald-300 bg-emerald-950/60 border-emerald-500/30",
        barColor: "bg-emerald-400",
      };
    }
  };

  const entropyMeta = getEntropyBadge(inspection.entropy);

  return (
    <div className="w-full space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
      
      {/* Top Banner: File Summary */}
      <div className="p-4 xs:p-6 rounded-2xl bg-[#071120]/95 border border-cyan-500/30 backdrop-blur-xl shadow-[0_0_40px_rgba(34,211,238,0.12)]">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-5 border-b border-white/[0.08]">
          <div className="flex items-center gap-3 xs:gap-4 min-w-0">
            <div className="w-12 h-12 xs:w-14 xs:h-14 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-purple-600/20 border border-cyan-400/40 text-cyan-400 flex items-center justify-center shrink-0 shadow-[0_0_15px_rgba(34,211,238,0.3)]">
              <FileCode2 className="w-6 h-6 xs:w-7 xs:h-7" />
            </div>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2 mb-1">
                <h2 className="text-lg xs:text-xl sm:text-2xl font-bold text-white font-display tracking-tight break-all">
                  {inspection.fileName}
                </h2>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 shrink-0">
                  {inspection.targetType}
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-2 xs:gap-3 text-xs font-mono text-slate-400">
                <span>Size: <strong className="text-slate-200">{inspection.formattedSize}</strong></span>
                <span>•</span>
                <span>Arch: <strong className="text-slate-200">{inspection.architecture}</strong></span>
              </div>
            </div>
          </div>

          <button
            onClick={onReset}
            className="w-full sm:w-auto justify-center px-4 py-2 rounded-xl bg-slate-800/80 hover:bg-slate-700/80 border border-white/10 hover:border-cyan-500/30 text-xs font-mono text-slate-300 hover:text-white transition-all cursor-pointer shrink-0 min-h-[38px] active:scale-95 flex items-center"
          >
            ← Scan Another File
          </button>
        </div>

        {/* Cryptographic SHA-256 Box */}
        <div className="mt-5 p-4 rounded-xl bg-[#040914] border border-cyan-500/20 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-start sm:items-center gap-3 overflow-hidden w-full">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 shrink-0">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div className="overflow-hidden w-full">
              <div className="text-xs uppercase tracking-wider font-mono font-medium text-slate-400 flex items-center gap-2 flex-wrap">
                <span>Verified SHA-256 Digest (Web Crypto API)</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-500/30 font-medium">
                  Real Hash
                </span>
              </div>
              <div className="text-xs sm:text-sm font-mono text-cyan-300 break-all select-all font-semibold mt-0.5">
                {inspection.sha256}
              </div>
            </div>
          </div>

          <button
            onClick={handleCopyHash}
            className="w-full sm:w-auto justify-center flex items-center gap-1.5 px-3 py-2 sm:py-1.5 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-500/30 text-xs font-mono text-cyan-300 transition-colors shrink-0 cursor-pointer min-h-[38px] active:scale-95"
            title="Copy SHA-256 to clipboard"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Hash</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Grid of Extracted PE Attributes */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Machine & Architecture */}
        <div className="p-5 rounded-xl bg-[#071120]/80 border border-white/[0.08] backdrop-blur-md">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mb-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>Target Architecture</span>
          </div>
          <div className="text-base font-bold text-white font-display">
            {inspection.architecture.split("(")[0].trim()}
          </div>
          <div className="text-xs font-mono text-cyan-300 mt-1">
            Machine ID: {inspection.machineHex}
          </div>
        </div>

        {/* Subsystem */}
        <div className="p-5 rounded-xl bg-[#071120]/80 border border-white/[0.08] backdrop-blur-md">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mb-2">
            <Terminal className="w-4 h-4 text-purple-400" />
            <span>Windows Subsystem</span>
          </div>
          <div className="text-base font-bold text-white font-display truncate">
            {inspection.subsystem}
          </div>
          <div className="text-xs font-mono text-purple-300 mt-1">
            Magic: {inspection.optHeaderMagic}
          </div>
        </div>

        {/* Sections Count */}
        <div className="p-5 rounded-xl bg-[#071120]/80 border border-white/[0.08] backdrop-blur-md">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mb-2">
            <Layers className="w-4 h-4 text-sky-400" />
            <span>PE Section Count</span>
          </div>
          <div className="text-base font-bold text-white font-display">
            {inspection.numberOfSections} Sections
          </div>
          <div className="text-xs font-mono text-sky-300 mt-1">
            DOS Header: Valid (&quot;MZ&quot;)
          </div>
        </div>

        {/* Compilation Timestamp */}
        <div className="p-5 rounded-xl bg-[#071120]/80 border border-white/[0.08] backdrop-blur-md">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mb-2">
            <Clock className="w-4 h-4 text-emerald-400" />
            <span>Compilation Timestamp</span>
          </div>
          <div className="text-sm font-bold text-white font-display truncate">
            {inspection.compilationTimestamp || "Not Available"}
          </div>
          <div className="text-xs font-mono text-emerald-300 mt-1">
            PE Header TimeDateStamp
          </div>
        </div>

      </div>

      {/* Shannon Entropy Meter Card */}
      <div className="p-5 sm:p-6 rounded-2xl bg-[#071120]/90 border border-white/[0.08] backdrop-blur-xl">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2.5">
            <BarChart3 className="w-5 h-5 text-cyan-400" />
            <div>
              <h3 className="text-sm font-bold text-white font-display">
                Binary Shannon Entropy
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Mathematical measure of byte randomness (0.0 to 8.0)
              </p>
            </div>
          </div>

          <div className={`px-3 py-1 rounded-full text-xs font-mono border ${entropyMeta.color}`}>
            {entropyMeta.label}
          </div>
        </div>

        {/* Meter Bar */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400">Entropy Score:</span>
            <span className="text-cyan-300 font-bold text-sm">
              {inspection.entropy.toFixed(3)} / 8.000
            </span>
          </div>
          <div className="h-3 w-full rounded-full bg-slate-900 border border-white/10 overflow-hidden relative">
            <div
              className={`h-full ${entropyMeta.barColor} transition-all duration-500 rounded-full shadow-[0_0_10px_currentColor]`}
              style={{ width: `${Math.min(100, (inspection.entropy / 8.0) * 100)}%` }}
            />
          </div>
          <div className="flex justify-between text-[10px] xs:text-[11px] font-mono text-slate-400">
            <span>0.0</span>
            <span className="hidden xs:inline">4.0</span>
            <span>6.0 (Normal)</span>
            <span>7.2+ (Packed)</span>
            <span>8.0</span>
          </div>
        </div>
      </div>

      {/* Section Table Card */}
      {inspection.sections.length > 0 && (
        <div className="p-5 sm:p-6 rounded-2xl bg-[#071120]/90 border border-white/[0.08] backdrop-blur-xl">
          <div className="flex items-center gap-2.5 mb-4">
            <Layers className="w-5 h-5 text-purple-400" />
            <h3 className="text-sm font-bold text-white font-display">
              Extracted PE Section Headers ({inspection.sections.length})
            </h3>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2.5">
            {inspection.sections.map((sec, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-[#050C18] border border-white/[0.06] flex flex-col justify-between"
              >
                <div className="font-mono text-xs font-bold text-cyan-300 truncate">
                  {sec.name}
                </div>
                <div className="mt-1 flex flex-col gap-0.5 text-[11px] font-mono text-slate-400">
                  <span>Virtual Size: {(sec.virtualSize / 1024).toFixed(1)} KB</span>
                  <span>Raw Data: {(sec.sizeOfRawData / 1024).toFixed(1)} KB</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

    </div>
  );
}

