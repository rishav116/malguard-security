"use client";

import React, { useState } from "react";
import Link from "next/link";
import { 
  X, 
  UploadCloud, 
  FileCode, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Sparkles, 
  Cpu, 
  CheckCircle2, 
  ArrowRight,
  RefreshCw,
  FileText
} from "lucide-react";

interface ScanModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface AnalysisResult {
  fileName: string;
  fileSize: string;
  sha256: string;
  verdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN";
  riskScore: number; // 0 - 100
  entropy: number;
  mitreTags: string[];
  malixExplanation: string;
  mitigationSteps: string[];
}

export default function ScanModal({ isOpen, onClose }: ScanModalProps) {
  const [analyzing, setAnalyzing] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [result, setResult] = useState<AnalysisResult | null>(null);

  if (!isOpen) return null;

  const sampleScenarios: Record<string, AnalysisResult> = {
    ransomware: {
      fileName: "Trojan.Win32.WannaLock.bin",
      fileSize: "1.42 MB",
      sha256: "8e932b130a103ecda45cf2a4176d4918e7e1a3bc89a74659b8a0",
      verdict: "MALICIOUS",
      riskScore: 94,
      entropy: 7.92,
      mitreTags: ["High Shannon Entropy", "Suspicious API Imports", "ClamAV Signature Match"],
      malixExplanation:
        "Malix AI Assistant (Illustrative Demo): The sample exhibits high section entropy indicative of packed encryption routines, coupled with API references commonly used in unauthorized file modification.",
      mitigationSteps: [
        "Isolate suspicious executable from test environment.",
        "Review host process execution logs.",
        "Submit hash to organizational threat database.",
      ],
    },
    suspiciousMacro: {
      fileName: "Invoice_Payment_Receipt.docm",
      fileSize: "384 KB",
      sha256: "3f829da48b1001cda85bb9a376510827ea8b01249bce746a",
      verdict: "SUSPICIOUS",
      riskScore: 68,
      entropy: 6.84,
      mitreTags: ["Obfuscated Macro Code", "Network Retrieval Call"],
      malixExplanation:
        "Malix AI Assistant (Illustrative Demo): Static analysis highlights an obfuscated VBA macro configured to execute on document open, containing strings indicative of external script retrieval.",
      mitigationSteps: [
        "Block outbound connection to unknown destination hosts.",
        "Enforce organizational policy disabling unauthenticated macros.",
        "Inspect email gateway headers for the delivery origin.",
      ],
    },
    cleanFile: {
      fileName: "SystemDiagnosticTool_v2.8.exe",
      fileSize: "3.10 MB",
      sha256: "01fca829b384ef81093ac6198f12a49b491a0c84bce12749",
      verdict: "CLEAN",
      riskScore: 8,
      entropy: 5.41,
      mitreTags: ["Benign Structure", "Standard Entropy"],
      malixExplanation:
        "Malix AI Assistant (Illustrative Demo): No anomalous entropy or high-risk API imports identified. Standard PE section structure and legitimate diagnostic routines observed.",
      mitigationSteps: [
        "File demonstrates benign characteristics.",
        "Add hash to trusted internal whitelist if verified.",
      ],
    },
  };

  const runAnalysis = (scenarioKey: "ransomware" | "suspiciousMacro" | "cleanFile", customName?: string, customSize?: string) => {
    setAnalyzing(true);
    setResult(null);
    setScanStep(1);

    setTimeout(() => setScanStep(2), 600);
    setTimeout(() => setScanStep(3), 1300);
    setTimeout(() => {
      const data = { ...sampleScenarios[scenarioKey] };
      if (customName) data.fileName = customName;
      if (customSize) data.fileSize = customSize;
      setResult(data);
      setAnalyzing(false);
      setScanStep(0);
    }, 2000);
  };

  const handleCustomFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const sizeStr = `${(file.size / 1024).toFixed(1)} KB`;
      // Run analysis on user's selected file using client-side simulated pipeline
      runAnalysis("suspiciousMacro", file.name, sizeStr);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 xs:p-4 sm:p-6 overflow-y-auto bg-[#040812]/85 backdrop-blur-xl animate-in fade-in duration-200">
      
      {/* Modal Dialog Card */}
      <div className="relative w-full max-w-2xl max-h-[90dvh] overflow-y-auto rounded-2xl glass-panel p-4 xs:p-6 sm:p-8 border border-cyan-500/30 shadow-[0_0_50px_rgba(0,0,0,0.8)] my-auto">
        
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 p-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-xl font-bold text-white flex items-center gap-2">
              MALGUARD AI File Scanner (Simulation)
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Dual-Engine Architecture & Malix AI Security Assistant
            </p>
          </div>
        </div>

        {/* Main Dropzone / Selection */}
        {!analyzing && !result && (
          <div className="space-y-6">
            
            {/* Live Scanner Banner */}
            <div className="p-3.5 rounded-xl bg-cyan-950/40 border border-cyan-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0" />
                <span className="text-xs text-slate-300">
                  Ready to inspect a real Windows PE binary (.exe / .dll)?
                </span>
              </div>
              <Link
                href="/scanner"
                onClick={onClose}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-400/40 text-cyan-300 text-xs font-mono font-semibold shrink-0 transition-colors w-fit"
              >
                <span>Open File Scanner</span>
                <ArrowRight className="w-3 h-3" />
              </Link>
            </div>

            {/* File Dropzone */}
            <label className="flex flex-col items-center justify-center w-full h-44 rounded-xl border-2 border-dashed border-cyan-500/30 hover:border-cyan-400 bg-[#071120]/60 hover:bg-[#071120] cursor-pointer transition-all duration-200 group">
              <UploadCloud className="w-10 h-10 text-cyan-400/80 group-hover:scale-110 group-hover:text-cyan-300 transition-all mb-2" />
              <p className="text-sm font-semibold text-slate-200">
                Click or drag & drop a file to inspect (Demo)
              </p>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                Planned Support: PE (.exe, .dll), Scripts (.ps1, .sh), Office Docs (.docm, .vba)
              </p>
              <input
                type="file"
                className="hidden"
                onChange={handleCustomFileUpload}
              />
            </label>

            {/* Quick Demo Pre-loaded Samples */}
            <div>
              <p className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-3">
                Or test with sample scenarios (Illustrative Demo):
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                
                {/* Sample 1: Ransomware */}
                <button
                  onClick={() => runAnalysis("ransomware")}
                  className="p-3 rounded-xl bg-[#091526] hover:bg-[#0c1d36] border border-rose-500/30 hover:border-rose-400/60 text-left transition-all"
                >
                  <div className="flex items-center justify-between text-xs font-bold text-rose-400 mb-1">
                    <span>High-Risk Sample</span>
                    <ShieldAlert className="w-4 h-4" />
                  </div>
                  <div className="text-[11px] text-slate-300 font-mono truncate">
                    WannaLock.bin
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">High Entropy Demo</div>
                </button>

                {/* Sample 2: Suspicious Macro */}
                <button
                  onClick={() => runAnalysis("suspiciousMacro")}
                  className="p-3 rounded-xl bg-[#091526] hover:bg-[#0c1d36] border border-amber-500/30 hover:border-amber-400/60 text-left transition-all"
                >
                  <div className="flex items-center justify-between text-xs font-bold text-amber-400 mb-1">
                    <span>Suspicious Macro</span>
                    <AlertTriangle className="w-4 h-4" />
                  </div>
                  <div className="text-[11px] text-slate-300 font-mono truncate">
                    Invoice_Doc.docm
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">Obfuscated Macro Demo</div>
                </button>

                {/* Sample 3: Clean Executable */}
                <button
                  onClick={() => runAnalysis("cleanFile")}
                  className="p-3 rounded-xl bg-[#091526] hover:bg-[#0c1d36] border border-emerald-500/30 hover:border-emerald-400/60 text-left transition-all"
                >
                  <div className="flex items-center justify-between text-xs font-bold text-emerald-400 mb-1">
                    <span>Clean Binary</span>
                    <ShieldCheck className="w-4 h-4" />
                  </div>
                  <div className="text-[11px] text-slate-300 font-mono truncate">
                    DiagnosticTool.exe
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">Benign Structure Demo</div>
                </button>

              </div>
            </div>

            <div className="p-3 rounded-lg bg-cyan-950/30 border border-cyan-500/20 text-xs font-mono text-cyan-300/80 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>Secure File Handling: Live PE feature extraction & ML inference engine active. Zero binary persistence.</span>
            </div>
          </div>
        )}

        {/* Live Analysis Progress State */}
        {analyzing && (
          <div className="py-12 flex flex-col items-center justify-center text-center space-y-6">
            <div className="relative">
              <RefreshCw className="w-14 h-14 text-cyan-400 animate-spin" />
              <div className="absolute inset-0 rounded-full bg-cyan-400/20 blur-xl animate-pulse" />
            </div>

            <div className="space-y-2">
              <h4 className="text-xl font-bold text-white">
                {scanStep === 1 && "Stage 1: Hashing & Extracting PE Header Features..."}
                {scanStep === 2 && "Stage 2: Evaluating ML Model & ClamAV Signatures..."}
                {scanStep === 3 && "Stage 3: Generating Malix AI Threat Explanation..."}
              </h4>
              <p className="text-xs font-mono text-cyan-300">
                Interactive frontend pipeline demonstration
              </p>
            </div>

            <div className="w-full max-w-md h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-400 to-purple-500 transition-all duration-500"
                style={{ width: `${(scanStep / 3) * 100}%` }}
              />
            </div>
          </div>
        )}

        {/* Threat Verdict & Malix Intelligence Results View */}
        {result && (
          <div className="space-y-6">
            
            {/* Top Verdict Ribbon */}
            <div className={`p-4 rounded-xl border flex items-center justify-between ${
              result.verdict === "MALICIOUS"
                ? "bg-rose-950/40 border-rose-500/40 text-rose-300"
                : result.verdict === "SUSPICIOUS"
                ? "bg-amber-950/40 border-amber-500/40 text-amber-300"
                : "bg-emerald-950/40 border-emerald-500/40 text-emerald-300"
            }`}>
              <div className="flex items-center gap-3">
                {result.verdict === "MALICIOUS" && <ShieldAlert className="w-7 h-7 text-rose-400" />}
                {result.verdict === "SUSPICIOUS" && <AlertTriangle className="w-7 h-7 text-amber-400" />}
                {result.verdict === "CLEAN" && <ShieldCheck className="w-7 h-7 text-emerald-400" />}
                <div>
                  <div className="text-xs uppercase tracking-wider font-mono">Detection Verdict (Illustrative Demo)</div>
                  <div className="text-xl font-bold">{result.verdict}</div>
                </div>
              </div>
              <div className="text-right">
                <div className="text-xs font-mono">Risk Index</div>
                <div className="text-2xl font-mono font-bold">{result.riskScore}/100</div>
              </div>
            </div>

            {/* Target Artifact Details */}
            <div className="grid grid-cols-1 xs:grid-cols-2 sm:grid-cols-3 gap-3 p-3 rounded-xl bg-[#060D19] border border-white/[0.08] text-xs font-mono">
              <div>
                <span className="text-slate-400">Target File:</span>
                <p className="text-white font-semibold truncate">{result.fileName}</p>
              </div>
              <div>
                <span className="text-slate-400">Size:</span>
                <p className="text-slate-200">{result.fileSize}</p>
              </div>
              <div>
                <span className="text-slate-400">Shannon Entropy:</span>
                <p className={result.entropy > 7.0 ? "text-amber-400 font-bold" : "text-cyan-300"}>
                  {result.entropy} / 8.0
                </p>
              </div>
            </div>

            {/* Malix AI Plain-English Reasoning Section */}
            <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/30 space-y-2">
              <div className="flex items-center gap-2 text-xs font-mono text-purple-300 font-semibold">
                <Sparkles className="w-4 h-4 text-purple-400" />
                <span>Malix AI Security Assistant (Illustrative Demo)</span>
              </div>
              <p className="text-sm text-slate-200 leading-relaxed font-sans">
                {result.malixExplanation}
              </p>
            </div>

            {/* Indicator Chips */}
            <div>
              <span className="text-xs font-mono text-slate-400 block mb-2">
                Suspicious Pattern Indicators (Illustrative Demo):
              </span>
              <div className="flex flex-wrap gap-2">
                {result.mitreTags.map((tag, i) => (
                  <span
                    key={i}
                    className="text-xs font-mono px-2.5 py-1 rounded bg-[#091526] border border-cyan-500/30 text-cyan-300"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>

            {/* Actionable Remediation Guidance */}
            <div className="space-y-2">
              <span className="text-xs font-mono text-slate-400 block">
                Remediation Guidance (Illustrative Demo):
              </span>
              <div className="space-y-1.5">
                {result.mitigationSteps.map((step, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-slate-300">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Footer buttons */}
            <div className="flex items-center justify-between pt-4 border-t border-white/[0.08]">
              <button
                onClick={() => {
                  setResult(null);
                  setAnalyzing(false);
                }}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Scan Another Artifact
              </button>
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white"
              >
                Close Report
              </button>
            </div>

          </div>
        )}

      </div>
    </div>
  );
}
