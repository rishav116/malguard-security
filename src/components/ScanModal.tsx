"use client";

import React, { useState, useCallback } from "react";
import Link from "next/link";
import { 
  X, 
  UploadCloud, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Cpu, 
  CheckCircle2, 
  ArrowRight,
  RefreshCw,
  Copy,
  Check,
  HelpCircle,
  FileCode2,
  Lock,
  Binary
} from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { 
  inspectPEBinary, 
  generateTestPE,
  PEInspectionResult 
} from "@/lib/scanner/peParser";
import { 
  submitBinaryForScan, 
  FastAPIScanResponse 
} from "@/lib/api/scannerService";

interface ScanModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function ScanModal({ isOpen, onClose }: ScanModalProps) {
  const { user, session } = useAuth();

  const [analyzing, setAnalyzing] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [result, setResult] = useState<FastAPIScanResponse | null>(null);
  const [inspectionResult, setInspectionResult] = useState<PEInspectionResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [authError, setAuthError] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  const resetState = useCallback(() => {
    setAnalyzing(false);
    setScanStep(0);
    setResult(null);
    setInspectionResult(null);
    setErrorMessage(null);
    setAuthError(false);
    setCopiedHash(false);
  }, []);

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  /**
   * Dispatches a real binary File through genuine PE inspection and the FastAPI detection engine.
   */
  const handleScanFile = async (file: File) => {
    resetState();
    setAnalyzing(true);
    setScanStep(1);

    try {
      // Stage 1: Client-side PE header verification & cryptographic hashing
      await new Promise((r) => setTimeout(r, 200));
      const pe = await inspectPEBinary(file);
      setInspectionResult(pe);

      // Stage 2: Digest confirmation & engine dispatch
      setScanStep(2);
      await new Promise((r) => setTimeout(r, 250));

      // Stage 3: FastAPI dual-engine ML and ClamAV analysis
      setScanStep(3);
      const token = session?.access_token || undefined;
      const res = await submitBinaryForScan(
        file,
        {
          sha256: pe.sha256,
          architecture: pe.architecture,
          isDLL: pe.isDLL,
        },
        token
      );

      if (res.success && res.data) {
        setResult(res.data);
      } else {
        const err = res.error || "Detection engine failed to return a scan verdict.";
        setErrorMessage(err);
        if (err.toLowerCase().includes("authentication") || err.toLowerCase().includes("sign in")) {
          setAuthError(true);
        }
      }
    } catch (err: unknown) {
      const msg = (err as Error)?.message || "PE validation failed: Corrupted or invalid binary.";
      setErrorMessage(msg);
    } finally {
      setAnalyzing(false);
      setScanStep(0);
    }
  };

  const handleCustomFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleScanFile(e.target.files[0]);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 xs:p-4 sm:p-6 overflow-y-auto bg-[#040812]/85 backdrop-blur-xl animate-in fade-in duration-200">
      
      {/* Modal Dialog Card */}
      <div className="relative w-full max-w-2xl max-h-[92dvh] overflow-y-auto rounded-2xl glass-panel p-4 xs:p-6 sm:p-8 border border-cyan-500/30 shadow-[0_0_50px_rgba(0,0,0,0.8)] my-auto">
        
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 p-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
          aria-label="Close scanner modal"
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
              MALGUARD AI File Scanner
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Dual-Engine Architecture: ClamAV Signatures & Random Forest Classifier
            </p>
          </div>
        </div>

        {/* Idle Selection View */}
        {!analyzing && !result && !errorMessage && (
          <div className="space-y-6">
            
            {/* Live Scanner Banner */}
            <div className="p-3.5 rounded-xl bg-cyan-950/40 border border-cyan-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0" />
                <span className="text-xs text-slate-300">
                  {user ? (
                    <>Authenticated as <span className="text-cyan-300 font-semibold">{user.email}</span>. Scans persist to Threat Reports.</>
                  ) : (
                    <>Sign in to automatically save scan history and query Malix AI Assistant.</>
                  )}
                </span>
              </div>
              {user ? (
                <Link
                  href="/reports"
                  onClick={onClose}
                  className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-400/40 text-cyan-300 text-xs font-mono font-semibold shrink-0 transition-colors w-fit"
                >
                  <span>Threat Reports</span>
                  <ArrowRight className="w-3 h-3" />
                </Link>
              ) : (
                <Link
                  href="/login"
                  onClick={onClose}
                  className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-400/40 text-cyan-300 text-xs font-mono font-semibold shrink-0 transition-colors w-fit"
                >
                  <Lock className="w-3 h-3" />
                  <span>Sign In</span>
                </Link>
              )}
            </div>

            {/* File Dropzone */}
            <label className="flex flex-col items-center justify-center w-full h-44 rounded-xl border-2 border-dashed border-cyan-500/30 hover:border-cyan-400 bg-[#071120]/60 hover:bg-[#071120] cursor-pointer transition-all duration-200 group">
              <UploadCloud className="w-10 h-10 text-cyan-400/80 group-hover:scale-110 group-hover:text-cyan-300 transition-all mb-2" />
              <p className="text-sm font-semibold text-slate-200">
                Click or drag & drop a Windows PE binary to scan
              </p>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                Supported Formats: Windows Executables (.exe) & Dynamic Link Libraries (.dll, max 10 MB)
              </p>
              <input
                type="file"
                accept=".exe,.dll"
                className="hidden"
                onChange={handleCustomFileUpload}
              />
            </label>

            {/* Authentic PE Test Samples */}
            <div>
              <p className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-3">
                Or test with authentic PE binaries:
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                
                {/* Sample 1: Benign Diagnostic PE */}
                <button
                  type="button"
                  onClick={() => handleScanFile(generateTestPE({ name: "sample_diagnostic_tool.exe" }))}
                  className="p-3.5 rounded-xl bg-[#091526] hover:bg-[#0c1d36] border border-cyan-500/30 hover:border-cyan-400/60 text-left transition-all group cursor-pointer"
                >
                  <div className="flex items-center justify-between text-xs font-bold text-cyan-400 mb-1">
                    <span>Benign Diagnostic PE</span>
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  </div>
                  <div className="text-[11px] text-slate-200 font-mono truncate">
                    sample_diagnostic_tool.exe
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1 font-mono">
                    Valid PE32 header • Normal entropy • Clean imports
                  </div>
                </button>

                {/* Sample 2: EICAR Antivirus Test PE */}
                <button
                  type="button"
                  onClick={() => handleScanFile(generateTestPE({ name: "sample_eicar_test.exe", includeEicar: true }))}
                  className="p-3.5 rounded-xl bg-[#091526] hover:bg-[#0c1d36] border border-rose-500/30 hover:border-rose-400/60 text-left transition-all group cursor-pointer"
                >
                  <div className="flex items-center justify-between text-xs font-bold text-rose-400 mb-1">
                    <span>EICAR Antivirus Test PE</span>
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                  </div>
                  <div className="text-[11px] text-slate-200 font-mono truncate">
                    sample_eicar_test.exe
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1 font-mono">
                    Standard Antivirus Signature verification
                  </div>
                </button>

              </div>
            </div>

            <div className="p-3 rounded-lg bg-cyan-950/30 border border-cyan-500/20 text-xs font-mono text-cyan-300/80 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>Genuine Pipeline: Live PE parsing, ClamAV signature stream, and 69-feature Random Forest ML classification.</span>
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
              <h4 className="text-xl font-bold text-white font-display">
                {scanStep === 1 && "Stage 1: Validating PE Headers & Extracting Sections..."}
                {scanStep === 2 && "Stage 2: Computing SHA-256 Digest & Dispatching to Backend..."}
                {scanStep === 3 && "Stage 3: Running ClamAV Signatures & Random Forest ML Inference..."}
              </h4>
              <p className="text-xs font-mono text-cyan-300">
                Executing authenticated dual-engine security pipeline
              </p>
            </div>

            <div className="w-full max-w-md h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-400 via-purple-500 to-emerald-400 transition-all duration-300"
                style={{ width: `${Math.max(15, (scanStep / 3) * 100)}%` }}
              />
            </div>
          </div>
        )}

        {/* Error State */}
        {!analyzing && errorMessage && (
          <div className="p-6 rounded-2xl bg-rose-950/30 border border-rose-500/40 backdrop-blur-xl space-y-4">
            <div className="flex items-start gap-3.5">
              <div className="p-2.5 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/30 shrink-0">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div className="space-y-1">
                <h4 className="text-base font-bold text-white font-display">
                  {authError ? "Authentication Required" : "Binary Scan Unsuccessful"}
                </h4>
                <p className="text-xs text-rose-200/90 font-mono leading-relaxed">
                  {errorMessage}
                </p>
              </div>
            </div>

            <div className="pt-2 flex flex-wrap gap-3">
              {authError && (
                <Link
                  href="/login"
                  onClick={onClose}
                  className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-bold text-xs flex items-center gap-1.5 hover:brightness-110 transition-all"
                >
                  <Lock className="w-3.5 h-3.5" />
                  <span>Log In to Scan</span>
                </Link>
              )}
              <button
                type="button"
                onClick={resetState}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-mono text-xs flex items-center gap-1.5 transition-all cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Try Another Binary</span>
              </button>
            </div>
          </div>
        )}

        {/* Genuine Detection Results View */}
        {!analyzing && result && (
          <div className="space-y-6 animate-in fade-in duration-300">
            
            {/* Top Verdict Ribbon */}
            <div className={`p-4 rounded-xl border flex items-center justify-between ${
              result.verdict === "MALICIOUS"
                ? "bg-rose-950/50 border-rose-500/50 text-rose-300 shadow-[0_0_20px_rgba(244,63,94,0.25)]"
                : result.verdict === "SUSPICIOUS"
                ? "bg-amber-950/50 border-amber-500/50 text-amber-300 shadow-[0_0_20px_rgba(245,158,11,0.2)]"
                : result.verdict === "NO_THREAT_DETECTED"
                ? "bg-emerald-950/50 border-emerald-500/50 text-emerald-300 shadow-[0_0_20px_rgba(16,185,129,0.2)]"
                : "bg-cyan-950/50 border-cyan-500/50 text-cyan-300 shadow-[0_0_20px_rgba(34,211,238,0.2)]"
            }`}>
              <div className="flex items-center gap-3">
                {result.verdict === "MALICIOUS" && <ShieldAlert className="w-7 h-7 text-rose-400 shrink-0" />}
                {result.verdict === "SUSPICIOUS" && <AlertTriangle className="w-7 h-7 text-amber-400 shrink-0" />}
                {result.verdict === "NO_THREAT_DETECTED" && <ShieldCheck className="w-7 h-7 text-emerald-400 shrink-0" />}
                {result.verdict === "INCONCLUSIVE" && <HelpCircle className="w-7 h-7 text-cyan-400 shrink-0" />}
                <div>
                  <div className="text-[10px] uppercase tracking-wider font-mono text-slate-400">
                    FastAPI Engine Verdict
                  </div>
                  <div className="text-xl font-bold font-display tracking-tight">
                    {result.verdict.replace(/_/g, " ")}
                  </div>
                </div>
              </div>
              <div className="text-right font-mono">
                {result.ml_inference.confidence_score != null ? (
                  <>
                    <div className="text-[10px] text-slate-400">ML Threat Prob</div>
                    <div className="text-lg font-bold text-white">
                      {(result.ml_inference.confidence_score * 100).toFixed(1)}%
                    </div>
                  </>
                ) : (
                  <>
                    <div className="text-[10px] text-slate-400">ML Prediction</div>
                    <div className="text-sm font-bold text-white uppercase">
                      {result.ml_inference.prediction || "N/A"}
                    </div>
                  </>
                )}
              </div>
            </div>

            {/* Target Artifact Details */}
            <div className="grid grid-cols-1 xs:grid-cols-2 sm:grid-cols-3 gap-3 p-3.5 rounded-xl bg-[#060D19] border border-white/[0.08] text-xs font-mono">
              <div>
                <span className="text-slate-400">Target Binary:</span>
                <p className="text-white font-semibold truncate mt-0.5">{result.file_name}</p>
              </div>
              <div>
                <span className="text-slate-400">Size:</span>
                <p className="text-slate-200 mt-0.5">{result.formatted_size}</p>
              </div>
              <div>
                <span className="text-slate-400">Shannon Entropy:</span>
                <p className={`mt-0.5 font-semibold ${
                  result.pe_analysis.file_entropy > 7.0 ? "text-amber-400 font-bold" : "text-cyan-300"
                }`}>
                  {result.pe_analysis.file_entropy.toFixed(3)} / 8.0
                </p>
              </div>
            </div>

            {/* SHA-256 Digest Bar */}
            <div className="p-3 rounded-xl bg-[#060D19] border border-white/[0.08] flex items-center justify-between gap-2 text-xs font-mono">
              <div className="flex items-center gap-2 min-w-0">
                <span className="text-slate-400 shrink-0">SHA-256:</span>
                <span className="text-cyan-300 truncate select-all">{result.hashes.sha256}</span>
              </div>
              <button
                type="button"
                onClick={() => handleCopyHash(result.hashes.sha256)}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors shrink-0 cursor-pointer"
                title="Copy SHA-256 Hash"
              >
                {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>

            {/* Dual Engine Telemetry Row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              
              {/* ClamAV Card */}
              <div className="p-3.5 rounded-xl bg-[#060D19] border border-white/[0.08] space-y-1">
                <div className="text-[11px] font-mono text-slate-400">ClamAV Signature Engine</div>
                <div className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                  <span className={`w-2 h-2 rounded-full ${
                    result.clamav.matched
                      ? "bg-rose-400"
                      : result.clamav.status === "clean"
                      ? "bg-emerald-400"
                      : "bg-amber-400"
                  }`} />
                  <span>Status: {result.clamav.status.toUpperCase()}</span>
                </div>
                {result.clamav.signature_name && (
                  <div className="text-xs font-mono text-rose-400 font-bold">
                    Match: {result.clamav.signature_name}
                  </div>
                )}
                <div className="text-[11px] font-mono text-slate-400">{result.clamav.message}</div>
              </div>

              {/* Random Forest Card */}
              <div className="p-3.5 rounded-xl bg-[#060D19] border border-white/[0.08] space-y-1">
                <div className="text-[11px] font-mono text-slate-400">Random Forest PE Classifier</div>
                <div className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                  <span className={`w-2 h-2 rounded-full ${
                    result.ml_inference.prediction === "malicious"
                      ? "bg-rose-400"
                      : result.ml_inference.prediction === "benign"
                      ? "bg-emerald-400"
                      : "bg-purple-400"
                  }`} />
                  <span>Prediction: {result.ml_inference.prediction?.toUpperCase() || "N/A"}</span>
                </div>
                <div className="text-[11px] font-mono text-slate-400">{result.ml_inference.message}</div>
              </div>

            </div>

            {/* Verdict Rationale */}
            <div className="p-4 rounded-xl bg-[#060D19] border border-white/[0.08] space-y-2">
              <div className="text-xs font-mono text-slate-300 font-semibold flex items-center gap-1.5">
                <FileCode2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>Verdict Rationale:</span>
              </div>
              <ul className="space-y-1.5">
                {result.verdict_reasons.map((reason, i) => (
                  <li key={i} className="text-xs font-mono text-slate-300 flex items-start gap-2">
                    <span className="text-cyan-400 mt-0.5">•</span>
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Suspicious Indicators (if detected) */}
            {result.pe_analysis.suspicious_indicators.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-xs font-mono text-slate-400 block">
                  PE Structural Indicators:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {result.pe_analysis.suspicious_indicators.map((ind, i) => (
                    <span
                      key={i}
                      className="text-xs font-mono px-2 py-0.5 rounded bg-rose-950/40 border border-rose-500/30 text-rose-300"
                    >
                      {ind}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Footer Actions */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-white/[0.08]">
              <button
                type="button"
                onClick={resetState}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Scan Another Binary</span>
              </button>
              
              <div className="flex items-center gap-2">
                <Link
                  href="/reports"
                  onClick={onClose}
                  className="px-3.5 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-400/40 text-cyan-300 text-xs font-mono font-semibold flex items-center gap-1.5 transition-colors"
                >
                  <span>Threat Reports</span>
                  <ArrowRight className="w-3 h-3" />
                </Link>
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition-colors cursor-pointer"
                >
                  Close
                </button>
              </div>
            </div>

          </div>
        )}

      </div>
    </div>
  );
}
