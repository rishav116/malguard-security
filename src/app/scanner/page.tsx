"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/context/AuthContext";
import Sidebar from "@/components/dashboard/Sidebar";
import DashboardHeader from "@/components/dashboard/DashboardHeader";
import FileDropZone from "@/components/scanner/FileDropZone";
import InspectionProgress, { ScanStage } from "@/components/scanner/InspectionProgress";
import FileInspectionCard from "@/components/scanner/FileInspectionCard";
import EngineStatusBanner from "@/components/scanner/EngineStatusBanner";
import FadeInSection from "@/components/FadeInSection";
import { 
  inspectPEBinary, 
  PEInspectionResult 
} from "@/lib/scanner/peParser";
import { 
  checkDetectionEngineHealth, 
  submitBinaryForScan,
  DetectionEngineStatus,
  FastAPIScanResponse
} from "@/lib/api/scannerService";
import { 
  Shield, 
  Binary, 
  Hash, 
  Cpu, 
  AlertTriangle, 
  ArrowLeft, 
  FileCode2, 
  Sparkles,
  CheckCircle2,
  Lock
} from "lucide-react";

export default function ScannerPage() {
  const router = useRouter();
  const { user, session, loading } = useAuth();

  // Layout state
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  // Detection Engine Health State
  const [engineStatus, setEngineStatus] = useState<DetectionEngineStatus>({
    connected: false,
    endpoint: process.env.NEXT_PUBLIC_FASTAPI_URL || "http://127.0.0.1:8000",
    message: "Probing detection engine status...",
    lastChecked: "Initial check",
  });

  // Scanner States: "idle" | "inspecting" | "completed" | "error"
  const [scannerState, setScannerState] = useState<"idle" | "inspecting" | "completed" | "error">("idle");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [inspectionResult, setInspectionResult] = useState<PEInspectionResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [currentStageIdx, setCurrentStageIdx] = useState(0);

  // Cloud Scan States
  const [isScanningCloud, setIsScanningCloud] = useState(false);
  const [cloudScanResult, setCloudScanResult] = useState<FastAPIScanResponse | null>(null);
  const [cloudScanError, setCloudScanError] = useState<string | null>(null);

  // Inspection Stages definition
  const [stages, setStages] = useState<ScanStage[]>([
    {
      id: "ingestion",
      name: "File Ingestion",
      description: "Size & format validation",
      icon: FileCode2,
      status: "pending",
    },
    {
      id: "pe_headers",
      name: "PE Header Parser",
      description: "DOS magic & COFF headers",
      icon: Binary,
      status: "pending",
    },
    {
      id: "crypto_hash",
      name: "SHA-256 Digest",
      description: "Web Crypto verification",
      icon: Hash,
      status: "pending",
    },
    {
      id: "backend_dispatch",
      name: "ML Inference",
      description: "FastAPI classification",
      icon: Cpu,
      status: "pending",
    },
  ]);

  // Route protection
  useEffect(() => {
    if (!loading && !user) {
      router.push("/login");
    }
  }, [user, loading, router]);

  // Resilient engine health polling:
  // - Poll every 3.5 seconds when disconnected or warming up (auto-connects when backend goes online)
  // - Poll every 30 seconds when connected (maintains fresh live telemetry)
  useEffect(() => {
    let mounted = true;

    const pollHealth = async (force = false) => {
      try {
        const latest = await checkDetectionEngineHealth(force);
        if (mounted) {
          setEngineStatus(latest);
        }
      } catch {
        // Handled gracefully in checkDetectionEngineHealth
      }
    };

    pollHealth(true);

    const intervalMs = (!engineStatus.connected || engineStatus.isWarmingUp) ? 3500 : 30000;
    const intervalId = setInterval(() => pollHealth(false), intervalMs);

    return () => {
      mounted = false;
      clearInterval(intervalId);
    };
  }, [engineStatus.connected, engineStatus.isWarmingUp]);

  // Handler for file drop / selection
  const handleFileSelected = useCallback(async (file: File) => {
    setSelectedFile(file);
    setScannerState("inspecting");
    setErrorMessage(null);
    setInspectionResult(null);

    // Reset stages
    setStages([
      { id: "ingestion", name: "File Ingestion", description: "Verifying size & extension", icon: FileCode2, status: "processing" },
      { id: "pe_headers", name: "PE Header Parser", description: "Pending inspection", icon: Binary, status: "pending" },
      { id: "crypto_hash", name: "SHA-256 Digest", description: "Pending calculation", icon: Hash, status: "pending" },
      { id: "backend_dispatch", name: "ML Inference", description: "Engine check", icon: Cpu, status: "pending" },
    ]);
    setCurrentStageIdx(0);

    try {
      // Visual stage transitions
      await new Promise((r) => setTimeout(r, 200));
      
      // Stage 1 Done -> Stage 2: PE Header Parser
      setStages((prev) => [
        { ...prev[0], status: "completed", description: `${(file.size / 1024).toFixed(1)} KB validated` },
        { ...prev[1], status: "processing", description: "Parsing DOS & COFF structures" },
        prev[2],
        prev[3],
      ]);
      setCurrentStageIdx(1);
      await new Promise((r) => setTimeout(r, 200));

      // Stage 2 Done -> Stage 3: SHA-256 Calculation
      setStages((prev) => [
        prev[0],
        { ...prev[1], status: "completed", description: "PE/COFF headers extracted" },
        { ...prev[2], status: "processing", description: "Computing Web Crypto digest" },
        prev[3],
      ]);
      setCurrentStageIdx(2);

      // Perform real client-side PE inspection & SHA-256
      const result = await inspectPEBinary(file);
      await new Promise((r) => setTimeout(r, 200));

      // Stage 3 Done -> Stage 4: Engine Status Check with retry resilience
      let latestEngine = await checkDetectionEngineHealth(false);
      if (!latestEngine.connected) {
        await new Promise((r) => setTimeout(r, 400));
        latestEngine = await checkDetectionEngineHealth(true);
      }
      setEngineStatus(latestEngine);

      setStages((prev) => [
        prev[0],
        prev[1],
        { ...prev[2], status: "completed", description: "SHA-256 fingerprint verified" },
        { 
          ...prev[3], 
          status: latestEngine.connected ? "completed" : "error", 
          description: latestEngine.connected ? "Ready for inference" : "Engine Not Connected" 
        },
      ]);
      setCurrentStageIdx(3);

      setInspectionResult(result);
      setScannerState("completed");
    } catch (err: unknown) {
      const errorMsg = (err as Error)?.message || "An unexpected error occurred during binary parsing.";
      setErrorMessage(errorMsg);
      setScannerState("error");

      setStages((prev) =>
        prev.map((s, idx) =>
          idx === currentStageIdx
            ? { ...s, status: "error", description: "Inspection failed" }
            : s
        )
      );
    }
  }, [currentStageIdx]);

  const handleRunCloudScan = async () => {
    if (!selectedFile || !inspectionResult) return;
    setIsScanningCloud(true);
    setCloudScanError(null);

    const token = session?.access_token || "demo-token";

    const res = await submitBinaryForScan(
      selectedFile,
      {
        sha256: inspectionResult.sha256,
        architecture: inspectionResult.architecture,
        isDLL: inspectionResult.isDLL,
      },
      token
    );

    setIsScanningCloud(false);
    if (res.success && res.data) {
      setCloudScanResult(res.data);
    } else {
      setCloudScanError(res.error || "Failed to analyze binary with FastAPI engine.");
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    setInspectionResult(null);
    setErrorMessage(null);
    setCloudScanResult(null);
    setCloudScanError(null);
    setScannerState("idle");
    setCurrentStageIdx(0);
    setStages((prev) => prev.map((s) => ({ ...s, status: "pending" })));
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#040812] flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-600/20 border border-cyan-400/40 text-cyan-400 flex items-center justify-center animate-pulse">
            <Shield className="w-6 h-6" />
          </div>
          <span className="text-xs font-mono text-cyan-300">
            Validating Security Session...
          </span>
        </div>
      </div>
    );
  }

  if (!user) {
    return null; // Redirects to /login
  }

  return (
    <div className="min-h-screen bg-[#040812] text-slate-100 flex relative overflow-x-hidden">
      
      {/* Background Cyber Glow */}
      <div className="fixed top-1/4 left-1/3 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[600px] bg-gradient-to-tr from-cyan-500/10 via-purple-600/10 to-transparent blur-[160px] pointer-events-none -z-10" />
      <div className="fixed inset-0 cyber-grid opacity-15 pointer-events-none -z-10" />

      {/* Reusable Sidebar */}
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        mobileOpen={mobileSidebarOpen}
        onCloseMobile={() => setMobileSidebarOpen(false)}
        onOpenQuickScan={handleReset}
      />

      {/* Main Content Area */}
      <div
        className={`flex-1 flex flex-col min-w-0 transition-all duration-300 ${
          sidebarCollapsed ? "lg:ml-20" : "lg:ml-64"
        }`}
      >
        
        {/* Dashboard Header */}
        <DashboardHeader
          onToggleMobileSidebar={() => setMobileSidebarOpen(true)}
          onOpenQuickScan={handleReset}
        />

        <main className="flex-1 p-3 xs:p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto space-y-6">
          
          {/* Breadcrumbs & Header */}
          <FadeInSection direction="down" delay={0.05} distance={16}>
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-2">
              <div>
                <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mb-1.5">
                  <Link href="/dashboard" className="hover:text-cyan-400 transition-colors flex items-center gap-1">
                    <ArrowLeft className="w-3.5 h-3.5" />
                    <span>Dashboard</span>
                  </Link>
                  <span>/</span>
                  <span className="text-cyan-300">File Scanner</span>
                </div>
                <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight font-display flex items-center gap-2.5">
                  <span>Static Binary Inspector</span>
                  <span className="text-xs px-2 py-0.5 rounded font-mono font-bold bg-cyan-950/80 border border-cyan-500/30 text-cyan-300">
                    PE32 / PE32+
                  </span>
                </h1>
                <p className="text-xs sm:text-sm text-slate-400 max-w-2xl mt-1">
                  Client-side Portable Executable verification and cryptographic hashing.
                  Inspect Windows PE binaries (.exe and .dll) up to 10 MB.
                </p>
              </div>

              {/* Engine Status Tag */}
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#071120] border border-white/10 text-xs font-mono">
                <span
                  className={`w-2 h-2 rounded-full ${
                    engineStatus.connected ? "bg-emerald-400 shadow-[0_0_8px_#34d399]" : "bg-amber-400 animate-pulse"
                  }`}
                />
                <span className="text-slate-400">Backend:</span>
                <span className={engineStatus.connected ? "text-emerald-300 font-semibold" : "text-amber-300 font-semibold"}>
                  {engineStatus.connected ? "Online" : "Not Connected"}
                </span>
              </div>
            </div>
          </FadeInSection>

          {/* Engine Status Banner */}
          <FadeInSection direction="up" delay={0.12} scale={0.98} distance={20}>
            <EngineStatusBanner
              engineStatus={engineStatus}
              onRefreshStatus={(newStatus) => setEngineStatus(newStatus)}
              hasFileSelected={Boolean(inspectionResult)}
              onRunCloudScan={handleRunCloudScan}
              isScanningCloud={isScanningCloud}
            />
          </FadeInSection>

          {/* Pipeline Stage Tracker (visible while inspecting or once completed) */}
          {scannerState !== "idle" && (
            <InspectionProgress
              stages={stages}
              currentStepIndex={currentStageIdx}
            />
          )}

          {/* Drop Zone (visible when idle) */}
          {scannerState === "idle" && (
            <FadeInSection direction="up" delay={0.18} scale={0.97} distance={28}>
              <FileDropZone
                onFileSelected={handleFileSelected}
                isProcessing={false}
              />
            </FadeInSection>
          )}

          {/* Inspection In-Progress State */}
          {scannerState === "inspecting" && (
            <div className="p-12 rounded-2xl bg-[#071120]/80 border border-cyan-500/30 text-center flex flex-col items-center justify-center">
              <div className="w-16 h-16 rounded-2xl bg-cyan-500/20 border border-cyan-400 text-cyan-300 flex items-center justify-center animate-pulse mb-4 shadow-[0_0_20px_rgba(34,211,238,0.4)]">
                <Binary className="w-8 h-8 animate-spin" />
              </div>
              <h3 className="text-lg font-bold text-white font-display mb-1">
                Parsing Binary Structure...
              </h3>
              <p className="text-xs font-mono text-cyan-300">
                Executing DOS header verification and Web Crypto SHA-256 calculation
              </p>
            </div>
          )}

          {/* Error State */}
          {scannerState === "error" && errorMessage && (
            <div className="p-6 sm:p-8 rounded-2xl bg-rose-950/30 border border-rose-500/30 backdrop-blur-xl space-y-4">
              <div className="flex items-start gap-3.5">
                <div className="p-3 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/30 shrink-0">
                  <AlertTriangle className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-base sm:text-lg font-bold text-white font-display">
                    Binary Validation Failed
                  </h3>
                  <p className="text-xs sm:text-sm text-rose-200/90 font-mono mt-1 leading-relaxed">
                    {errorMessage}
                  </p>
                </div>
              </div>

              <div className="pt-2 flex flex-wrap gap-3">
                <button
                  onClick={handleReset}
                  className="px-4 py-2 rounded-xl bg-gradient-to-r from-rose-500 to-amber-600 text-white font-bold text-xs flex items-center gap-2 cursor-pointer hover:brightness-110 transition-all shadow-md"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Try Another File</span>
                </button>
              </div>
            </div>
          )}

          {/* Completed State: Inspection Card */}
          {scannerState === "completed" && inspectionResult && (
            <div className="space-y-6">
              <FileInspectionCard
                inspection={inspectionResult}
                onReset={handleReset}
              />

              {/* Cloud Scan Error (if any) */}
              {cloudScanError && (
                <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs flex items-center justify-between gap-3 animate-in fade-in duration-200">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                    <span>{cloudScanError}</span>
                  </div>
                  <button
                    onClick={() => setCloudScanError(null)}
                    className="text-rose-400 hover:text-white underline font-mono text-xs cursor-pointer"
                  >
                    Dismiss
                  </button>
                </div>
              )}

              {/* Real Backend Scan Results Card */}
              {cloudScanResult && (
                <div className="p-4 xs:p-6 rounded-2xl bg-[#071120]/95 border border-cyan-500/40 backdrop-blur-xl space-y-5 animate-in fade-in slide-in-from-bottom-2 duration-300 shadow-[0_0_35px_rgba(34,211,238,0.15)]">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-white/[0.08]">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-400/30 text-cyan-400 flex items-center justify-center">
                        <Shield className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-lg font-bold text-white font-display flex items-center gap-2">
                          <span>Detection Engine Analysis</span>
                          <span className="text-xs px-2 py-0.5 rounded font-mono bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                            FastAPI Engine
                          </span>
                        </h3>
                        <div className="text-xs font-mono text-slate-400 mt-0.5">
                          Scan ID: {cloudScanResult.scan_id} • Owner: {cloudScanResult.owner_id}
                        </div>
                      </div>
                    </div>

                    {/* Verdict Badge */}
                    <div className={`px-4 py-2 rounded-xl border font-display font-bold text-sm tracking-tight flex items-center gap-2 ${
                      cloudScanResult.verdict === "MALICIOUS"
                        ? "bg-rose-950/60 border-rose-500/60 text-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.4)]"
                        : cloudScanResult.verdict === "SUSPICIOUS"
                        ? "bg-amber-950/60 border-amber-500/60 text-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.3)]"
                        : cloudScanResult.verdict === "NO_THREAT_DETECTED"
                        ? "bg-emerald-950/60 border-emerald-500/60 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.3)]"
                        : "bg-cyan-950/60 border-cyan-500/50 text-cyan-300 shadow-[0_0_15px_rgba(34,211,238,0.25)]"
                    }`}>
                      <span>Verdict: {cloudScanResult.verdict}</span>
                    </div>
                  </div>

                  {/* Reasons */}
                  <div className="space-y-2">
                    <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
                      Verdict Rationale:
                    </span>
                    <ul className="space-y-1.5">
                      {cloudScanResult.verdict_reasons.map((r, i) => (
                        <li key={i} className="text-xs font-mono text-slate-300 flex items-start gap-2">
                          <span className="text-cyan-400 mt-0.5">•</span>
                          <span>{r}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Engine telemetry row */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
                    <div className="p-3.5 rounded-xl bg-[#040914] border border-white/[0.06]">
                      <div className="text-xs font-mono text-slate-400 mb-1">ClamAV Signature Engine</div>
                      <div className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                        <span className={`w-2 h-2 rounded-full ${cloudScanResult.clamav.available ? "bg-emerald-400" : "bg-amber-400"}`} />
                        <span>Status: {cloudScanResult.clamav.status.toUpperCase()}</span>
                      </div>
                      <div className="text-xs font-mono text-slate-400 mt-1">{cloudScanResult.clamav.message}</div>
                    </div>

                    <div className="p-3.5 rounded-xl bg-[#040914] border border-white/[0.06]">
                      <div className="text-xs font-mono text-slate-400 mb-1">Random Forest ML Classifier</div>
                      <div className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                        <span className={`w-2 h-2 rounded-full ${cloudScanResult.ml_inference.available ? "bg-emerald-400" : "bg-purple-400"}`} />
                        <span>Status: {cloudScanResult.ml_inference.status.toUpperCase()}</span>
                      </div>
                      <div className="text-xs font-mono text-slate-400 mt-1">{cloudScanResult.ml_inference.message}</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Architecture / Integrity Guarantee Footer Note */}
          <div className="p-4 rounded-xl bg-[#060D19]/60 border border-white/[0.05] text-xs font-mono text-slate-400 flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Shield className="w-3.5 h-3.5 text-cyan-400" />
              <span>Static PE Analysis adheres to Microsoft Portable Executable and Common Object File Format (PE/COFF) specifications.</span>
            </div>
            <span className="text-slate-500 shrink-0">Phase 3 — MALGUARD AI</span>
          </div>

        </main>
      </div>

    </div>
  );
}
