"use client";

import React, { useState } from "react";
import { 
  ServerOff, 
  Server, 
  RefreshCw, 
  Lock, 
  ShieldAlert, 
  ExternalLink, 
  CheckCircle2, 
  Info,
  ChevronDown,
  ChevronUp,
  Cpu,
  Sparkles
} from "lucide-react";
import { DetectionEngineStatus, checkDetectionEngineHealth } from "@/lib/api/scannerService";

interface EngineStatusBannerProps {
  engineStatus: DetectionEngineStatus;
  onRefreshStatus: (newStatus: DetectionEngineStatus) => void;
  hasFileSelected: boolean;
  onRunCloudScan?: () => void;
  isScanningCloud?: boolean;
}

export default function EngineStatusBanner({
  engineStatus,
  onRefreshStatus,
  hasFileSelected,
  onRunCloudScan,
  isScanningCloud = false,
}: EngineStatusBannerProps) {
  const [isChecking, setIsChecking] = useState(false);
  const [showDocs, setShowDocs] = useState(false);

  const handleTestConnection = async () => {
    setIsChecking(true);
    try {
      const updated = await checkDetectionEngineHealth();
      onRefreshStatus(updated);
    } finally {
      setIsChecking(false);
    }
  };

  return (
    <div className="w-full space-y-4">
      {/* Main Status Container */}
      <div
        className={`p-5 sm:p-6 rounded-2xl border backdrop-blur-xl transition-all ${
          engineStatus.connected
            ? "bg-emerald-950/20 border-emerald-500/30 shadow-[0_0_25px_rgba(16,185,129,0.15)]"
            : "bg-[#091526]/90 border-amber-500/30 shadow-[0_0_30px_rgba(245,158,11,0.1)]"
        }`}
      >
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-5">
          
          {/* Status info */}
          <div className="flex items-start gap-4">
            <div
              className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 border ${
                engineStatus.connected
                  ? "bg-emerald-500/20 border-emerald-400/40 text-emerald-400"
                  : "bg-amber-500/15 border-amber-500/30 text-amber-400"
              }`}
            >
              {engineStatus.connected ? (
                <Server className="w-6 h-6" />
              ) : (
                <ServerOff className="w-6 h-6" />
              )}
            </div>

            <div>
              <div className="flex flex-wrap items-center gap-2.5 mb-1">
                <span
                  className={`w-2 h-2 rounded-full ${
                    engineStatus.connected
                      ? "bg-emerald-400 shadow-[0_0_8px_#34d399]"
                      : "bg-amber-400 animate-pulse shadow-[0_0_8px_#fbbf24]"
                  }`}
                />
                <h3 className="text-base sm:text-lg font-bold text-white font-display">
                  {engineStatus.connected
                    ? "Detection Engine Connected"
                    : "Detection Engine Not Connected"}
                </h3>
                <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-slate-900 border border-white/10 text-slate-300">
                  {engineStatus.endpoint}
                </span>
              </div>

              <p className="text-xs sm:text-sm text-slate-300/90 leading-relaxed max-w-2xl">
                {engineStatus.connected
                  ? engineStatus.message
                  : "FastAPI detection backend is offline. Static PE header analysis and cryptographic SHA-256 fingerprinting have been performed locally. Machine learning classification (Random Forest) and signature scanning (ClamAV) are disabled."}
              </p>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex flex-wrap items-center gap-3 w-full lg:w-auto justify-end">
            
            {/* Test Connection Button */}
            <button
              onClick={handleTestConnection}
              disabled={isChecking}
              className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-slate-800/90 hover:bg-slate-700/90 border border-white/10 hover:border-cyan-500/40 text-xs font-mono text-cyan-300 transition-all cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isChecking ? "animate-spin" : ""}`} />
              <span>{isChecking ? "Testing..." : "Test Connection"}</span>
            </button>

            {/* Scan with AI Engine (Active when engine is connected) */}
            <button
              onClick={onRunCloudScan}
              disabled={!engineStatus.connected || !hasFileSelected || isScanningCloud}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
                engineStatus.connected && hasFileSelected && !isScanningCloud
                  ? "bg-gradient-to-r from-cyan-400 to-purple-500 text-slate-950 hover:brightness-110 shadow-[0_0_15px_rgba(34,211,238,0.4)] cursor-pointer"
                  : "bg-slate-900/80 border border-slate-800 text-slate-500 cursor-not-allowed"
              }`}
              title={
                !engineStatus.connected
                  ? "Detection engine is offline. AI classification is disabled."
                  : !hasFileSelected
                  ? "Select a file to initiate AI classification."
                  : "Submit binary for AI classification"
              }
            >
              {!engineStatus.connected ? (
                <>
                  <Lock className="w-3.5 h-3.5" />
                  <span>AI Engine Disabled</span>
                </>
              ) : isScanningCloud ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Analyzing with Engine...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Run Cloud ML Scan</span>
                </>
              )}
            </button>

          </div>
        </div>

        {/* Toggle Developer Notes */}
        <div className="mt-4 pt-3 border-t border-white/[0.06] flex items-center justify-between text-xs font-mono text-slate-400">
          <button
            onClick={() => setShowDocs(!showDocs)}
            className="flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            <Info className="w-3.5 h-3.5" />
            <span>FastAPI Architecture & Integration Specs</span>
            {showDocs ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
          <span>Last checked: {engineStatus.lastChecked}</span>
        </div>

        {/* Expandable Developer Info */}
        {showDocs && (
          <div className="mt-4 p-4 rounded-xl bg-[#040914] border border-white/[0.08] text-xs font-mono text-slate-300 space-y-2.5 animate-in fade-in duration-200">
            <div className="text-cyan-300 font-bold flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>Future FastAPI Backend Specification (Phase 4 Ready)</span>
            </div>
            <p className="text-slate-400 leading-relaxed text-xs">
              The scanner is fully wired to integrate with your upcoming FastAPI microservice.
              Once running, start your FastAPI service on <code className="text-cyan-300 font-mono">http://localhost:8000</code> or configure <code className="text-cyan-300 font-mono">NEXT_PUBLIC_FASTAPI_URL</code> in <code className="text-cyan-300 font-mono">.env.local</code>.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 text-xs font-mono">
              <div className="p-2.5 rounded-lg bg-slate-900/80 border border-white/5">
                <span className="text-slate-400 block mb-0.5">Health Endpoint:</span>
                <span className="text-emerald-400">GET /api/v1/health</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-900/80 border border-white/5">
                <span className="text-slate-400 block mb-0.5">Classification Endpoint:</span>
                <span className="text-purple-400">POST /api/v1/scan (multipart/form-data)</span>
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}

