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

  const handleTestConnection = async () => {
    setIsChecking(true);
    try {
      const updated = await checkDetectionEngineHealth(true);
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
          engineStatus.connected && !engineStatus.isWarmingUp
            ? "bg-emerald-950/20 border-emerald-500/30 shadow-[0_0_25px_rgba(16,185,129,0.15)]"
            : engineStatus.isWarmingUp
            ? "bg-amber-950/30 border-amber-500/40 shadow-[0_0_30px_rgba(245,158,11,0.2)] animate-pulse"
            : "bg-[#091526]/90 border-amber-500/30 shadow-[0_0_30px_rgba(245,158,11,0.1)]"
        }`}
      >
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-5">
          
          {/* Status info */}
          <div className="flex items-start gap-4">
            <div
              className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 border ${
                engineStatus.connected && !engineStatus.isWarmingUp
                  ? "bg-emerald-500/20 border-emerald-400/40 text-emerald-400"
                  : engineStatus.isWarmingUp
                  ? "bg-amber-500/20 border-amber-400/40 text-amber-300"
                  : "bg-amber-500/15 border-amber-500/30 text-amber-400"
              }`}
            >
              {engineStatus.connected && !engineStatus.isWarmingUp ? (
                <Server className="w-6 h-6" />
              ) : engineStatus.isWarmingUp ? (
                <RefreshCw className="w-6 h-6 animate-spin text-amber-400" />
              ) : (
                <ServerOff className="w-6 h-6" />
              )}
            </div>

            <div>
              <div className="flex flex-wrap items-center gap-2.5 mb-1">
                <span
                  className={`w-2 h-2 rounded-full ${
                    engineStatus.connected && !engineStatus.isWarmingUp
                      ? "bg-emerald-400 shadow-[0_0_8px_#34d399]"
                      : engineStatus.isWarmingUp
                      ? "bg-amber-400 animate-ping shadow-[0_0_8px_#fbbf24]"
                      : "bg-amber-400 animate-pulse shadow-[0_0_8px_#fbbf24]"
                  }`}
                />
                <h3 className="text-base sm:text-lg font-bold text-white font-display">
                  {engineStatus.connected && !engineStatus.isWarmingUp
                    ? "Detection Engines Online & Verified"
                    : engineStatus.isWarmingUp
                    ? "Initializing Security Engine (Cold Start)"
                    : "Detection Engine Not Connected"}
                </h3>
                {engineStatus.isWarmingUp && (
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30 animate-pulse">
                    Loading 3.6M signatures into RAM...
                  </span>
                )}
                {engineStatus.connected && !engineStatus.isWarmingUp && engineStatus.clamavVersion && (
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                    Official ClamAV
                  </span>
                )}
              </div>

              <p className="text-xs sm:text-sm text-slate-300/90 leading-relaxed max-w-2xl">
                {engineStatus.connected
                  ? engineStatus.message
                  : "FastAPI detection backend is offline. Static PE header analysis and cryptographic SHA-256 fingerprinting have been performed locally. Machine learning classification (Random Forest) and signature scanning (ClamAV) are disabled."}
              </p>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex flex-col xs:flex-row items-stretch xs:items-center gap-3 w-full lg:w-auto justify-end">
            
            {/* Test Connection Button */}
            <button
              onClick={handleTestConnection}
              disabled={isChecking}
              className="flex items-center justify-center gap-2 px-3.5 py-2.5 sm:py-2 rounded-xl bg-slate-800/90 hover:bg-slate-700/90 border border-white/10 hover:border-cyan-500/40 text-xs font-mono text-cyan-300 transition-all cursor-pointer disabled:opacity-50 min-h-[40px] active:scale-95"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isChecking ? "animate-spin" : ""}`} />
              <span>{isChecking ? "Testing..." : "Test Connection"}</span>
            </button>

            {/* Scan with AI Engine (Active when engine is connected AND not warming up) */}
            <button
              onClick={onRunCloudScan}
              disabled={!engineStatus.connected || engineStatus.isWarmingUp || !hasFileSelected || isScanningCloud}
              className={`flex items-center justify-center gap-2 px-4 py-2.5 sm:py-2 rounded-xl text-xs font-bold transition-all min-h-[40px] active:scale-95 ${
                engineStatus.connected && !engineStatus.isWarmingUp && hasFileSelected && !isScanningCloud
                  ? "bg-gradient-to-r from-cyan-400 to-purple-500 text-slate-950 hover:brightness-110 shadow-[0_0_15px_rgba(34,211,238,0.4)] cursor-pointer"
                  : engineStatus.isWarmingUp
                  ? "bg-amber-950/60 border border-amber-500/40 text-amber-300 cursor-wait shadow-[0_0_15px_rgba(245,158,11,0.2)]"
                  : "bg-slate-900/80 border border-slate-800 text-slate-500 cursor-not-allowed"
              }`}
              title={
                !engineStatus.connected
                  ? "Detection engine is offline. AI classification is disabled."
                  : engineStatus.isWarmingUp
                  ? "ClamAV database is actively loading into memory. Scans are temporarily held to prevent premature inconclusive verdicts."
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
              ) : engineStatus.isWarmingUp ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin text-amber-300" />
                  <span>Warming Up Engine...</span>
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

        {/* Last Checked Timestamp */}
        {engineStatus.lastChecked && (
          <div className="mt-4 pt-3 border-t border-white/[0.06] flex items-center justify-end text-xs font-mono text-slate-400">
            <span>Last checked: {engineStatus.lastChecked}</span>
          </div>
        )}

      </div>
    </div>
  );
}

