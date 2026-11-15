"use client";

import React from "react";
import { 
  FileText, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Search, 
  ExternalLink, 
  RefreshCw, 
  Plus, 
  CheckCircle2,
  FolderOpen
} from "lucide-react";

export interface ScanItem {
  id: string;
  fileName: string;
  fileSize: string;
  sha256: string;
  verdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "INCONCLUSIVE";
  riskScore: number;
  scannedAt: string;
  type: string;
}

interface RecentScansTableProps {
  scans: ScanItem[];
  onOpenQuickScan: () => void;
  onToggleSampleData: () => void;
  isSampleData: boolean;
  onInspectScan: (scan: ScanItem) => void;
}

export default function RecentScansTable({
  scans,
  onOpenQuickScan,
  onToggleSampleData,
  isSampleData,
  onInspectScan,
}: RecentScansTableProps) {
  return (
    <div id="recent-scans" className="rounded-2xl glass-panel p-4 xs:p-6 border border-white/[0.08] shadow-2xl">
      
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="text-base sm:text-lg font-bold text-white font-display">
              Recent Artifact Scans
            </h3>
            {isSampleData && (
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-purple-950/60 border border-purple-500/30 text-purple-300">
                Illustrative Demo Data
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time triage telemetry persisted in Supabase PostgreSQL via FastAPI
          </p>
        </div>

        <div className="flex flex-col xs:flex-row items-stretch xs:items-center gap-2 sm:gap-2.5 w-full sm:w-auto">
          {/* Toggle sample demo data button */}
          <button
            onClick={onToggleSampleData}
            className="px-3 py-2 sm:py-1.5 rounded-xl bg-[#091526] hover:bg-[#0d1e36] border border-cyan-500/30 text-cyan-300 text-xs font-mono transition-colors flex items-center justify-center gap-1.5 cursor-pointer min-h-[38px] active:scale-95"
          >
            <RefreshCw className="w-3 h-3 shrink-0" />
            <span>{isSampleData ? "Clear Demo Data" : "Load Sample Telemetry"}</span>
          </button>

          {/* Quick Scan CTA */}
          <button
            onClick={onOpenQuickScan}
            className="px-3.5 py-2 sm:py-1.5 rounded-xl bg-gradient-to-r from-cyan-400 to-purple-500 text-slate-950 font-bold text-xs flex items-center justify-center gap-1.5 shadow-md cursor-pointer hover:brightness-110 transition-all min-h-[38px] active:scale-95"
          >
            <Plus className="w-3.5 h-3.5 shrink-0" />
            <span>Scan Artifact</span>
          </button>
        </div>
      </div>

      {/* Empty State when no scans exist */}
      {scans.length === 0 ? (
        <div className="py-16 px-4 rounded-xl border border-dashed border-slate-700/80 bg-[#050C17]/60 flex flex-col items-center justify-center text-center">
          <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mb-4 shadow-[0_0_20px_rgba(34,211,238,0.15)]">
            <FolderOpen className="w-8 h-8" />
          </div>

          <h4 className="text-base font-bold text-white font-display mb-1">
            No Artifact Scans Logged Yet
          </h4>
          <p className="text-xs text-slate-400 max-w-md mb-6 leading-relaxed">
            The security database contains no scan records for this session. 
            Upload a target binary or test with simulated telemetry to evaluate the dashboard.
          </p>

          <div className="flex flex-col sm:flex-row items-center gap-3">
            <button
              onClick={onOpenQuickScan}
              className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-400 to-purple-500 text-slate-950 font-bold text-xs flex items-center gap-2 shadow-md cursor-pointer hover:brightness-110 active:scale-[0.99] transition-all"
            >
              <Plus className="w-4 h-4" />
              <span>Launch Quick Scan</span>
            </button>
            <button
              onClick={onToggleSampleData}
              className="px-4 py-2 rounded-xl bg-[#091526] hover:bg-[#0c1c33] border border-cyan-500/30 text-cyan-300 text-xs font-mono transition-colors cursor-pointer"
            >
              Populate Demo Data
            </button>
          </div>
        </div>
      ) : (
        /* Scans Table */
        <div className="overflow-x-auto rounded-xl border border-white/[0.06] bg-[#050C17]">
          <table className="w-full text-left border-collapse min-w-[700px]">
            <thead>
              <tr className="border-b border-white/[0.08] text-xs font-mono font-medium text-slate-300 uppercase tracking-wider bg-[#060E1A]">
                <th className="py-3 px-4">Artifact Name</th>
                <th className="py-3 px-4">SHA-256 Hash</th>
                <th className="py-3 px-4">Size</th>
                <th className="py-3 px-4">Verdict</th>
                <th className="py-3 px-4">Risk Index</th>
                <th className="py-3 px-4">Scan Timestamp</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04] text-xs font-mono">
              {scans.map((scan) => {
                const isMalicious = scan.verdict === "MALICIOUS";
                const isSuspicious = scan.verdict === "SUSPICIOUS";
                const isClean = scan.verdict === "CLEAN";

                return (
                  <tr
                    key={scan.id}
                    className="hover:bg-slate-800/30 transition-colors group"
                  >
                    {/* File Name */}
                    <td className="py-3 px-4 font-semibold text-white flex items-center gap-2">
                      <FileText className="w-4 h-4 text-cyan-400 shrink-0" />
                      <span className="truncate max-w-[180px] font-sans text-xs">
                        {scan.fileName}
                      </span>
                    </td>

                    {/* SHA256 */}
                    <td className="py-3 px-4 text-slate-400 text-xs font-mono">
                      {scan.sha256.substring(0, 16)}...
                    </td>

                    {/* Size */}
                    <td className="py-3 px-4 text-slate-300">
                      {scan.fileSize}
                    </td>

                    {/* Verdict */}
                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold border ${
                          isMalicious
                            ? "bg-rose-950/60 border-rose-500/40 text-rose-300"
                            : isSuspicious
                            ? "bg-amber-950/60 border-amber-500/40 text-amber-300"
                            : isClean
                            ? "bg-emerald-950/60 border-emerald-500/40 text-emerald-300"
                            : "bg-cyan-950/60 border-cyan-500/40 text-cyan-300"
                        }`}
                      >
                        {isMalicious && <ShieldAlert className="w-3 h-3 text-rose-400" />}
                        {isSuspicious && <AlertTriangle className="w-3 h-3 text-amber-400" />}
                        {isClean && <ShieldCheck className="w-3 h-3 text-emerald-400" />}
                        {!isMalicious && !isSuspicious && !isClean && <RefreshCw className="w-3 h-3 text-cyan-400" />}
                        <span>{scan.verdict}</span>
                      </span>
                    </td>

                    {/* Risk Index */}
                    <td className="py-3 px-4 font-bold text-slate-200 tabular-nums">
                      {scan.riskScore}/100
                    </td>

                    {/* Timestamp */}
                    <td className="py-3 px-4 text-slate-400 text-xs font-mono">
                      {scan.scannedAt}
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => onInspectScan(scan)}
                        className="px-2.5 py-1 rounded-lg bg-[#091526] hover:bg-cyan-500/20 text-cyan-300 text-xs font-mono border border-cyan-500/30 transition-colors inline-flex items-center gap-1 cursor-pointer"
                      >
                        <span>Details</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Table footer info */}
      <div className="pt-4 mt-2 flex flex-col sm:flex-row items-center justify-between text-xs font-mono text-slate-400 gap-2">
        <span>Persisted Table: <code className="text-cyan-300 font-mono">public.scans(id, user_id, sha256, verdict, pe_summary)</code> with RLS</span>
        <span className="text-slate-400">Showing {scans.length} Record(s)</span>
      </div>

    </div>
  );
}

