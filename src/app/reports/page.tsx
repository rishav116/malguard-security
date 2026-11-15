"use client";

import React, { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/context/AuthContext";
import Sidebar from "@/components/dashboard/Sidebar";
import DashboardHeader from "@/components/dashboard/DashboardHeader";
import { 
  FileText, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Search, 
  RefreshCw, 
  Plus, 
  Filter, 
  ArrowUpDown,
  ExternalLink,
  Copy,
  Check,
  Binary,
  Layers,
  Cpu,
  Shield,
  Clock,
  ChevronRight,
  X
} from "lucide-react";
import { formatDeterministicDateTime } from "@/lib/utils/timeFormat";
import { fetchUserScans, PersistedScanItem } from "@/lib/api/scannerService";

export default function ThreatReportsPage() {
  const router = useRouter();
  const { user, session, loading } = useAuth();

  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  // Scans data
  const [scans, setScans] = useState<PersistedScanItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedVerdict, setSelectedVerdict] = useState<string>("ALL");
  const [selectedScan, setSelectedScan] = useState<PersistedScanItem | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Route protection
  useEffect(() => {
    if (!loading && !user) {
      router.push("/login");
    }
  }, [user, loading, router]);

  // Load scans from FastAPI / Supabase
  const loadScans = async () => {
    if (!user) return;
    setIsLoading(true);
    try {
      const res = await fetchUserScans(session?.access_token, {
        limit: 100,
        search: searchQuery || undefined,
        verdict: selectedVerdict !== "ALL" ? selectedVerdict : undefined,
      });
      if (res.success && res.data) {
        setScans(res.data);
      }
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (user) {
      const timer = setTimeout(() => {
        loadScans();
      }, 0);
      return () => clearTimeout(timer);
    }
  }, [user, session, selectedVerdict]);

  // Client-side search filtering
  const filteredScans = useMemo(() => {
    if (!searchQuery.trim()) return scans;
    const q = searchQuery.toLowerCase();
    return scans.filter(
      (s) =>
        s.file_name.toLowerCase().includes(q) ||
        s.sha256.toLowerCase().includes(q) ||
        s.verdict.toLowerCase().includes(q) ||
        (s.clamav_signature && s.clamav_signature.toLowerCase().includes(q))
    );
  }, [scans, searchQuery]);

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#040812] flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-600/20 border border-cyan-400/40 text-cyan-400 flex items-center justify-center animate-pulse">
            <Shield className="w-6 h-6" />
          </div>
          <span className="text-xs font-mono text-cyan-300">Loading Threat Intelligence...</span>
        </div>
      </div>
    );
  }

  if (!user) return null;

  return (
    <div className="min-h-screen bg-[#040812] text-slate-100 flex">
      {/* Sidebar */}
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        mobileOpen={mobileSidebarOpen}
        onCloseMobile={() => setMobileSidebarOpen(false)}
        onOpenQuickScan={() => router.push("/scanner")}
      />

      {/* Main Content */}
      <div
        className={`flex-1 flex flex-col transition-all duration-300 min-w-0 ${
          sidebarCollapsed ? "lg:pl-20" : "lg:pl-64"
        }`}
      >
        <DashboardHeader onToggleMobileSidebar={() => setMobileSidebarOpen(true)} />

        <main className="flex-1 p-3 xs:p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto space-y-6">
          
          {/* Page Title & Actions */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl sm:text-3xl font-bold text-white font-display tracking-tight">
                  Threat Reports & Audit History
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium bg-cyan-950/80 text-cyan-400 border border-cyan-500/30">
                  PostgreSQL Persisted
                </span>
              </div>
              <p className="text-xs sm:text-sm text-slate-400 mt-1">
                Cryptographic audit trail of all inspected PE binaries and multi-engine threat verdicts.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={loadScans}
                disabled={isLoading}
                className="px-3.5 py-2 rounded-xl bg-slate-900 border border-white/10 hover:border-cyan-400/40 text-xs font-mono text-slate-300 hover:text-white flex items-center gap-2 transition-all cursor-pointer"
                title="Refresh scan history"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin text-cyan-400" : ""}`} />
                <span>Refresh</span>
              </button>

              <Link
                href="/scanner"
                className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 text-white font-bold text-xs flex items-center gap-2 shadow-[0_0_20px_rgba(34,211,238,0.3)] transition-all cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>New Binary Scan</span>
              </Link>
            </div>
          </div>

          {/* Search Bar & Verdict Filters */}
          <div className="p-4 rounded-2xl bg-[#071120]/90 border border-white/[0.08] backdrop-blur-xl flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
            
            {/* Search Input */}
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search by file name, SHA-256 hash or signature..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 rounded-xl bg-[#040812] border border-white/10 focus:border-cyan-400/50 text-xs text-white placeholder-slate-500 focus:outline-none font-mono"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Verdict Filter Buttons */}
            <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
              <span className="text-slate-400 mr-1 hidden sm:inline">Verdict:</span>
              {[
                { id: "ALL", label: "All" },
                { id: "MALICIOUS", label: "Malicious" },
                { id: "SUSPICIOUS", label: "Suspicious" },
                { id: "NO_THREAT_DETECTED", label: "Clean" },
                { id: "INCONCLUSIVE", label: "Inconclusive" },
              ].map((btn) => (
                <button
                  key={btn.id}
                  onClick={() => setSelectedVerdict(btn.id)}
                  className={`px-3 py-1.5 rounded-lg border text-xs transition-all cursor-pointer ${
                    selectedVerdict === btn.id
                      ? "bg-cyan-500/20 border-cyan-400 text-cyan-300 shadow-[0_0_12px_rgba(34,211,238,0.25)] font-bold"
                      : "bg-slate-900/60 border-white/5 text-slate-400 hover:text-slate-200 hover:bg-slate-800"
                  }`}
                >
                  {btn.label}
                </button>
              ))}
            </div>
          </div>

          {/* Results Summary Info */}
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 px-1">
            <span>
              Showing {filteredScans.length} {filteredScans.length === 1 ? "record" : "records"}
              {searchQuery && ` matching "${searchQuery}"`}
            </span>
            <span>RLS Active: Authenticated Owner UUID</span>
          </div>

          {/* Scans Table */}
          <div className="rounded-2xl bg-[#071120]/90 border border-white/[0.08] backdrop-blur-xl overflow-hidden shadow-2xl">
            {isLoading ? (
              <div className="py-16 flex flex-col items-center justify-center text-center">
                <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mb-3" />
                <span className="text-xs font-mono text-slate-400">Querying Supabase scan records...</span>
              </div>
            ) : filteredScans.length === 0 ? (
              <div className="py-16 px-4 flex flex-col items-center justify-center text-center space-y-4">
                <div className="w-14 h-14 rounded-2xl bg-cyan-950/40 border border-cyan-500/30 text-cyan-400 flex items-center justify-center">
                  <FileText className="w-7 h-7" />
                </div>
                <div className="space-y-1">
                  <h3 className="text-base font-bold text-white font-display">
                    {searchQuery || selectedVerdict !== "ALL"
                      ? "No Matching Scans Found"
                      : "No Scan Records In Your Account"}
                  </h3>
                  <p className="text-xs font-mono text-slate-400 max-w-sm">
                    {searchQuery || selectedVerdict !== "ALL"
                      ? "Try adjusting your search query or verdict filters."
                      : "Upload and analyze Windows PE binaries (.exe, .dll) to build your persistent threat audit trail."}
                  </p>
                </div>
                <Link
                  href="/scanner"
                  className="px-4 py-2 rounded-xl bg-cyan-500/20 border border-cyan-400/40 hover:bg-cyan-500/30 text-cyan-300 font-bold text-xs flex items-center gap-2 cursor-pointer transition-all"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Scan Your First Artifact</span>
                </Link>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse min-w-[700px]">
                  <thead>
                    <tr className="border-b border-white/[0.06] text-[11px] font-mono text-slate-400 uppercase tracking-wider bg-[#050C18]/80">
                      <th className="py-3 px-4">Artifact</th>
                      <th className="py-3 px-4">SHA-256 Digest</th>
                      <th className="py-3 px-4">Size</th>
                      <th className="py-3 px-4">ClamAV</th>
                      <th className="py-3 px-4">Random Forest ML</th>
                      <th className="py-3 px-4">Verdict</th>
                      <th className="py-3 px-4">Timestamp</th>
                      <th className="py-3 px-4 text-right">Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.04] text-xs font-mono">
                    {filteredScans.map((scan) => {
                      const isMalicious = scan.verdict === "MALICIOUS";
                      const isSuspicious = scan.verdict === "SUSPICIOUS";
                      const isClean = scan.verdict === "NO_THREAT_DETECTED";
                      const isInconclusive = scan.verdict === "INCONCLUSIVE";

                      return (
                        <tr
                          key={scan.id}
                          className="hover:bg-slate-800/30 transition-colors group cursor-pointer"
                          onClick={() => setSelectedScan(scan)}
                        >
                          {/* Artifact Name */}
                          <td className="py-3.5 px-4 font-semibold text-white">
                            <div className="flex items-center gap-2.5">
                              <FileText className="w-4 h-4 text-cyan-400 shrink-0" />
                              <span className="font-sans text-xs truncate max-w-[170px]" title={scan.file_name}>
                                {scan.file_name}
                              </span>
                            </div>
                          </td>

                          {/* SHA-256 */}
                          <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                            <div className="flex items-center gap-1.5">
                              <span>{scan.sha256.substring(0, 14)}...</span>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleCopyHash(scan.sha256);
                                }}
                                className="text-slate-500 hover:text-cyan-300 p-1"
                                title="Copy full SHA-256"
                              >
                                {copiedHash === scan.sha256 ? (
                                  <Check className="w-3 h-3 text-emerald-400" />
                                ) : (
                                  <Copy className="w-3 h-3" />
                                )}
                              </button>
                            </div>
                          </td>

                          {/* Size */}
                          <td className="py-3.5 px-4 text-slate-300">
                            {scan.formatted_size}
                          </td>

                          {/* ClamAV */}
                          <td className="py-3.5 px-4">
                            {scan.clamav_matched ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950/80 border border-rose-500/40 text-rose-300 truncate max-w-[130px] inline-block" title={scan.clamav_signature || "Infected"}>
                                {scan.clamav_signature || "INFECTED"}
                              </span>
                            ) : scan.clamav_available ? (
                              <span className="text-emerald-400 text-[11px]">CLEAN</span>
                            ) : (
                              <span className="text-slate-500 text-[11px]">OFFLINE</span>
                            )}
                          </td>

                          {/* Random Forest ML */}
                          <td className="py-3.5 px-4">
                            {scan.ml_available && scan.ml_prediction ? (
                              <span className={`text-[11px] font-bold ${scan.ml_prediction === "malicious" ? "text-amber-400" : "text-emerald-400"}`}>
                                {scan.ml_prediction.toUpperCase()} {scan.ml_confidence_score ? `(${(scan.ml_confidence_score * 100).toFixed(0)}%)` : ""}
                              </span>
                            ) : (
                              <span className="text-slate-500 text-[11px]">UNAVAILABLE</span>
                            )}
                          </td>

                          {/* Final Verdict */}
                          <td className="py-3.5 px-4">
                            <span
                              className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${
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
                              {isInconclusive && <RefreshCw className="w-3 h-3 text-cyan-400" />}
                              <span>{scan.verdict === "NO_THREAT_DETECTED" ? "CLEAN" : scan.verdict}</span>
                            </span>
                          </td>

                          {/* Timestamp */}
                          <td className="py-3.5 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                            {formatDeterministicDateTime(scan.created_at)}
                          </td>

                          {/* Inspect action */}
                          <td className="py-3.5 px-4 text-right">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedScan(scan);
                              }}
                              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 justify-end ml-auto group-hover:translate-x-0.5 transition-transform"
                            >
                              <span>View</span>
                              <ChevronRight className="w-3.5 h-3.5" />
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </main>
      </div>

      {/* Detail Inspection Modal / Drawer */}
      {selectedScan && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div
            className="w-full max-w-2xl bg-[#071120] border border-cyan-500/30 rounded-2xl p-4 xs:p-6 space-y-6 max-h-[90vh] overflow-y-auto shadow-[0_0_50px_rgba(34,211,238,0.2)] animate-in fade-in duration-200"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-start justify-between gap-4 pb-4 border-b border-white/[0.08]">
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-400 text-cyan-300 flex items-center justify-center shrink-0">
                  <Shield className="w-5 h-5" />
                </div>
                <div className="min-w-0">
                  <h3 className="text-base sm:text-lg font-bold text-white font-display truncate">
                    Scan Detail: {selectedScan.file_name}
                  </h3>
                  <div className="text-xs font-mono text-slate-400 truncate">
                    Scan ID: {selectedScan.id}
                  </div>
                </div>
              </div>

              <button
                onClick={() => setSelectedScan(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer shrink-0"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Verdict Badge Bar */}
            <div
              className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 sm:gap-4 ${
                selectedScan.verdict === "MALICIOUS"
                  ? "bg-rose-950/50 border-rose-500/50 text-rose-300"
                  : selectedScan.verdict === "SUSPICIOUS"
                  ? "bg-amber-950/50 border-amber-500/50 text-amber-300"
                  : selectedScan.verdict === "NO_THREAT_DETECTED"
                  ? "bg-emerald-950/50 border-emerald-500/50 text-emerald-300"
                  : "bg-cyan-950/50 border-cyan-500/50 text-cyan-300"
              }`}
            >
              <div className="flex items-center gap-2.5">
                {selectedScan.verdict === "MALICIOUS" && <ShieldAlert className="w-6 h-6 text-rose-400 shrink-0" />}
                {selectedScan.verdict === "SUSPICIOUS" && <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0" />}
                {selectedScan.verdict === "NO_THREAT_DETECTED" && <ShieldCheck className="w-6 h-6 text-emerald-400 shrink-0" />}
                {selectedScan.verdict === "INCONCLUSIVE" && <RefreshCw className="w-6 h-6 text-cyan-400 shrink-0" />}
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider">Final Synthesized Verdict</div>
                  <div className="text-lg font-extrabold">{selectedScan.verdict}</div>
                </div>
              </div>
              <div className="text-left sm:text-right text-xs font-mono text-slate-300">
                {formatDeterministicDateTime(selectedScan.created_at)}
              </div>
            </div>

            {/* Verdict Rationale */}
            <div className="space-y-2">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
                Verdict Rationale:
              </span>
              <ul className="space-y-1.5">
                {selectedScan.verdict_reasons.map((r, i) => (
                  <li key={i} className="text-xs font-mono text-slate-300 flex items-start gap-2">
                    <span className="text-cyan-400 mt-0.5">•</span>
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Cryptographic Hashes */}
            <div className="p-4 rounded-xl bg-[#040914] border border-white/[0.08] space-y-2.5 text-xs font-mono">
              <span className="text-slate-400 uppercase tracking-wider text-[11px] block">
                Cryptographic Fingerprints:
              </span>
              <div className="space-y-1.5">
                <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center text-slate-400 gap-1">
                  <span>SHA-256:</span>
                  <div className="flex items-center gap-1.5 break-all">
                    <span className="text-cyan-300 font-bold break-all select-all">{selectedScan.sha256}</span>
                    <button
                      onClick={() => handleCopyHash(selectedScan.sha256)}
                      className="text-slate-400 hover:text-white shrink-0 p-1"
                      title="Copy"
                    >
                      {copiedHash === selectedScan.sha256 ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                </div>
                {selectedScan.sha1 && (
                  <div className="flex justify-between text-slate-400">
                    <span>SHA-1:</span>
                    <span className="text-slate-300">{selectedScan.sha1}</span>
                  </div>
                )}
                {selectedScan.md5 && (
                  <div className="flex justify-between text-slate-400">
                    <span>MD5:</span>
                    <span className="text-slate-300">{selectedScan.md5}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Engine Telemetry Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {/* ClamAV */}
              <div className="p-4 rounded-xl bg-[#040914] border border-white/[0.08] space-y-1.5">
                <div className="text-xs font-mono text-slate-400 flex items-center justify-between">
                  <span>ClamAV Engine</span>
                  <span className={`w-2 h-2 rounded-full ${selectedScan.clamav_available ? "bg-emerald-400" : "bg-amber-400"}`} />
                </div>
                <div className="text-xs font-mono font-bold text-white">
                  Status: {selectedScan.clamav_status.toUpperCase()}
                </div>
                <div className="text-[11px] font-mono text-slate-400">
                  {selectedScan.clamav_message}
                </div>
              </div>

              {/* Random Forest */}
              <div className="p-4 rounded-xl bg-[#040914] border border-white/[0.08] space-y-1.5">
                <div className="text-xs font-mono text-slate-400 flex items-center justify-between">
                  <span>Random Forest ML</span>
                  <span className={`w-2 h-2 rounded-full ${selectedScan.ml_available ? "bg-emerald-400" : "bg-purple-400"}`} />
                </div>
                <div className="text-xs font-mono font-bold text-white">
                  Prediction: {selectedScan.ml_prediction ? selectedScan.ml_prediction.toUpperCase() : "N/A"}
                </div>
                <div className="text-[11px] font-mono text-slate-400">
                  {selectedScan.ml_message}
                </div>
              </div>
            </div>

            {/* PE Header Metadata */}
            {selectedScan.pe_summary && (
              <div className="p-4 rounded-xl bg-[#040914] border border-white/[0.08] space-y-2 text-xs font-mono">
                <span className="text-slate-400 uppercase tracking-wider text-[11px] block">
                  Static PE Inspection Summary:
                </span>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-slate-300">
                  <div>
                    <span className="text-slate-500 block">Architecture:</span>
                    <span>{selectedScan.pe_summary.machine || "Unknown"}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Subsystem:</span>
                    <span>{selectedScan.pe_summary.subsystem || "Unknown"}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Sections:</span>
                    <span>{selectedScan.pe_summary.number_of_sections || 0}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Entropy:</span>
                    <span>{selectedScan.pe_summary.file_entropy ? selectedScan.pe_summary.file_entropy.toFixed(3) : "N/A"} / 8.0</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Total Imports:</span>
                    <span>{selectedScan.pe_summary.total_imports_count || 0}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Suspicious APIs:</span>
                    <span className={selectedScan.pe_summary.suspicious_indicators_count ? "text-amber-400 font-bold" : "text-emerald-400"}>
                      {selectedScan.pe_summary.suspicious_indicators_count || 0} detected
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Footer */}
            <div className="flex justify-end pt-2 border-t border-white/[0.08]">
              <button
                onClick={() => setSelectedScan(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white cursor-pointer"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

