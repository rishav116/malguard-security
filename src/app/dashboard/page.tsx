"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/context/AuthContext";
import Sidebar from "@/components/dashboard/Sidebar";
import DashboardHeader from "@/components/dashboard/DashboardHeader";
import OverviewCards from "@/components/dashboard/OverviewCards";
import ScanCharts from "@/components/dashboard/ScanCharts";
import RecentScansTable, { ScanItem } from "@/components/dashboard/RecentScansTable";
import GeminiAssistantCard from "@/components/dashboard/GeminiAssistantCard";
import ScanModal from "@/components/ScanModal";
import { fetchDashboardMetrics } from "@/lib/api/scannerService";
import { formatDeterministicDateTime } from "@/lib/utils/timeFormat";
import { Shield, Sparkles, AlertCircle, RefreshCw } from "lucide-react";

export default function DashboardPage() {
  const router = useRouter();
  const { user, session, loading, isConfigured } = useAuth();

  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [isSampleData, setIsSampleData] = useState(false);
  const [realScans, setRealScans] = useState<ScanItem[]>([]);
  const [loadingMetrics, setLoadingMetrics] = useState(false);

  // Sample scans list used when user toggles "Load Sample Telemetry"
  const sampleScans: ScanItem[] = [
    {
      id: "scan-001",
      fileName: "Trojan.Win32.WannaLock.bin",
      fileSize: "1.42 MB",
      sha256: "8e932b130a103ecda45cf2a4176d4918e7e1a3bc89a74659b8a0",
      verdict: "MALICIOUS",
      riskScore: 94,
      scannedAt: "Today, 14:28",
      type: "PE32 Executable",
    },
    {
      id: "scan-002",
      fileName: "Invoice_Payment_Receipt.docm",
      fileSize: "384 KB",
      sha256: "3f829da48b1001cda85bb9a376510827ea8b01249bce746a",
      verdict: "SUSPICIOUS",
      riskScore: 68,
      scannedAt: "Today, 11:15",
      type: "Office Macro",
    },
    {
      id: "scan-003",
      fileName: "SystemDiagnosticTool_v2.8.exe",
      fileSize: "3.10 MB",
      sha256: "01fca829b384ef81093ac6198f12a49b491a0c84bce12749",
      verdict: "CLEAN",
      riskScore: 8,
      scannedAt: "Yesterday, 17:40",
      type: "PE32 Executable",
    },
    {
      id: "scan-004",
      fileName: "CloudSync_Setup_v4.exe",
      fileSize: "4.85 MB",
      sha256: "c45df89104bce81938fa82b412948ce10827ea49bc128471",
      verdict: "CLEAN",
      riskScore: 5,
      scannedAt: "2 days ago",
      type: "Installer",
    },
  ];

  // Active scans state: starts empty (true empty state) or populated from database
  const [scans, setScans] = useState<ScanItem[]>([]);

  // Route protection
  useEffect(() => {
    if (!loading && !user) {
      router.push("/login");
    }
  }, [user, loading, router]);

  // Fetch real scan history from backend / Supabase
  useEffect(() => {
    if (user) {
      let isCancelled = false;
      const timer = setTimeout(() => {
        if (!isCancelled) setLoadingMetrics(true);
      }, 0);

      fetchDashboardMetrics(session?.access_token).then((res) => {
        if (isCancelled) return;
        if (res.success && res.data && res.data.recent_scans.length > 0) {
          const mapped: ScanItem[] = res.data.recent_scans.map((r) => {
            const v = r.verdict === "NO_THREAT_DETECTED" ? "CLEAN" : r.verdict;
            const score = v === "MALICIOUS" ? 95 : v === "SUSPICIOUS" ? 70 : v === "CLEAN" ? 5 : 25;
            let displayTime = "Recent";
            if (r.scannedAt) {
              displayTime = formatDeterministicDateTime(r.scannedAt);
            }
            return {
              id: r.id,
              fileName: r.fileName,
              fileSize: r.fileSize,
              sha256: r.sha256,
              verdict: (v === "MALICIOUS" || v === "SUSPICIOUS" || v === "CLEAN" ? v : "INCONCLUSIVE") as ScanItem["verdict"],
              riskScore: score,
              scannedAt: displayTime,
              type: r.type || "PE Binary",
            };
          });
          setRealScans(mapped);
          setScans(mapped);
        }
        setLoadingMetrics(false);
      });

      return () => {
        isCancelled = true;
        clearTimeout(timer);
      };
    }
  }, [user, session]);

  // Toggle sample data
  const handleToggleSampleData = () => {
    if (isSampleData) {
      setScans(realScans);
      setIsSampleData(false);
    } else {
      setScans(sampleScans);
      setIsSampleData(true);
    }
  };

  const handleInspectScan = (_item: ScanItem) => {
    setIsScanModalOpen(true);
  };

  // Compute metric counts
  const totalScans = scans.length;
  const threatsDetected = scans.filter((s) => s.verdict === "MALICIOUS").length;
  const cleanFiles = scans.filter((s) => s.verdict === "CLEAN").length;
  const suspiciousFiles = scans.filter((s) => s.verdict === "SUSPICIOUS").length;

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
    return null; // Will redirect to /login
  }

  const userDisplayName =
    user.user_metadata?.full_name ||
    user.email?.split("@")[0] ||
    "Security Analyst";

  return (
    <div className="min-h-screen bg-[#040812] text-slate-100 flex">
      
      {/* Collapsible Sidebar */}
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        mobileOpen={mobileSidebarOpen}
        onCloseMobile={() => setMobileSidebarOpen(false)}
        onOpenQuickScan={() => router.push("/scanner")}
      />

      {/* Main Content Area */}
      <div
        className={`flex-1 flex flex-col transition-all duration-300 ${
          sidebarCollapsed ? "lg:ml-20" : "lg:ml-64"
        }`}
      >
        {/* Top Header */}
        <DashboardHeader
          onToggleMobileSidebar={() => setMobileSidebarOpen(!mobileSidebarOpen)}
          onOpenQuickScan={() => router.push("/scanner")}
        />

        {/* Dashboard Main View */}
        <main className="p-3 xs:p-4 sm:p-6 lg:p-8 space-y-6 sm:space-y-8 flex-1">
          
          {/* Welcome Banner & Environment Notice */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-white/[0.06]">
            <div>
              <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-xs font-mono font-medium text-cyan-300 mb-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                <span>ANALYST WORKSPACE</span>
              </div>
              <h2 className="text-xl xs:text-2xl sm:text-3xl font-bold text-white tracking-tight font-display">
                Welcome back, {userDisplayName}
              </h2>
              <p className="text-xs sm:text-sm text-slate-400 mt-1">
                Security operations telemetry and static artifact inspection overview.
              </p>
            </div>

            {/* Supabase connection indicator pill */}
            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="text-slate-400">Auth Provider:</span>
              <span className={`px-2.5 py-1 rounded-lg border font-semibold ${
                isConfigured
                  ? "bg-emerald-950/40 border-emerald-500/40 text-emerald-300"
                  : "bg-cyan-950/40 border-cyan-500/30 text-cyan-300"
              }`}>
                {isConfigured ? "Supabase Cloud" : "Demo Session Active"}
              </span>
            </div>
          </div>

          {/* 1. Overview Metric Cards */}
          <OverviewCards
            totalScans={totalScans}
            threatsDetected={threatsDetected}
            cleanFiles={cleanFiles}
            suspiciousFiles={suspiciousFiles}
          />

          {/* 2. Charts Section (Activity + Distribution) */}
          <ScanCharts hasData={isSampleData || totalScans > 0} />

          {/* 3. Recent Scans Table (with true empty state and demo toggle) */}
          <RecentScansTable
            scans={scans}
            onOpenQuickScan={() => setIsScanModalOpen(true)}
            onToggleSampleData={handleToggleSampleData}
            isSampleData={isSampleData}
            onInspectScan={handleInspectScan}
          />

          {/* 4. Gemini AI Assistant Entry Point (Live Phase 5) */}
          <GeminiAssistantCard />

        </main>
      </div>

      {/* Quick Scan Modal */}
      <ScanModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
      />

    </div>
  );
}

