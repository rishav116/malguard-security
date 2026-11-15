"use client";

import React from "react";
import { FileSearch, ShieldAlert, ShieldCheck, AlertTriangle } from "lucide-react";

interface OverviewCardsProps {
  totalScans: number;
  threatsDetected: number;
  cleanFiles: number;
  suspiciousFiles: number;
}

export default function OverviewCards({
  totalScans = 0,
  threatsDetected = 0,
  cleanFiles = 0,
  suspiciousFiles = 0,
}: OverviewCardsProps) {
  const cards = [
    {
      title: "Total Scans",
      value: totalScans,
      badge: totalScans === 0 ? "Awaiting Ingestion" : "Artifacts Logged",
      icon: FileSearch,
      color: "text-cyan-400",
      borderColor: "border-cyan-500/25",
      glowColor: "group-hover:border-cyan-400/50",
      bgGradient: "from-cyan-500/10 via-transparent to-transparent",
      description: "Uploaded binaries and documents queued for inspection.",
    },
    {
      title: "Threats Detected",
      value: threatsDetected,
      badge: threatsDetected === 0 ? "Clean Baseline" : "Action Required",
      icon: ShieldAlert,
      color: "text-rose-400",
      borderColor: "border-rose-500/25",
      glowColor: "group-hover:border-rose-400/50",
      bgGradient: "from-rose-500/10 via-transparent to-transparent",
      description: "Artifacts confirmed malicious via signatures or ML model.",
    },
    {
      title: "Clean Files",
      value: cleanFiles,
      badge: cleanFiles === 0 ? "No Records" : "Verified Benign",
      icon: ShieldCheck,
      color: "text-emerald-400",
      borderColor: "border-emerald-500/25",
      glowColor: "group-hover:border-emerald-400/50",
      bgGradient: "from-emerald-500/10 via-transparent to-transparent",
      description: "Standard PE sections and valid digital signatures.",
    },
    {
      title: "Suspicious Files",
      value: suspiciousFiles,
      badge: suspiciousFiles === 0 ? "Zero Flagged" : "Under Review",
      icon: AlertTriangle,
      color: "text-amber-400",
      borderColor: "border-amber-500/25",
      glowColor: "group-hover:border-amber-400/50",
      bgGradient: "from-amber-500/10 via-transparent to-transparent",
      description: "High entropy or anomalous IAT hooks requiring triage.",
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 sm:gap-6">
      {cards.map((card, idx) => {
        const Icon = card.icon;

        return (
          <div
            key={idx}
            className={`group relative rounded-2xl p-[1px] bg-gradient-to-b ${card.bgGradient} transition-all duration-300 hover:-translate-y-1`}
          >
            <div
              className={`rounded-2xl bg-[#070F1E] p-4 xs:p-5 sm:p-6 border ${card.borderColor} ${card.glowColor} transition-colors shadow-lg flex flex-col justify-between h-full`}
            >
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div
                    className={`w-10 h-10 rounded-xl bg-[#091526] border ${card.borderColor} flex items-center justify-center ${card.color} shadow-sm`}
                  >
                    <Icon className="w-5 h-5" />
                  </div>
                  <span className="text-[11px] font-mono font-medium px-2.5 py-0.5 rounded-full bg-[#060D19] border border-white/[0.08] text-slate-300">
                    {card.badge}
                  </span>
                </div>

                <div className="text-xs font-mono font-medium text-slate-300 uppercase tracking-wider">
                  {card.title}
                </div>
                <div className="text-3xl font-bold text-white font-display mt-1 tabular-nums tracking-tight">
                  {card.value}
                </div>
              </div>

              <p className="text-xs text-slate-400 mt-4 pt-3 border-t border-white/[0.06] leading-relaxed">
                {card.description}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

