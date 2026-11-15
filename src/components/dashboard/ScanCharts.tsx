"use client";

import React, { useState } from "react";
import { Activity, PieChart, Info, BarChart3, ShieldAlert } from "lucide-react";

interface ScanChartsProps {
  hasData?: boolean;
}

export default function ScanCharts({ hasData = false }: ScanChartsProps) {
  const [hoveredBar, setHoveredBar] = useState<number | null>(null);

  // 7-day timeline data (Illustrative sample data when data exists vs 0 when empty)
  const activityData = [
    { day: "Mon", count: hasData ? 4 : 0, height: hasData ? "40%" : "4%" },
    { day: "Tue", count: hasData ? 8 : 0, height: hasData ? "65%" : "4%" },
    { day: "Wed", count: hasData ? 3 : 0, height: hasData ? "30%" : "4%" },
    { day: "Thu", count: hasData ? 12 : 0, height: hasData ? "90%" : "4%" },
    { day: "Fri", count: hasData ? 7 : 0, height: hasData ? "55%" : "4%" },
    { day: "Sat", count: hasData ? 2 : 0, height: hasData ? "20%" : "4%" },
    { day: "Sun", count: hasData ? 5 : 0, height: hasData ? "45%" : "4%" },
  ];

  // Threat distribution categories
  const categories = [
    { label: "High Shannon Entropy", percentage: hasData ? 42 : 0, color: "bg-amber-400", hex: "#fbbf24" },
    { label: "Anomalous Import Hooks (IAT)", percentage: hasData ? 28 : 0, color: "bg-purple-400", hex: "#c084fc" },
    { label: "Obfuscated Macro Scripts", percentage: hasData ? 18 : 0, color: "bg-cyan-400", hex: "#22d3ee" },
    { label: "ClamAV Signature Matches", percentage: hasData ? 12 : 0, color: "bg-rose-400", hex: "#f43f5e" },
  ];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      
      {/* Chart 1: Scan Activity Timeline (7 Columns) */}
      <div className="lg:col-span-7 rounded-2xl glass-panel p-6 border border-cyan-500/20 shadow-xl flex flex-col justify-between">
        
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <BarChart3 className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white font-display">
                  Scan Activity Timeline
                </h3>
                <p className="text-[11px] font-mono text-slate-400">
                  {hasData ? "Daily artifact inspection volume (7-day window)" : "No scan telemetry logged yet"}
                </p>
              </div>
            </div>
            
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#091526] border border-white/[0.08] text-cyan-300">
              {hasData ? "Active Feed (Demo)" : "Awaiting Scans"}
            </span>
          </div>

          {/* Bar Chart Visualization */}
          <div className="h-48 w-full pt-6 flex items-end justify-between gap-3 px-2 border-b border-white/[0.06]">
            {activityData.map((item, idx) => (
              <div
                key={idx}
                onMouseEnter={() => setHoveredBar(idx)}
                onMouseLeave={() => setHoveredBar(null)}
                className="flex-1 flex flex-col items-center h-full justify-end group cursor-pointer relative"
              >
                {/* Tooltip on Hover */}
                {hoveredBar === idx && (
                  <div className="absolute -top-8 px-2 py-1 rounded bg-[#060D19] border border-cyan-500/40 text-[10px] font-mono text-cyan-300 shadow-xl z-20 whitespace-nowrap">
                    {item.count} Scans ({item.day})
                  </div>
                )}

                {/* Animated Bar */}
                <div className="w-full max-w-[36px] bg-slate-800/60 rounded-t-lg overflow-hidden flex items-end h-full">
                  <div
                    className="w-full bg-gradient-to-t from-cyan-500 via-sky-400 to-purple-500 rounded-t-lg transition-all duration-700 group-hover:brightness-125"
                    style={{ height: item.height }}
                  />
                </div>

                <span className="text-[11px] font-mono text-slate-400 mt-2">
                  {item.day}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="pt-3 flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span>Inspection Volume Range: 0 - 15 Files/Day</span>
          <span className="text-cyan-400">7-Day Aggregation</span>
        </div>

      </div>

      {/* Chart 2: Threat Distribution Breakdown (5 Columns) */}
      <div id="threat-distribution" className="lg:col-span-5 rounded-2xl glass-panel p-6 border border-purple-500/20 shadow-xl flex flex-col justify-between">
        
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-400">
                <PieChart className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white font-display">
                  Threat Pattern Breakdown
                </h3>
                <p className="text-[11px] font-mono text-slate-400">
                  Distribution of flagged indicators
                </p>
              </div>
            </div>

            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#091526] border border-white/[0.08] text-purple-300">
              {hasData ? "Demo Indicators" : "Baseline"}
            </span>
          </div>

          {/* Category Progress Bars */}
          <div className="space-y-4 pt-2">
            {categories.map((cat, idx) => (
              <div key={idx} className="space-y-1.5">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-slate-300 flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${cat.color}`} />
                    {cat.label}
                  </span>
                  <span className="text-slate-200 font-bold">{cat.percentage}%</span>
                </div>
                <div className="w-full h-1.5 rounded-full bg-slate-800/80 overflow-hidden">
                  <div
                    className={`h-full ${cat.color} rounded-full transition-all duration-700`}
                    style={{ width: `${cat.percentage}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="pt-4 border-t border-white/[0.06] mt-4 flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span>ClamAV + Random Forest Feature Model</span>
          <span className="text-purple-300">Planned Integration</span>
        </div>

      </div>

    </div>
  );
}

