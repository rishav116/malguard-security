"use client";

import React, { useState } from "react";
import FadeInSection from "./FadeInSection";
import { 
  Binary, 
  Sparkles, 
  FileText, 
  ShieldAlert, 
  Cpu, 
  CheckCircle, 
  AlertTriangle, 
  ChevronRight, 
  ExternalLink,
  Code2,
  Network,
  Lock,
  Layers
} from "lucide-react";

export default function FeatureCards() {
  const [activeTabCard2, setActiveTabCard2] = useState<"analysis" | "mitigation">("analysis");

  return (
    <section id="features" className="relative py-24 sm:py-32 overflow-hidden">
      {/* Background radial glow with GPU promotion */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[400px] bg-gradient-to-r from-cyan-500/10 via-purple-600/10 to-transparent blur-[140px] pointer-events-none -z-10 gpu-halo" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 sm:mb-20">
          <FadeInSection direction="down" delay={0.05}>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full glass-panel border border-cyan-400/25 text-xs font-mono text-cyan-300 mb-4">
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              <span>CORE CAPABILITIES</span>
            </div>
          </FadeInSection>
          <FadeInSection direction="up" delay={0.12} distance={24} scale={0.98}>
            <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold text-white tracking-tight leading-[1.2]">
              Engineered for Precision. <br />
              <span className="text-gradient-cyan">Powered by Next-Gen AI.</span>
            </h2>
          </FadeInSection>
          <FadeInSection direction="up" delay={0.2} distance={20}>
            <p className="mt-4 text-base sm:text-lg text-slate-300">
              A tripartite defense architecture combining Random Forest ML classification, 
              ClamAV signature scanning, and Malix-powered explanations.
            </p>
          </FadeInSection>
        </div>

        {/* 3 Animated Feature Cards */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

          {/* CARD 1: AI Malware Detection */}
          <FadeInSection direction="up" delay={0.1} scale={0.97} distance={36} className="h-full flex flex-col">
            <div className="group relative rounded-2xl p-[1px] transition-all duration-300 hover:-translate-y-1.5 flex flex-col h-full">
              {/* Gradient border on hover */}
              <div className="absolute inset-0 rounded-2xl bg-gradient-to-b from-cyan-500/40 via-cyan-500/10 to-transparent opacity-60 group-hover:opacity-100 transition-opacity blur-[1px]" />
              
              <div className="relative flex-1 rounded-2xl bg-[#091322]/95 backdrop-blur-sm p-4 xs:p-6 sm:p-8 flex flex-col justify-between border border-cyan-500/20 group-hover:border-cyan-400/40 transition-colors transform-gpu">
                
                <div>
                  {/* Top Icon & Badge */}
                  <div className="flex items-center justify-between mb-6">
                    <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.25)] group-hover:scale-110 transition-transform">
                      <Binary className="w-6 h-6" />
                    </div>
                    <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-300">
                      ML & Signatures
                    </span>
                  </div>

                  <h3 className="text-xl sm:text-2xl font-bold text-white mb-3 group-hover:text-cyan-300 transition-colors">
                    AI Malware Detection
                  </h3>
                  <p className="text-sm text-slate-300/90 leading-relaxed mb-6">
                    Static PE structure inspection combining Random Forest machine learning classification 
                    and ClamAV signature matching to identify suspicious code patterns and packed binaries.
                  </p>
                </div>

                {/* Interactive Micro Visualization: Shannon Entropy & Section Scanner */}
                <div className="rounded-xl bg-[#060D19]/90 border border-cyan-500/20 p-4 font-mono text-xs text-slate-300 space-y-3">
                  <div className="flex items-center justify-between border-b border-white/[0.08] pb-2 text-xs text-slate-400">
                    <span className="flex items-center gap-1.5 text-cyan-400">
                      <Code2 className="w-3.5 h-3.5" /> PE Section Dissector
                    </span>
                    <span className="text-cyan-400 text-[11px] font-medium">Illustrative Demo</span>
                  </div>

                  {/* Section 1: .text */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-300 font-semibold">.text [Exec Code]</span>
                      <span className="text-cyan-300">6.34 / 8.0</span>
                    </div>
                    <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div className="h-full bg-cyan-400 rounded-full w-[72%]" />
                    </div>
                  </div>

                  {/* Section 2: .rdata (Packed/Encrypted warning) */}
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-amber-300 flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3 text-amber-400" />
                        .rsrc [High Entropy]
                      </span>
                      <span className="text-amber-400 font-bold">7.89 / 8.0</span>
                    </div>
                    <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div className="h-full bg-amber-400 rounded-full w-[94%] animate-pulse" />
                    </div>
                  </div>

                  <div className="pt-1 flex items-center justify-between text-[11px] text-slate-400">
                    <span>Import Table: <span className="text-cyan-300">VirtualAlloc, MemProtect</span></span>
                    <span className="text-rose-400 font-bold">Flagged</span>
                  </div>
                </div>

                <div className="mt-6 pt-4 border-t border-white/[0.06] flex items-center justify-between text-xs text-cyan-400 font-medium">
                  <span>PE Static & Random Forest ML (Live Engine)</span>
                  <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </div>

              </div>
            </div>
          </FadeInSection>

          {/* CARD 2: Malix AI Assistant */}
          <FadeInSection direction="up" delay={0.22} scale={0.97} distance={36} className="h-full flex flex-col">
            <div className="group relative rounded-2xl p-[1px] transition-all duration-300 hover:-translate-y-1.5 flex flex-col h-full">
              {/* Gradient border on hover */}
              <div className="absolute inset-0 rounded-2xl bg-gradient-to-b from-purple-500/40 via-purple-500/10 to-transparent opacity-60 group-hover:opacity-100 transition-opacity blur-[1px]" />
              
              <div className="relative flex-1 rounded-2xl bg-[#091322]/95 backdrop-blur-sm p-4 xs:p-6 sm:p-8 flex flex-col justify-between border border-purple-500/20 group-hover:border-purple-400/40 transition-colors transform-gpu">
                
                <div>
                  {/* Top Icon & Badge */}
                  <div className="flex items-center justify-between mb-6">
                    <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-400/30 flex items-center justify-center text-purple-400 shadow-[0_0_15px_rgba(139,92,246,0.25)] group-hover:scale-110 transition-transform">
                      <Sparkles className="w-6 h-6" />
                    </div>
                    <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-purple-950/60 border border-purple-500/30 text-purple-300">
                      Security Assistant
                    </span>
                  </div>

                  <h3 className="text-xl sm:text-2xl font-bold text-white mb-3 group-hover:text-purple-300 transition-colors">
                    Malix AI Assistant
                  </h3>
                  <p className="text-sm text-slate-300/90 leading-relaxed mb-6">
                    Translates static PE analysis and low-level code anomalies into clear, 
                    human-readable explanations. Provides interactive threat summaries and mitigation guidance.
                  </p>
                </div>

                {/* Interactive Micro Visualization: Malix Copilot Output */}
                <div className="rounded-xl bg-[#060D19]/90 border border-purple-500/25 p-4 font-mono text-xs space-y-3">
                  <div className="flex items-center justify-between border-b border-white/[0.08] pb-2 text-xs">
                    <div className="flex items-center gap-1.5 text-purple-300 font-semibold">
                      <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                      Malix AI Security Assistant
                    </div>
                    <div className="flex gap-1 text-[11px]">
                      <button
                        onClick={() => setActiveTabCard2("analysis")}
                        className={`px-1.5 py-0.5 rounded ${activeTabCard2 === "analysis" ? "bg-purple-500/20 text-purple-300 border border-purple-500/40" : "text-slate-400"}`}
                      >
                        Intent
                      </button>
                      <button
                        onClick={() => setActiveTabCard2("mitigation")}
                        className={`px-1.5 py-0.5 rounded ${activeTabCard2 === "mitigation" ? "bg-purple-500/20 text-purple-300 border border-purple-500/40" : "text-slate-400"}`}
                      >
                        Remedy
                      </button>
                    </div>
                  </div>

                  {activeTabCard2 === "analysis" ? (
                    <div className="space-y-2 text-xs text-slate-300 leading-relaxed font-sans">
                      <p className="text-purple-200">
                        <strong className="text-white">Demonstration Assessment:</strong> High entropy (.rsrc) and memory allocation imports suggest packed code intended to mask payload behavior before in-memory execution.
                      </p>
                      <div className="p-2 rounded bg-purple-950/40 border border-purple-500/20 text-purple-300 text-[11px] font-mono">
                        Illustrative Demo | Risk Classification: Suspicious
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-2 text-xs text-slate-300 leading-relaxed font-sans">
                      <p className="text-slate-300">
                        <strong className="text-emerald-400">Remediation Guidance:</strong> Quarantine the suspicious binary, inspect process creation logs, and block unverified executable paths.
                      </p>
                      <div className="p-2 rounded bg-emerald-950/40 border border-emerald-500/20 text-emerald-300 text-[11px] font-mono flex items-center gap-1">
                        <CheckCircle className="w-3 h-3 text-emerald-400" /> Illustrative Remediation Advice
                      </div>
                    </div>
                  )}
                </div>

                <div className="mt-6 pt-4 border-t border-white/[0.06] flex items-center justify-between text-xs text-purple-400 font-medium">
                  <span>Malix Security AI (Live Assistant)</span>
                  <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </div>

              </div>
            </div>
          </FadeInSection>

          {/* CARD 3: Threat Reports */}
          <FadeInSection direction="up" delay={0.34} scale={0.97} distance={36} className="h-full flex flex-col">
            <div className="group relative rounded-2xl p-[1px] transition-all duration-300 hover:-translate-y-1.5 flex flex-col h-full">
              {/* Gradient border on hover */}
              <div className="absolute inset-0 rounded-2xl bg-gradient-to-b from-cyan-500/30 via-purple-500/20 to-transparent opacity-60 group-hover:opacity-100 transition-opacity blur-[1px]" />
              
              <div className="relative flex-1 rounded-2xl bg-[#091322]/95 backdrop-blur-sm p-4 xs:p-6 sm:p-8 flex flex-col justify-between border border-cyan-500/20 group-hover:border-cyan-400/40 transition-colors transform-gpu">
                
                <div>
                  {/* Top Icon & Badge */}
                  <div className="flex items-center justify-between mb-6">
                    <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/10 to-purple-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-300 shadow-[0_0_15px_rgba(34,211,238,0.25)] group-hover:scale-110 transition-transform">
                      <FileText className="w-6 h-6" />
                    </div>
                    <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-slate-900 border border-slate-700 text-slate-300">
                      Threat Reports
                    </span>
                  </div>

                  <h3 className="text-xl sm:text-2xl font-bold text-white mb-3 group-hover:text-cyan-300 transition-colors">
                    Threat Reports
                  </h3>
                  <p className="text-sm text-slate-300/90 leading-relaxed mb-6">
                    Transforms scan findings into structured threat summaries. Organizes identified 
                    suspicious behaviors, extracted Indicators of Compromise (IOCs), and exportable reports.
                  </p>
                </div>

                {/* Interactive Micro Visualization: Pattern Indicators & IOC List */}
                <div className="rounded-xl bg-[#060D19]/90 border border-cyan-500/20 p-4 font-mono text-xs space-y-3">
                  <div className="flex items-center justify-between border-b border-white/[0.08] pb-2 text-xs">
                    <span className="flex items-center gap-1.5 text-cyan-300 font-semibold">
                      <Network className="w-3.5 h-3.5 text-cyan-400" />
                      Suspicious Indicators
                    </span>
                    <span className="text-[11px] text-purple-300">Illustrative Demo</span>
                  </div>

                  {/* Indicators Tags */}
                  <div className="flex flex-wrap gap-1.5">
                    <span className="px-2 py-0.5 rounded bg-rose-500/15 border border-rose-500/30 text-rose-300 text-[11px] font-medium">
                      Suspicious Import Hook
                    </span>
                    <span className="px-2 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-300 text-[11px] font-medium">
                      Obfuscated Section
                    </span>
                    <span className="px-2 py-0.5 rounded bg-purple-500/15 border border-purple-500/30 text-purple-300 text-[11px] font-medium">
                      High Shannon Entropy
                    </span>
                  </div>

                  {/* Extracted IOC preview */}
                  <div className="space-y-1 pt-1 text-[11px] text-slate-400">
                    <div className="flex justify-between">
                      <span>SHA-256:</span>
                      <span className="text-slate-300">7b38d...9fa2</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Artifact Status:</span>
                      <span className="text-amber-400 font-bold">Flagged for Review</span>
                    </div>
                  </div>
                </div>

                <div className="mt-6 pt-4 border-t border-white/[0.06] flex items-center justify-between text-xs text-cyan-400 font-medium">
                  <span>Structured Threat Reports (Live Database)</span>
                  <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </div>

              </div>
            </div>
          </FadeInSection>

        </div>

      </div>
    </section>
  );
}
