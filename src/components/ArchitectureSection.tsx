"use client";

import React, { useState } from "react";
import FadeInSection from "./FadeInSection";
import { 
  Sparkles, 
  Terminal, 
  ShieldCheck, 
  Lock, 
  Cpu, 
  FileCheck2, 
  Share2, 
  Download, 
  Code,
  Network,
  Activity,
  Layers,
  Check
} from "lucide-react";

export default function ArchitectureSection({ onOpenScanModal }: { onOpenScanModal: () => void }) {
  const [activeTab, setActiveTab] = useState<"malix" | "sandbox" | "mitre">("malix");

  return (
    <section id="architecture" className="relative py-24 sm:py-32 overflow-hidden">
      {/* Background radial gradient with GPU compositing */}
      <div className="absolute top-1/2 right-1/4 w-[600px] h-[500px] bg-purple-600/10 blur-[130px] pointer-events-none -z-10 gpu-halo" />
      <div className="absolute bottom-10 left-1/4 w-[500px] h-[400px] bg-cyan-500/10 blur-[120px] pointer-events-none -z-10 gpu-halo" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 sm:mb-20">
          <FadeInSection direction="down" delay={0.05}>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full glass-panel border border-cyan-400/25 text-xs font-mono text-cyan-300 mb-4">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>AI COGNITIVE ARCHITECTURE</span>
            </div>
          </FadeInSection>
          <FadeInSection direction="up" delay={0.12} distance={24} scale={0.98}>
            <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold text-white tracking-tight leading-[1.2]">
              Malix AI Security Assistant
            </h2>
          </FadeInSection>
          <FadeInSection direction="up" delay={0.2} distance={20}>
            <p className="mt-4 text-base sm:text-lg text-slate-300">
              Designed to bridge deterministic signature scanning and machine learning with generative AI, 
              MALGUARD AI combines Random Forest ML classification and ClamAV signatures with Malix AI to generate plain-English security explanations.
            </p>
          </FadeInSection>
        </div>

        {/* Tab Selector */}
        <FadeInSection direction="up" delay={0.24} scale={0.98} distance={20} className="flex justify-center mb-10 w-full">
          <div className="glass-panel p-1 rounded-xl flex flex-col sm:flex-row gap-1 border border-white/[0.08] w-full sm:w-auto">
            <button
              onClick={() => setActiveTab("malix")}
              className={`px-4 py-2.5 rounded-lg text-xs sm:text-sm font-medium transition-all text-center min-h-[44px] flex items-center justify-center cursor-pointer ${
                activeTab === "malix"
                  ? "bg-gradient-to-r from-cyan-500 to-purple-600 text-slate-950 font-bold shadow-[0_0_15px_rgba(34,211,238,0.3)]"
                  : "text-slate-400 hover:text-white hover:bg-white/[0.04]"
              }`}
            >
              Malix Security Assistant
            </button>
            <button
              onClick={() => setActiveTab("sandbox")}
              className={`px-4 py-2.5 rounded-lg text-xs sm:text-sm font-medium transition-all text-center min-h-[44px] flex items-center justify-center cursor-pointer ${
                activeTab === "sandbox"
                  ? "bg-gradient-to-r from-cyan-500 to-purple-600 text-slate-950 font-bold shadow-[0_0_15px_rgba(34,211,238,0.3)]"
                  : "text-slate-400 hover:text-white hover:bg-white/[0.04]"
              }`}
            >
              Secure File Handling
            </button>
            <button
              onClick={() => setActiveTab("mitre")}
              className={`px-4 py-2.5 rounded-lg text-xs sm:text-sm font-medium transition-all text-center min-h-[44px] flex items-center justify-center cursor-pointer ${
                activeTab === "mitre"
                  ? "bg-gradient-to-r from-cyan-500 to-purple-600 text-slate-950 font-bold shadow-[0_0_15px_rgba(34,211,238,0.3)]"
                  : "text-slate-400 hover:text-white hover:bg-white/[0.04]"
              }`}
            >
              Threat Intelligence & Audit
            </button>
          </div>
        </FadeInSection>

        {/* Dynamic Interactive Panel */}
        <FadeInSection direction="up" delay={0.3} scale={0.97} distance={32}>
          <div className="rounded-2xl sm:rounded-3xl glass-panel p-4 xs:p-6 sm:p-10 border border-cyan-500/20 shadow-[0_4px_40px_rgba(0,0,0,0.6)]">
          
          {activeTab === "malix" && (
            <div id="malix-ai" className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center animate-in fade-in duration-300">
              <div className="lg:col-span-6 space-y-6">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded bg-purple-950/60 border border-purple-500/30 text-xs font-mono text-purple-300">
                  <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                  Malix AI Security Assistant
                </div>
                <h3 className="text-2xl sm:text-3xl font-bold text-white">
                  AI-Powered Static Malware Analysis
                </h3>
                <p className="text-sm sm:text-base text-slate-300 leading-relaxed">
                  Traditional antivirus tools often return cryptic alerts like <code className="text-cyan-300 bg-slate-900 px-1.5 py-0.5 rounded text-xs font-mono">Win32.Heur.Gen!c2</code>. 
                  MALGUARD AI integrates the Malix AI Security Assistant to produce clear, conversational explanations of suspicious file attributes, entropy flags, and potential risks.
                </p>

                <div className="space-y-3 font-mono text-xs text-slate-300">
                  <div className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span>Plain-English explanations of static PE characteristics and anomalies</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span>Contextual risk interpretation based on extracted file metadata</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-cyan-400 shrink-0" />
                    <span>Plain-language mitigation suggestions and defensive guidance</span>
                  </div>
                </div>

                <div className="pt-2">
                  <button
                    onClick={onOpenScanModal}
                    className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-400 to-purple-500 text-slate-950 font-bold text-sm shadow-[0_0_20px_rgba(34,211,238,0.3)] hover:shadow-[0_0_25px_rgba(34,211,238,0.5)] hover:brightness-110 active:scale-[0.99] transition-all cursor-pointer"
                  >
                    Explore Interactive Demo
                  </button>
                </div>
              </div>

              {/* Malix Chat Visual Mockup */}
              <div className="lg:col-span-6">
                <div className="rounded-2xl bg-[#040810] border border-purple-500/30 p-5 font-mono text-xs space-y-4 shadow-2xl">
                  <div className="flex items-center justify-between border-b border-white/[0.08] pb-3 text-slate-400 text-xs font-mono">
                    <span className="flex items-center gap-2 text-purple-300 font-semibold">
                      <Sparkles className="w-4 h-4 text-purple-400" />
                      Malix Assistant (Illustrative Demo)
                    </span>
                    <span className="text-cyan-400 text-[11px] font-medium">● Illustrative Demo</span>
                  </div>

                  {/* User query */}
                  <div className="p-3 rounded-xl bg-[#0A1220] border border-white/[0.06] text-slate-300 text-xs">
                    <span className="text-cyan-400 font-bold block mb-1">Analyst Query:</span>
                    &quot;What do the high entropy in .rsrc and the flagged VirtualAlloc import indicate?&quot;
                  </div>

                  {/* Malix response */}
                  <div className="p-4 rounded-xl bg-purple-950/30 border border-purple-500/30 text-xs space-y-2 text-slate-200 font-sans">
                    <span className="text-purple-300 font-bold flex items-center gap-1.5 font-mono">
                      <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                      Malix Threat Assessment:
                    </span>
                    <p className="leading-relaxed">
                      &quot;The <code className="text-cyan-300 font-mono">.rsrc</code> section exhibits high Shannon entropy (7.89), suggesting a compressed or obfuscated payload. Combined with memory allocation imports, this pattern commonly indicates a staged binary attempting to evade static detection before unpacking in memory.&quot;
                    </p>
                    <div className="pt-2 text-xs text-emerald-400 font-semibold">
                      → Recommended action: Inspect child process spawning and quarantine the suspicious artifact.
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "sandbox" && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center animate-in fade-in duration-300">
              <div className="lg:col-span-6 space-y-6">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded bg-cyan-950/60 border border-cyan-500/30 text-xs font-mono text-cyan-300">
                  <Lock className="w-3.5 h-3.5 text-cyan-400" />
                  Secure Handling Architecture
                </div>
                <h3 className="text-2xl sm:text-3xl font-bold text-white">
                  Isolated File Processing
                </h3>
                <p className="text-sm sm:text-base text-slate-300 leading-relaxed">
                  Security and confidentiality are fundamental. MALGUARD AI is architected with strict, 
                  isolated file processing routines designed to inspect uploaded artifacts safely without 
                  persistent storage or unauthorized external exposure.
                </p>

                <div className="grid grid-cols-2 gap-4 pt-2">
                  <div className="p-4 rounded-xl bg-[#091526] border border-cyan-500/20">
                    <div className="text-cyan-400 font-bold text-lg font-mono">Isolated</div>
                    <div className="text-xs text-slate-400 mt-1">Controlled processing environment</div>
                  </div>
                  <div className="p-4 rounded-xl bg-[#091526] border border-cyan-500/20">
                    <div className="text-purple-400 font-bold text-lg font-mono">SHA-256</div>
                    <div className="text-xs text-slate-400 mt-1">Cryptographic file identification</div>
                  </div>
                </div>
              </div>

              <div className="lg:col-span-6">
                <div className="rounded-2xl bg-[#040810] border border-cyan-500/30 p-6 font-mono text-xs space-y-4 shadow-2xl">
                  <div className="flex items-center justify-between border-b border-white/[0.08] pb-3 text-slate-400 text-xs">
                    <span className="text-cyan-400 font-semibold">FILE HANDLING SPECIFICATION</span>
                    <span className="text-cyan-300">ACTIVE PROTOCOL</span>
                  </div>
                  <div className="space-y-2 text-slate-300">
                    <div className="flex items-center justify-between">
                      <span>Memory Buffer:</span>
                      <span className="text-cyan-300">Controlled Allocation</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>External Sockets:</span>
                      <span className="text-emerald-400">Restricted Access</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Disk Access:</span>
                      <span className="text-emerald-400">Ephemeral Quarantine</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Post-Analysis:</span>
                      <span className="text-purple-300">Scheduled Cleanup</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "mitre" && (
            <div id="threat-reports" className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center animate-in fade-in duration-300">
              <div className="lg:col-span-6 space-y-6">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded bg-rose-950/60 border border-rose-500/30 text-xs font-mono text-rose-300">
                  <Network className="w-3.5 h-3.5 text-rose-400" />
                  Threat Intelligence & Reporting
                </div>
                <h3 className="text-2xl sm:text-3xl font-bold text-white">
                  Suspicious Pattern Detection & Reporting
                </h3>
                <p className="text-sm sm:text-base text-slate-300 leading-relaxed">
                  Capabilities include organizing flagged static indicators into structured threat summaries, 
                  helping security analysts understand potential tactics and export Indicators of Compromise (IOCs) for review.
                </p>

                <div className="flex flex-wrap gap-2">
                  <span className="px-3 py-1 rounded-full bg-[#0A1628] border border-cyan-500/30 text-cyan-300 text-xs font-mono">
                    Suspicious Import Analysis
                  </span>
                  <span className="px-3 py-1 rounded-full bg-[#0A1628] border border-purple-500/30 text-purple-300 text-xs font-mono">
                    Obfuscated File Structure
                  </span>
                  <span className="px-3 py-1 rounded-full bg-[#0A1628] border border-rose-500/30 text-rose-300 text-xs font-mono">
                    Section Entropy Flags
                  </span>
                  <span className="px-3 py-1 rounded-full bg-[#0A1628] border border-amber-500/30 text-amber-300 text-xs font-mono">
                    ClamAV Signature Matches
                  </span>
                </div>
              </div>

              <div className="lg:col-span-6">
                <div className="rounded-2xl bg-[#040810] border border-slate-700 p-5 font-mono text-xs space-y-3 shadow-2xl">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-white/[0.08] pb-3 text-slate-400 text-xs gap-1">
                    <span className="text-slate-200 font-semibold truncate">IOC THREAT FEED (ILLUSTRATIVE DEMO)</span>
                    <span className="text-cyan-400 shrink-0">JSON FORMAT</span>
                  </div>
                  <pre className="text-cyan-300/90 text-xs leading-relaxed overflow-x-auto p-2 bg-[#060D19] rounded-lg">
{`{
  "report_id": "DEMO-2026-X89",
  "verdict": "SUSPICIOUS",
  "engine_matches": {
    "clamav": "Win.Trojan.Generic-99",
    "ml_classifier": "High_Risk_Entropy"
  },
  "flagged_indicators": ["High_Entropy_rsrc", "VirtualAlloc_Import"],
  "remediation_status": "GUIDANCE_GENERATED"
}`}
                  </pre>
                </div>
              </div>
            </div>
          )}

        </div>
        </FadeInSection>

      </div>
    </section>
  );
}
