"use client";

import React, { useState } from "react";
import FadeInSection from "./FadeInSection";
import { 
  UploadCloud, 
  Cpu, 
  ShieldAlert, 
  ArrowRight, 
  CheckCircle2, 
  Lock, 
  Binary, 
  Sparkles, 
  FileCheck,
  Zap,
  Activity,
  Layers
} from "lucide-react";

export default function WorkflowSection() {
  const [selectedStep, setSelectedStep] = useState<number>(1);

  const steps = [
    {
      id: 1,
      title: "Upload",
      tagline: "Client-Side Ingestion & Hashing",
      icon: UploadCloud,
      color: "from-cyan-500 to-blue-500",
      accentBorder: "border-cyan-500/40",
      accentGlow: "shadow-[0_0_20px_rgba(34,211,238,0.3)]",
      badgeText: "Step 01",
      description:
        "The target binary or document is hashed and handled through secure, isolated file processing routines designed to protect system integrity during inspection.",
      specs: [
        "Cryptographic SHA-256 Hashing",
        "MIME & File Structure Verification",
        "Secure Isolated Processing",
      ],
      terminalSnippet: `[INGEST] File: sample_artifact.bin\n[HASH] SHA256: 9b2d8e411b0e27f6a7...\n[STATUS] Assigned to isolated inspection queue`,
    },
    {
      id: 2,
      title: "Analyze",
      tagline: "Static Inspection & Dual Engine",
      icon: Cpu,
      color: "from-purple-500 to-indigo-500",
      accentBorder: "border-purple-500/40",
      accentGlow: "shadow-[0_0_20px_rgba(139,92,246,0.3)]",
      badgeText: "Step 02",
      description:
        "The active pipeline conducts static PE inspection, scans with ClamAV signatures, evaluates feature vectors using Random Forest ML classification, and generates Malix-powered explanations.",
      specs: [
        "ClamAV Known Signature Detection",
        "Random Forest ML Classification",
        "Malix AI Security Assistant",
      ],
      terminalSnippet: `[SCAN] Running ClamAV Signatures & ML Model\n[FEATURES] PE Section Entropy & Import Analysis\n[MALIX] Generating plain-English threat summary...`,
    },
    {
      id: 3,
      title: "Results",
      tagline: "Risk Verdict & Threat Summary",
      icon: ShieldAlert,
      color: "from-emerald-400 to-cyan-500",
      accentBorder: "border-emerald-500/40",
      accentGlow: "shadow-[0_0_20px_rgba(52,211,153,0.3)]",
      badgeText: "Step 03",
      description:
        "Delivers a clear risk classification score, highlights identified suspicious pattern indicators, and provides actionable, plain-English guidance from the Malix AI Security Assistant.",
      specs: [
        "Plain-English Threat Summary by Malix",
        "Suspicious Pattern Identification",
        "Recommended Remediation Guidance",
      ],
      terminalSnippet: `[VERDICT] SUSPICIOUS (Confidence: High)\n[INDICATOR] High Entropy & Suspicious Imports\n[GUIDANCE] Quarantine artifact & review host logs`,
    },
  ];

  return (
    <section id="workflow" className="relative py-24 sm:py-32 bg-[#060D19]/60 border-y border-white/[0.04] overflow-hidden">
      {/* Background cyber grid */}
      <div className="absolute inset-0 cyber-grid opacity-30 pointer-events-none" />

      {/* Radial soft glow with GPU compositing */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[700px] h-[350px] bg-gradient-to-b from-purple-600/10 via-cyan-500/10 to-transparent blur-[120px] pointer-events-none gpu-halo" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Heading */}
        <div className="text-center max-w-3xl mx-auto mb-16 sm:mb-20">
          <FadeInSection direction="down" delay={0.05}>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full glass-panel border border-purple-400/25 text-xs font-mono text-purple-300 mb-4">
              <Activity className="w-3.5 h-3.5 text-purple-400" />
              <span>DETECTION PIPELINE</span>
            </div>
          </FadeInSection>
          <FadeInSection direction="up" delay={0.12} distance={24} scale={0.98}>
            <h2 className="text-3xl sm:text-4xl md:text-5xl font-bold text-white tracking-tight leading-[1.2]">
              How MALGUARD AI Works
            </h2>
          </FadeInSection>
          <FadeInSection direction="up" delay={0.2} distance={20}>
            <p className="mt-4 text-base sm:text-lg text-slate-300">
              A structured three-stage pipeline designed for rapid file intake, 
              machine learning analysis, and Malix-powered threat explanation.
            </p>
          </FadeInSection>
        </div>

        {/* 3 Step Interactive Workflow Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 lg:gap-8 mb-12">
          {steps.map((step, idx) => {
            const Icon = step.icon;
            const isSelected = selectedStep === step.id;

            return (
              <FadeInSection
                key={step.id}
                direction="up"
                delay={0.1 + 0.14 * idx}
                scale={0.97}
                distance={36}
                className="h-full flex flex-col"
              >
                <div
                  onClick={() => setSelectedStep(step.id)}
                  className={`cursor-pointer relative rounded-2xl p-[1px] transition-all duration-300 h-full flex flex-col ${
                    isSelected ? "-translate-y-1 shadow-[0_12px_30px_rgba(0,0,0,0.5)]" : "hover:-translate-y-0.5 opacity-80 hover:opacity-100"
                  }`}
                >
                  {/* Active glow / border */}
                  <div
                    className={`absolute inset-0 rounded-2xl bg-gradient-to-r ${step.color} ${
                      isSelected ? "opacity-100 blur-[2px]" : "opacity-20 hover:opacity-40"
                    } transition-opacity`}
                  />

                  <div className="relative h-full rounded-2xl bg-[#091322] p-6 sm:p-7 flex flex-col justify-between border border-white/[0.08] flex-1">
                    
                    {/* Step Header */}
                    <div>
                      <div className="flex items-center justify-between mb-4">
                        <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300">
                          {step.badgeText}
                        </span>
                        <div
                          className={`w-10 h-10 rounded-xl bg-gradient-to-br ${step.color} p-[1px] flex items-center justify-center`}
                        >
                          <div className="w-full h-full rounded-xl bg-[#071120] flex items-center justify-center text-white">
                            <Icon className="w-5 h-5 text-cyan-300" />
                          </div>
                        </div>
                      </div>

                      <h3 className="text-2xl font-bold text-white mb-1 flex items-center gap-2">
                        {step.title}
                      </h3>
                      <p className="text-xs font-mono text-cyan-300/80 mb-4">
                        {step.tagline}
                      </p>

                      <p className="text-sm text-slate-300 leading-relaxed mb-6">
                        {step.description}
                      </p>
                    </div>

                    {/* Bullet points */}
                    <div className="space-y-2 pt-4 border-t border-white/[0.06]">
                      {step.specs.map((spec, sIdx) => (
                        <div key={sIdx} className="flex items-center gap-2 text-xs text-slate-300 font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                          <span>{spec}</span>
                        </div>
                      ))}
                    </div>

                    {/* Step indicator footer */}
                    <div className="mt-6 pt-3 flex items-center justify-between text-xs font-mono">
                      <span className={isSelected ? "text-cyan-400 font-bold" : "text-slate-500"}>
                        {isSelected ? "● ACTIVE VIEW" : "Click to inspect"}
                      </span>
                      <ArrowRight className={`w-4 h-4 ${isSelected ? "text-cyan-400 translate-x-1" : "text-slate-600"} transition-transform`} />
                    </div>

                  </div>
                </div>
              </FadeInSection>
            );
          })}
        </div>

        {/* Dynamic Detail Console for the Selected Step */}
        <FadeInSection direction="up" delay={0.25} scale={0.98} distance={28}>
          <div className="rounded-2xl glass-panel p-4 xs:p-6 sm:p-8 border border-cyan-500/25 shadow-[0_4px_30px_rgba(0,0,0,0.4)]">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
              
              {/* Left explanation */}
              <div className="lg:col-span-6 space-y-4">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded bg-cyan-950/60 border border-cyan-500/30 text-xs font-mono text-cyan-300">
                  <span>STAGE {selectedStep} PIPELINE TRACE</span>
                </div>
                <h4 className="text-2xl font-bold text-white">
                  {steps[selectedStep - 1].title}: {steps[selectedStep - 1].tagline}
                </h4>
                <p className="text-sm text-slate-300 leading-relaxed">
                  {steps[selectedStep - 1].description}
                </p>
                
                <div className="flex flex-wrap gap-2 pt-2">
                  {steps[selectedStep - 1].specs.map((item, idx) => (
                    <span
                      key={idx}
                      className="text-xs font-mono px-2.5 py-1 rounded bg-[#071120] border border-cyan-500/20 text-slate-300"
                    >
                      ✓ {item}
                    </span>
                  ))}
                </div>
              </div>

              {/* Right Interactive Code / Terminal View */}
              <div className="lg:col-span-6">
                <div className="rounded-xl bg-[#040810] border border-slate-700/80 p-4 font-mono text-xs shadow-2xl">
                  {/* Window header */}
                  <div className="flex items-center justify-between pb-3 mb-3 border-b border-white/[0.08] text-slate-400 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80 inline-block" />
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block" />
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" />
                      <span className="ml-2 text-slate-300 font-semibold">malguard-pipeline://trace</span>
                    </div>
                    <span className="text-cyan-400 text-[11px] font-medium">PIPELINE PREVIEW</span>
                  </div>

                  {/* Console Output */}
                  <pre className="text-cyan-300/90 whitespace-pre-wrap break-all leading-relaxed">
                    {steps[selectedStep - 1].terminalSnippet}
                  </pre>
                </div>
              </div>

            </div>
          </div>
        </FadeInSection>

      </div>
    </section>
  );
}
