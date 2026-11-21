"use client";

import React from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/context/AuthContext";
import { Shield, Sparkles, ArrowRight, Binary, FileSearch, ShieldCheck, Terminal, Cpu, Network, Lock, Zap } from "lucide-react";
import CyberShield from "./CyberShield";
import FadeInSection from "./FadeInSection";

interface HeroProps {
  onOpenScanModal: () => void;
}

export default function Hero({ onOpenScanModal }: HeroProps) {
  const router = useRouter();
  const { user } = useAuth();

  const handleScanClick = () => {
    if (!user) {
      router.push("/login?redirectTo=/scanner");
    } else {
      onOpenScanModal();
    }
  };

  return (
    <section className="relative min-h-[92vh] pt-32 pb-16 flex flex-col justify-center overflow-hidden">
      {/* Subtle Futuristic Cybersecurity Hero Grid */}
      <div 
        className="absolute inset-0 hero-cyber-grid pointer-events-none -z-10" 
        aria-hidden="true" 
      />

      {/* Background radial gradient halos with GPU compositing */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] sm:w-[900px] h-[500px] bg-gradient-to-b from-cyan-500/10 via-purple-600/15 to-transparent blur-[120px] pointer-events-none -z-10 gpu-halo" />
      <div className="absolute bottom-10 left-10 w-[300px] h-[300px] bg-cyan-600/5 blur-[90px] pointer-events-none -z-10 gpu-halo" />
      <div className="absolute top-20 right-10 w-[350px] h-[350px] bg-purple-600/10 blur-[100px] pointer-events-none -z-10 gpu-halo" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-8 items-center">
          
          {/* Left Column: Headline, Description & CTAs */}
          <div className="lg:col-span-7 flex flex-col items-start text-left z-10">
            
            {/* Top Pill / Badge */}
            <FadeInSection direction="down" delay={0.05} distance={16}>
              <div className="inline-flex items-center gap-1.5 xs:gap-2 px-3 py-1.5 rounded-full glass-panel border border-cyan-400/30 text-[11px] xs:text-xs font-mono text-cyan-300 shadow-[0_0_15px_rgba(34,211,238,0.15)] mb-6 max-w-full flex-wrap sm:flex-nowrap">
                <span className="flex h-2 w-2 relative shrink-0">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
                </span>
                <span className="tracking-wide uppercase font-semibold">Active Detection Engine</span>
                <span className="text-slate-500 hidden xs:inline">|</span>
                <span className="text-purple-300 flex items-center gap-1 font-sans font-medium">
                  <Sparkles className="w-3.5 h-3.5 text-purple-400 shrink-0" /> Malix AI Security Assistant
                </span>
              </div>
            </FadeInSection>

            {/* Main Headline */}
            <FadeInSection direction="up" delay={0.12} distance={24} scale={0.98}>
              <h1 className="text-3xl xs:text-4xl sm:text-5xl md:text-6xl font-extrabold tracking-tight text-white leading-[1.15] mb-6">
                Detect Threats. <br />
                <span className="text-gradient-shield">
                  Understand Risks.
                </span> <br />
                <span className="relative inline-block text-cyan-400">
                  Stay Protected.
                  {/* Subtle highlight line */}
                  <span className="absolute bottom-1 left-0 w-full h-[3px] bg-gradient-to-r from-cyan-400 via-purple-500 to-transparent rounded-full" />
                </span>
              </h1>
            </FadeInSection>

            {/* Subtitle describing active system accurately */}
            <FadeInSection direction="up" delay={0.2} distance={20}>
              <p className="text-base sm:text-lg text-slate-300/95 leading-relaxed max-w-2xl mb-8 font-normal">
                MALGUARD AI integrates static PE inspection, Random Forest machine learning classification, 
                ClamAV signature scanning, and <span className="text-cyan-300 font-medium">Malix AI security assistance</span> to 
                identify suspicious file patterns and deliver clear, human-readable threat explanations.
              </p>
            </FadeInSection>

            {/* CTA Action Buttons */}
            <FadeInSection direction="up" delay={0.28} distance={20} scale={0.98} className="w-full sm:w-auto">
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4 w-full sm:w-auto mb-10">
                {/* Primary CTA: Scan a File */}
                <button
                  onClick={handleScanClick}
                  className="relative group overflow-hidden rounded-xl p-[2px] transition-all duration-150 hover:shadow-[0_0_35px_rgba(34,211,238,0.45)] active:scale-[0.98] cursor-pointer"
                >
                  <div className="absolute inset-0 bg-gradient-to-r from-cyan-400 via-sky-400 to-purple-500 rounded-xl" />
                  <div className="relative px-7 py-3.5 rounded-[10px] bg-[#071120] text-slate-100 font-semibold text-base flex items-center justify-center gap-3 group-hover:bg-[#0b182e] transition-colors">
                    <Shield className="w-5 h-5 text-cyan-400 group-hover:scale-105 transition-transform" />
                    <span>Scan a File</span>
                    <ArrowRight className="w-4 h-4 text-cyan-300 group-hover:translate-x-1 transition-transform" />
                  </div>
                </button>

                {/* Secondary CTA: Explore Features */}
                <a
                  href="#features"
                  className="px-6 py-3.5 rounded-xl glass-panel hover:bg-slate-800/50 border border-slate-700/80 hover:border-cyan-500/40 text-slate-200 hover:text-white font-medium text-base flex items-center justify-center gap-2.5 transition-all duration-150 active:scale-[0.98] cursor-pointer"
                >
                  <FileSearch className="w-4 h-4 text-purple-400" />
                  <span>Explore Features</span>
                </a>
              </div>
            </FadeInSection>

            {/* Value Architecture Chips */}
            <FadeInSection direction="up" delay={0.35} distance={24} scale={0.97} className="w-full">
              <div className="grid grid-cols-1 xs:grid-cols-2 sm:grid-cols-3 gap-3 w-full pt-4 border-t border-white/[0.08]">
                <div className="flex items-center gap-2.5">
                  <div className="p-1.5 rounded-md bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 shrink-0">
                    <Binary className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-200">ML & Signatures</div>
                    <div className="text-xs text-slate-400">Random Forest + ClamAV</div>
                  </div>
                </div>

                <div className="flex items-center gap-2.5">
                  <div className="p-1.5 rounded-md bg-purple-500/10 border border-purple-500/20 text-purple-400 shrink-0">
                    <Cpu className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-200">Malix Assistant</div>
                    <div className="text-xs text-slate-400">Plain-English Reports</div>
                  </div>
                </div>

                <div className="flex items-center gap-2.5 xs:col-span-2 sm:col-span-1">
                  <div className="p-1.5 rounded-md bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 shrink-0">
                    <ShieldCheck className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-slate-200">Secure Handling</div>
                    <div className="text-xs text-slate-400">Isolated Processing</div>
                  </div>
                </div>
              </div>
            </FadeInSection>

          </div>

          {/* Right Column: 3D Cybersecurity Shield Visual Centerpiece */}
          <div className="lg:col-span-5 flex items-center justify-center relative">
            <FadeInSection direction="up" delay={0.2} distance={30} scale={0.95} className="w-full flex justify-center">
              <CyberShield />
            </FadeInSection>
          </div>

        </div>

        {/* Security Framework & Architecture Ecosystem Bar */}
        <FadeInSection direction="up" delay={0.4} distance={20} scale={0.98}>
          <div className="mt-16 pt-8 border-t border-white/[0.06] flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400 uppercase tracking-wider">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              <span>Active Architecture:</span>
            </div>

            <div className="flex flex-wrap items-center justify-center gap-3 sm:gap-6 text-xs font-mono text-slate-300">
              <span className="px-3 py-1 rounded-md bg-[#091526] border border-cyan-500/20 text-cyan-300 flex items-center gap-1.5">
                <Zap className="w-3 h-3 text-cyan-400" /> Suspicious Pattern Detection
              </span>
              <span className="px-3 py-1 rounded-md bg-[#091526] border border-purple-500/20 text-purple-300 flex items-center gap-1.5">
                <Sparkles className="w-3 h-3 text-purple-400" /> Malix AI Security Assistant
              </span>
              <span className="px-3 py-1 rounded-md bg-[#091526] border border-cyan-500/20 text-slate-300 flex items-center gap-1.5">
                <Binary className="w-3 h-3 text-amber-400" /> Random Forest & ClamAV Engine
              </span>
              <span className="px-3 py-1 rounded-md bg-[#091526] border border-emerald-500/20 text-emerald-300 flex items-center gap-1.5">
                <ShieldCheck className="w-3 h-3 text-emerald-400" /> Isolated File Processing
              </span>
            </div>
          </div>
        </FadeInSection>

      </div>
    </section>
  );
}
