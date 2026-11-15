"use client";

import React from "react";
import Link from "next/link";
import { Shield, Sparkles, Terminal, Github, Twitter, Linkedin, ExternalLink } from "lucide-react";

export default function Footer({ onOpenScanModal }: { onOpenScanModal: () => void }) {
  return (
    <footer className="relative bg-[#040810] border-t border-white/[0.08] pt-16 pb-12 overflow-hidden">
      {/* Subtle top glow */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-1 bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-40 shadow-[0_0_15px_#22D3EE]" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-10 pb-12 border-b border-white/[0.06]">
          
          {/* Brand Column */}
          <div className="lg:col-span-2 space-y-4">
            <a href="#" className="flex items-center gap-3 group">
              <div className="flex items-center justify-center w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-600/20 border border-cyan-400/40 text-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.25)]">
                <Shield className="w-5 h-5" />
              </div>
              <div className="flex items-center gap-1.5">
                <span className="font-bold text-lg tracking-tight text-white">
                  MALGUARD
                </span>
                <span className="text-[11px] px-1.5 py-0.5 rounded font-mono font-bold bg-gradient-to-r from-cyan-400 to-purple-500 text-slate-950">
                  AI
                </span>
              </div>
            </a>

            <p className="text-sm text-slate-400 leading-relaxed max-w-sm">
              Next-generation malware detection combining Random Forest ML classification, 
              ClamAV signature scanning, and Malix AI security assistance.
            </p>

            {/* Status indicator */}
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#081220] border border-emerald-500/20 text-xs font-mono text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_6px_#34d399]" />
              <span className="text-slate-400">AI Detection Engine:</span>
              <span className="text-emerald-300 font-semibold">Active (RF v1.0 + Malix)</span>
            </div>
          </div>

          {/* Column 1: Capabilities */}
          <div>
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 mb-4">
              Capabilities
            </h4>
            <ul className="space-y-2.5 text-sm text-slate-400 font-medium">
              <li>
                <a href="#features" className="hover:text-cyan-400 transition-colors">
                  AI Malware Detection
                </a>
              </li>
              <li>
                <a href="#malix-ai" className="hover:text-purple-400 transition-colors flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-purple-400" />
                  Malix AI Assistant
                </a>
              </li>
              <li>
                <Link href="/reports" className="hover:text-cyan-400 transition-colors">
                  Threat Reports
                </Link>
              </li>
              <li>
                <button
                  onClick={onOpenScanModal}
                  className="hover:text-cyan-400 text-left transition-colors"
                >
                  Scanner Preview
                </button>
              </li>
            </ul>
          </div>

          {/* Column 2: Architecture */}
          <div>
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 mb-4">
              Architecture
            </h4>
            <ul className="space-y-2.5 text-sm text-slate-400 font-medium">
              <li>
                <a href="#workflow" className="hover:text-cyan-400 transition-colors">
                  Detection Pipeline
                </a>
              </li>
              <li>
                <a href="#architecture" className="hover:text-cyan-400 transition-colors">
                  Static PE Inspection
                </a>
              </li>
              <li>
                <a href="#architecture" className="hover:text-cyan-400 transition-colors">
                  Secure File Handling
                </a>
              </li>
              <li>
                <a href="#threat-reports" className="hover:text-cyan-400 transition-colors">
                  Pattern Indicators
                </a>
              </li>
            </ul>
          </div>

          {/* Column 3: Trust & Handling */}
          <div>
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300 mb-4">
              Security Design
            </h4>
            <ul className="space-y-2.5 text-sm text-slate-400 font-medium">
              <li className="text-slate-400 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                Secure File Handling
              </li>
              <li className="text-slate-400 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                Cryptographic Hashing
              </li>
              <li className="text-slate-400 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                Isolated Processing
              </li>
              <li className="text-slate-400 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                Transparent Architecture
              </li>
            </ul>
          </div>

        </div>

        {/* Bottom bar */}
        <div className="pt-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-slate-500 text-center sm:text-left">
          <div>
            © {new Date().getFullYear()} MALGUARD AI Security. All rights reserved.
          </div>
          <div className="flex items-center gap-4 sm:gap-6">
            <span className="text-slate-400">Next.js • TypeScript • Tailwind CSS • Malix AI</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
