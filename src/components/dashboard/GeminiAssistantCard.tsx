"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Sparkles, Bot, Send, ArrowRight, ShieldCheck, Check, Globe } from "lucide-react";

export default function GeminiAssistantCard() {
  const router = useRouter();
  const [promptText, setPromptText] = useState("");

  const handleSendPrompt = (e: React.FormEvent) => {
    e.preventDefault();
    if (!promptText.trim()) {
      router.push("/copilot");
    } else {
      router.push(`/copilot?q=${encodeURIComponent(promptText.trim())}`);
    }
  };

  return (
    <div id="gemini-copilot" className="rounded-2xl glass-panel-purple p-6 sm:p-8 border border-purple-500/30 shadow-2xl relative overflow-hidden">
      {/* Background ambient purple light */}
      <div className="absolute top-0 right-0 w-80 h-80 bg-purple-600/10 blur-[100px] pointer-events-none -z-10" />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
        
        {/* Left Column: Information & Capabilities */}
        <div className="lg:col-span-7 space-y-4">
          
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-400/30 text-purple-400">
              <Sparkles className="w-5 h-5" />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-purple-300">
                Cognitive Threat Intelligence
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-emerald-500/20 border border-emerald-400/40 text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                ONLINE (PHASE 5)
              </span>
            </div>
          </div>

          <h3 className="text-2xl font-bold text-white font-display">
            Malix AI Security Assistant
          </h3>

          <p className="text-sm text-slate-300 leading-relaxed">
            Connected to Malix AI Assistant through FastAPI. Grounded in your own saved Supabase 
            scan metadata to dissect PE section entropy, investigate imports, and translate complex 
            malware indicators with full support for English, Hindi, and Hinglish.
          </p>

          <div className="space-y-2 pt-2 text-xs font-mono text-slate-300">
            <div className="flex items-center gap-2">
              <Check className="w-4 h-4 text-purple-400 shrink-0" />
              <span>Grounded on your real static PE features, entropy, and Random Forest predictions</span>
            </div>
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>Multilingual: Fluent reasoning in English, Hindi (हिंदी), and natural Hinglish</span>
            </div>
            <div className="flex items-center gap-2">
              <Check className="w-4 h-4 text-purple-400 shrink-0" />
              <span>Zero binary payload leakage — only cryptographic hashes & metadata are processed</span>
            </div>
          </div>

          <div className="pt-2">
            <Link
              href="/copilot"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-cyan-500 hover:from-purple-500 hover:to-cyan-400 text-white font-semibold text-xs shadow-[0_0_20px_rgba(168,85,247,0.4)] transition-all"
            >
              <Sparkles className="w-4 h-4" />
              <span>Open Malix AI Workspace</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

        </div>

        {/* Right Column: Interactive Quick Launch */}
        <div className="lg:col-span-5">
          <div className="rounded-2xl bg-[#040810] border border-purple-500/25 p-5 font-mono text-xs shadow-xl space-y-3">
            <div className="flex items-center justify-between border-b border-white/[0.08] pb-3 text-slate-400 text-xs">
              <span className="flex items-center gap-1.5 text-purple-300 font-semibold">
                <Bot className="w-4 h-4 text-purple-400" />
                Quick Ask Malix AI
              </span>
              <span className="text-[11px] px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-500/30 text-emerald-400 font-medium">
                Ready
              </span>
            </div>

            {/* Simulated Query Snippet */}
            <div className="p-3 rounded-xl bg-[#081120] border border-white/[0.06] text-slate-300 text-xs leading-normal">
              <span className="text-cyan-400 font-bold block mb-1">Try asking in Hinglish or English:</span>
              &quot;Yeh file safe lag rahi hai ya suspicious? Iske entropy aur imports explain karo.&quot;
            </div>

            {/* Prompt Input Form */}
            <form onSubmit={handleSendPrompt} className="space-y-2 pt-1">
              <div className="relative">
                <input
                  type="text"
                  value={promptText}
                  onChange={(e) => setPromptText(e.target.value)}
                  placeholder="Ask in English or Hinglish..."
                  className="w-full pl-3 pr-10 py-2.5 rounded-xl bg-[#060D19] border border-purple-500/30 focus:border-purple-400 focus:outline-none text-xs text-white placeholder-slate-500 font-sans"
                />
                <button
                  type="submit"
                  className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 rounded-lg text-purple-400 hover:text-purple-300 hover:bg-purple-500/20 transition-colors"
                >
                  <Send className="w-3.5 h-3.5" />
                </button>
              </div>
            </form>

            <div className="text-[10px] text-slate-500 text-center pt-1 font-mono">
              Powered by Malix AI Engine & MALGUARD PE Engine.
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}

