"use client";

import React, { useState } from "react";
import Link from "next/link";
import { Menu, Shield, Sparkles, User, LogOut, ChevronDown, Bell, CheckCircle2, ShieldCheck } from "lucide-react";
import { useAuth } from "@/context/AuthContext";

interface DashboardHeaderProps {
  onToggleMobileSidebar: () => void;
  onOpenQuickScan?: () => void;
}

export default function DashboardHeader({
  onToggleMobileSidebar,
  onOpenQuickScan,
}: DashboardHeaderProps) {
  const { user, signOut, isConfigured } = useAuth();
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);
  const [imgError, setImgError] = useState(false);

  const userEmail = user?.email || "analyst@malguard.ai";
  const userName = (user?.user_metadata?.full_name as string) || (user?.user_metadata?.name as string) || "";
  const avatarUrl = (user?.user_metadata?.avatar_url as string) || (user?.user_metadata?.picture as string) || null;
  const userInitial = (userName ? userName.charAt(0) : userEmail.charAt(0) || "A");

  return (
    <header className="h-16 bg-[#060D19]/80 backdrop-blur-xl border-b border-white/[0.06] sticky top-0 z-30 flex items-center justify-between px-4 sm:px-6 lg:px-8">
      
      {/* Left section: mobile hamburger & title */}
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleMobileSidebar}
          className="lg:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div>
          <h1 className="text-base sm:text-lg font-bold text-white font-display flex items-center gap-2">
            <span>Operations Console</span>
          </h1>
          <p className="text-xs text-slate-300/85 hidden sm:block">
            Static Artifact Inspection & Threat Intelligence
          </p>
        </div>
      </div>

      {/* Right section: System Status, Quick Scan, Profile Dropdown */}
      <div className="flex items-center gap-3 sm:gap-4">
        
        {/* Engine status indicator */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#091526] border border-emerald-500/25 text-xs font-mono shadow-[0_0_12px_rgba(52,211,153,0.1)]">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_6px_#34d399]" />
          <span className="text-slate-400">AI Detection Engine:</span>
          <span className="text-emerald-300 font-semibold">Active (RF v1.0 + Malix)</span>
        </div>

        {/* Quick Scan CTA */}
        <Link
          href="/scanner"
          onClick={onOpenQuickScan}
          className="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-cyan-400 to-purple-500 hover:from-cyan-300 hover:to-purple-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 shadow-[0_0_15px_rgba(34,211,238,0.3)] transition-all cursor-pointer"
        >
          <Shield className="w-3.5 h-3.5" />
          <span>Quick Scan</span>
        </Link>

        {/* Profile Menu Dropdown */}
        <div className="relative">
          <button
            onClick={() => setProfileDropdownOpen(!profileDropdownOpen)}
            className="flex items-center gap-2 p-1 sm:px-2.5 sm:py-1 rounded-full sm:rounded-xl bg-[#091526] hover:bg-[#0c1c33] border border-white/[0.08] hover:border-cyan-400/40 text-xs transition-colors cursor-pointer"
          >
            <div className="w-7 h-7 rounded-full bg-[#384e5b] border border-white/20 text-white flex items-center justify-center font-bold text-xs overflow-hidden select-none">
              {avatarUrl && !imgError ? (
                <img
                  src={avatarUrl}
                  alt={userEmail}
                  className="w-full h-full object-cover"
                  onError={() => setImgError(true)}
                />
              ) : (
                <span className="font-sans leading-none">{userInitial}</span>
              )}
            </div>
            <span className="hidden sm:inline font-mono text-slate-300 max-w-[120px] truncate">
              {userEmail}
            </span>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </button>

          {profileDropdownOpen && (
            <div className="absolute right-0 mt-2 w-56 rounded-2xl bg-[#070F1E] border border-cyan-500/20 shadow-2xl p-2 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
              <div className="px-3 py-2 border-b border-white/[0.06] mb-1">
                <div className="text-xs font-semibold text-white font-display">
                  {user?.user_metadata?.full_name || "Security Analyst"}
                </div>
                <div className="text-[11px] text-slate-400 font-mono truncate">
                  {userEmail}
                </div>
                <div className="mt-1.5 text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 inline-block">
                  {isConfigured ? "Supabase Cloud" : "Demo Session"}
                </div>
              </div>

              <Link
                href="/scanner"
                onClick={() => setProfileDropdownOpen(false)}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs text-slate-300 hover:text-white hover:bg-slate-800/50 transition-colors"
              >
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                <span>File Scanner</span>
              </Link>

              <Link
                href="/"
                onClick={() => setProfileDropdownOpen(false)}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs text-slate-300 hover:text-white hover:bg-slate-800/50 transition-colors"
              >
                <Shield className="w-3.5 h-3.5 text-slate-400" />
                <span>Landing Page</span>
              </Link>

              <button
                onClick={() => {
                  setProfileDropdownOpen(false);
                  signOut();
                }}
                className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs text-rose-300 hover:bg-rose-500/10 transition-colors cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5 text-rose-400" />
                <span>Sign Out</span>
              </button>
            </div>
          )}
        </div>

      </div>
    </header>
  );
}

