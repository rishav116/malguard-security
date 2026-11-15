"use client";

import React, { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { Shield, Sparkles, Menu, X, ArrowRight, LayoutDashboard, LogIn, UserPlus, LogOut, ShieldCheck } from "lucide-react";
import { useAuth } from "@/context/AuthContext";

interface NavbarProps {
  onOpenScanModal: () => void;
}

export default function Navbar({ onOpenScanModal }: NavbarProps) {
  const { user, signOut } = useAuth();
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [userDropdownOpen, setUserDropdownOpen] = useState(false);
  const [imgError, setImgError] = useState(false);
  const userDropdownRef = useRef<HTMLDivElement>(null);

  const userEmail = user?.email || "";
  const userName = (user?.user_metadata?.full_name as string) || (user?.user_metadata?.name as string) || "";
  const avatarUrl = (user?.user_metadata?.avatar_url as string) || (user?.user_metadata?.picture as string) || null;
  const userInitial = (userName ? userName.charAt(0) : userEmail.charAt(0) || "U");

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener("scroll", handleScroll, { passive: true });

    return () => {
      window.removeEventListener("scroll", handleScroll);
    };
  }, []);

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (userDropdownRef.current && !userDropdownRef.current.contains(e.target as Node)) {
        setUserDropdownOpen(false);
      }
    };
    if (userDropdownOpen) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [userDropdownOpen]);

  return (
    <header
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 transform-gpu ${
        scrolled
          ? "bg-[#060D19]/95 backdrop-blur-md border-b border-cyan-500/20 py-3 shadow-[0_4px_30px_rgba(0,0,0,0.7)]"
          : "bg-[#060D19]/70 backdrop-blur-md border-b border-white/[0.06] py-4"
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between">
          
          {/* Logo & Brand */}
          <Link href="/" className="flex items-center gap-2 sm:gap-3 group min-w-0">
            <div className="relative flex items-center justify-center w-8 h-8 sm:w-10 sm:h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 via-purple-600/20 to-transparent border border-cyan-400/40 shadow-[0_0_15px_rgba(34,211,238,0.3)] group-hover:shadow-[0_0_25px_rgba(34,211,238,0.6)] transition-all duration-300 shrink-0">
              <Shield className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400 group-hover:scale-110 transition-transform duration-300" />
              <div className="absolute inset-0 rounded-xl bg-cyan-400/10 opacity-0 group-hover:opacity-100 transition-opacity" />
            </div>
            <div className="flex items-center gap-1.5 min-w-0">
              <span className="font-bold text-xs xs:text-sm sm:text-base md:text-lg tracking-tight text-white font-display truncate">
                <span className="hidden sm:inline">MALWARE DETECTION SYSTEM</span>
                <span className="sm:hidden">MALGUARD AI</span>
              </span>
              <span className="text-[10px] sm:text-[11px] px-1.5 py-0.5 rounded font-mono font-bold bg-gradient-to-r from-cyan-400 to-purple-500 text-slate-950 shadow-sm shrink-0">
                AI
              </span>
            </div>
          </Link>

          {/* Desktop Navigation Links */}
          <nav className="hidden md:flex items-center gap-8">
            <a
              href="#features"
              className="text-sm text-slate-300 hover:text-cyan-400 transition-colors font-medium"
            >
              Features
            </a>
            <a
              href="#workflow"
              className="text-sm text-slate-300 hover:text-cyan-400 transition-colors font-medium"
            >
              Workflow
            </a>
            <a
              href="#malix-ai"
              className="text-sm text-slate-300 hover:text-purple-400 transition-colors font-medium flex items-center gap-1.5"
            >
              <Sparkles className="w-3.5 h-3.5 text-purple-400" />
              Malix AI
            </a>
            <a
              href="#architecture"
              className="text-sm text-slate-300 hover:text-cyan-400 transition-colors font-medium"
            >
              Architecture
            </a>
          </nav>

          {/* Right CTA & Actions */}
          <div className="hidden sm:flex items-center gap-3">
            {!user ? (
              <div className="flex items-center gap-2">
                {/* Login Button */}
                <Link
                  href="/login"
                  className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-slate-200 hover:text-white bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 hover:border-cyan-400/40 transition-all active:scale-95 flex items-center gap-1.5 cursor-pointer"
                >
                  <LogIn className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Log In</span>
                </Link>

                {/* Sign Up Button */}
                <Link
                  href="/signup"
                  className="px-3.5 py-1.5 rounded-lg text-xs font-semibold text-slate-950 bg-gradient-to-r from-cyan-400 to-sky-400 hover:from-cyan-300 hover:to-sky-300 shadow-[0_0_15px_rgba(34,211,238,0.35)] transition-all active:scale-95 flex items-center gap-1.5 cursor-pointer"
                >
                  <UserPlus className="w-3.5 h-3.5 text-slate-950" />
                  <span>Sign Up</span>
                </Link>
              </div>
            ) : (
              <div className="relative" ref={userDropdownRef}>
                {/* Google / Account Circular Profile Avatar Button */}
                <button
                  type="button"
                  onClick={() => setUserDropdownOpen(!userDropdownOpen)}
                  className="flex items-center justify-center w-9 h-9 sm:w-10 sm:h-10 rounded-full transition-all duration-150 focus:outline-none cursor-pointer active:scale-95"
                  aria-label="Account profile and logout menu"
                  title={userEmail}
                >
                  {/* Circular Avatar Body (clean style without glow or dot) */}
                  <div className="w-full h-full rounded-full bg-[#384e5b] border border-white/20 hover:border-slate-400 flex items-center justify-center text-white font-bold text-sm sm:text-base overflow-hidden shadow-sm select-none transition-colors">
                    {avatarUrl && !imgError ? (
                      <img
                        src={avatarUrl}
                        alt={userName || userEmail}
                        className="w-full h-full object-cover"
                        onError={() => setImgError(true)}
                      />
                    ) : (
                      <span className="font-sans leading-none">{userInitial}</span>
                    )}
                  </div>
                </button>

                {/* Profile & Logout Dropdown Menu */}
                {userDropdownOpen && (
                  <div className="absolute right-0 top-full mt-2.5 w-64 rounded-2xl bg-[#071120]/95 backdrop-blur-xl border border-cyan-500/30 shadow-[0_12px_45px_rgba(0,0,0,0.85),0_0_30px_rgba(34,211,238,0.2)] p-2 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
                    
                    {/* User Profile Card */}
                    <div className="p-3 bg-[#0a182c] rounded-xl border border-white/[0.06] mb-1.5 flex items-center gap-3">
                      <div className="relative w-10 h-10 rounded-full shrink-0 overflow-hidden bg-[#384e5b] border border-cyan-400/40 flex items-center justify-center text-white font-bold text-base shadow-sm">
                        {avatarUrl && !imgError ? (
                          <img src={avatarUrl} alt="Avatar" className="w-full h-full object-cover" />
                        ) : (
                          <span className="font-sans leading-none">{userInitial}</span>
                        )}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="text-xs font-bold text-white truncate font-display">
                          {userName || "Security Analyst"}
                        </div>
                        <div className="text-[11px] text-cyan-300/85 font-mono truncate" title={userEmail}>
                          {userEmail}
                        </div>
                        <div className="mt-1 flex items-center gap-1.5 text-[10px] text-emerald-400 font-mono">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                          <span>Active Session</span>
                        </div>
                      </div>
                    </div>

                    {/* Quick navigation links */}
                    <div className="space-y-0.5">
                      <Link
                        href="/dashboard"
                        onClick={() => setUserDropdownOpen(false)}
                        className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs font-medium text-slate-200 hover:text-white hover:bg-white/[0.06] transition-colors"
                      >
                        <LayoutDashboard className="w-4 h-4 text-cyan-400" />
                        <span>Security Dashboard</span>
                      </Link>

                      <button
                        type="button"
                        onClick={() => {
                          setUserDropdownOpen(false);
                          onOpenScanModal();
                        }}
                        className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs font-medium text-slate-200 hover:text-white hover:bg-white/[0.06] transition-colors cursor-pointer text-left"
                      >
                        <ShieldCheck className="w-4 h-4 text-emerald-400" />
                        <span>Scan a File</span>
                      </button>

                      <div className="my-1 border-t border-white/[0.08]" />

                      {/* Log Out button */}
                      <button
                        type="button"
                        onClick={async () => {
                          setUserDropdownOpen(false);
                          await signOut();
                        }}
                        className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs font-semibold text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 transition-colors cursor-pointer text-left"
                      >
                        <LogOut className="w-4 h-4 text-rose-400" />
                        <span>Log Out</span>
                      </button>
                    </div>

                  </div>
                )}
              </div>
            )}

            {/* Dashboard Button */}
            <Link
              href="/dashboard"
              className="relative group overflow-hidden rounded-lg p-[1px] focus:outline-none focus:ring-2 focus:ring-cyan-400/50 cursor-pointer"
            >
              <span className="absolute inset-0 bg-gradient-to-r from-cyan-400 via-sky-500 to-purple-600 rounded-lg group-hover:opacity-100 transition-opacity blur-[2px]" />
              <span className="relative flex items-center gap-2 px-4 py-2 rounded-lg bg-[#071120] text-sm font-semibold text-white group-hover:bg-[#0a182c] transition-colors">
                <LayoutDashboard className="w-4 h-4 text-cyan-400 group-hover:scale-110 transition-transform duration-300" />
                <span>Dashboard</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-400 group-hover:text-cyan-400 group-hover:translate-x-0.5 transition-all" />
              </span>
            </Link>
          </div>

          {/* Mobile Menu Button & Quick Actions */}
          <div className="md:hidden flex items-center gap-1.5 xs:gap-2">
            {!user ? (
              <div className="flex items-center gap-1 xs:gap-1.5">
                <Link
                  href="/login"
                  className="text-xs px-2 xs:px-2.5 py-1.5 rounded-lg bg-slate-800 text-slate-200 border border-slate-700 font-medium active:scale-95 transition-all"
                >
                  Login
                </Link>
                <Link
                  href="/signup"
                  className="text-xs px-2 xs:px-2.5 py-1.5 rounded-lg bg-cyan-400 text-slate-950 font-bold active:scale-95 transition-all"
                >
                  Sign Up
                </Link>
              </div>
            ) : (
              <Link
                href="/dashboard"
                className="text-xs px-2 xs:px-2.5 py-1.5 rounded-lg bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-medium flex items-center gap-1.5 active:scale-95 transition-all"
              >
                <LayoutDashboard className="w-3.5 h-3.5 text-cyan-400" />
                <span className="hidden xs:inline">Dashboard</span>
              </Link>
            )}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60 focus:outline-none cursor-pointer min-h-[44px] min-w-[44px] flex items-center justify-center transition-colors"
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? <X className="w-6 h-6 text-white" /> : <Menu className="w-6 h-6 text-slate-200" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Drawer Menu */}
      {mobileMenuOpen && (
        <div className="md:hidden glass-panel border-b border-cyan-500/20 mt-3 px-4 sm:px-6 py-5 space-y-4 animate-in slide-in-from-top-4 duration-200 bg-[#071224]/98 backdrop-blur-2xl max-h-[85vh] overflow-y-auto shadow-2xl">
          <div className="flex flex-col space-y-1 font-medium text-slate-200">
            <Link
              href="/dashboard"
              onClick={() => setMobileMenuOpen(false)}
              className="min-h-[44px] px-3 py-2.5 rounded-xl hover:bg-white/[0.05] hover:text-cyan-400 border-b border-white/[0.05] flex items-center justify-between text-cyan-300 transition-colors"
            >
              <span className="text-sm">Security Dashboard</span>
              <LayoutDashboard className="w-4 h-4 text-cyan-400" />
            </Link>
            <a
              href="#features"
              onClick={() => setMobileMenuOpen(false)}
              className="min-h-[44px] px-3 py-2.5 rounded-xl hover:bg-white/[0.05] hover:text-cyan-400 border-b border-white/[0.05] flex items-center text-sm transition-colors"
            >
              Features
            </a>
            <a
              href="#workflow"
              onClick={() => setMobileMenuOpen(false)}
              className="min-h-[44px] px-3 py-2.5 rounded-xl hover:bg-white/[0.05] hover:text-cyan-400 border-b border-white/[0.05] flex items-center text-sm transition-colors"
            >
              Workflow (Upload → Analyze → Results)
            </a>
            <a
              href="#malix-ai"
              onClick={() => setMobileMenuOpen(false)}
              className="min-h-[44px] px-3 py-2.5 rounded-xl hover:bg-purple-500/10 hover:text-purple-300 flex items-center justify-between border-b border-white/[0.05] text-sm transition-colors"
            >
              <span>Malix AI Security Assistant</span>
              <Sparkles className="w-4 h-4 text-purple-400" />
            </a>
            <a
              href="#architecture"
              onClick={() => setMobileMenuOpen(false)}
              className="min-h-[44px] px-3 py-2.5 rounded-xl hover:bg-white/[0.05] hover:text-cyan-400 border-b border-white/[0.05] flex items-center text-sm transition-colors"
            >
              Architecture & Security
            </a>
          </div>

          <div className="pt-2 flex flex-col gap-3">
            {!user ? (
              <div className="grid grid-cols-2 gap-2">
                <Link
                  href="/login"
                  onClick={() => setMobileMenuOpen(false)}
                  className="min-h-[44px] py-2.5 px-3 rounded-xl bg-[#091526] border border-cyan-500/30 text-xs font-semibold flex items-center justify-center text-cyan-300 hover:bg-[#0c1e38] transition-colors"
                >
                  Log In
                </Link>
                <Link
                  href="/signup"
                  onClick={() => setMobileMenuOpen(false)}
                  className="min-h-[44px] py-2.5 px-3 rounded-xl bg-cyan-400 text-xs font-semibold flex items-center justify-center text-slate-950 font-bold hover:bg-cyan-300 transition-colors shadow-md"
                >
                  Sign Up
                </Link>
              </div>
            ) : (
              <div className="p-3 rounded-xl bg-[#081528] border border-cyan-500/25 flex items-center justify-between gap-3">
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="relative w-9 h-9 rounded-full shrink-0 overflow-hidden bg-[#384e5b] border border-cyan-400/40 flex items-center justify-center text-white font-bold text-sm">
                    {avatarUrl && !imgError ? (
                      <img src={avatarUrl} alt="Avatar" className="w-full h-full object-cover" />
                    ) : (
                      <span className="font-sans leading-none">{userInitial}</span>
                    )}
                  </div>
                  <div className="min-w-0 truncate">
                    <div className="text-xs font-bold text-white truncate font-display">
                      {userName || "Security Analyst"}
                    </div>
                    <div className="text-[11px] font-mono text-cyan-300 truncate">
                      {userEmail}
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => {
                    signOut();
                    setMobileMenuOpen(false);
                  }}
                  className="min-h-[40px] px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 text-xs font-semibold flex items-center gap-1.5 cursor-pointer shrink-0 transition-colors"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Logout</span>
                </button>
              </div>
            )}

            <button
              onClick={() => {
                setMobileMenuOpen(false);
                onOpenScanModal();
              }}
              className="w-full min-h-[46px] flex items-center justify-center gap-2 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-600 font-bold text-slate-950 shadow-[0_0_20px_rgba(34,211,238,0.4)] cursor-pointer text-sm active:scale-[0.98] transition-all"
            >
              <Shield className="w-5 h-5 text-slate-950" />
              Scan a File
            </button>
          </div>
        </div>
      )}
    </header>
  );
}
