"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, ArrowRight, Eye, EyeOff, Lock, Mail, AlertCircle, Github, Chrome } from "lucide-react";
import { useAuth } from "@/context/AuthContext";

export default function LoginPage() {
  const router = useRouter();
  const { signIn, signInWithOAuth, isConfigured } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const getRedirectTarget = () => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      return params.get("redirectTo") || "/";
    }
    return "/";
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg("");

    if (!email || !password) {
      setErrorMsg("Please enter both email and password.");
      return;
    }

    setLoading(true);

    const { error } = await signIn(email, password);

    if (error) {
      setErrorMsg(error.message);
      setLoading(false);
    } else {
      router.push(getRedirectTarget());
    }
  };

  return (
    <div className="relative min-h-screen bg-[#040812] flex items-center justify-center p-4 sm:p-6 overflow-hidden">
      {/* Background radial glow */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[500px] bg-gradient-to-tr from-cyan-500/10 via-purple-600/15 to-transparent blur-[140px] pointer-events-none -z-10" />

      {/* Background Cyber Grid */}
      <div className="absolute inset-0 cyber-grid opacity-20 pointer-events-none" />

      {/* Main Authentication Card */}
      <div className="relative w-full max-w-4xl rounded-2xl p-[1px] bg-gradient-to-b from-cyan-500/30 via-purple-500/15 to-transparent shadow-[0_0_50px_rgba(0,0,0,0.8)]">
        <div className="rounded-2xl bg-[#070F1E]/95 backdrop-blur-2xl grid grid-cols-1 lg:grid-cols-12 overflow-hidden border border-white/[0.08]">
          
          {/* Left Column: Cyber Brand & Feature Bullets */}
          <div className="lg:col-span-5 p-5 xs:p-7 sm:p-10 bg-gradient-to-b from-[#091528] to-[#060D19] flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-white/[0.06]">
            
            <div>
              {/* Top Pill / Badge */}
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-xs font-mono text-cyan-300 mb-6">
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
                <span>ENTERPRISE GRADE SECURITY</span>
              </div>

              {/* Title & Brand */}
              <Link href="/" className="inline-block mb-3">
                <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-white flex items-center gap-2 font-display">
                  <span>MALGUARD</span>
                  <span className="text-sm px-1.5 py-0.5 rounded font-mono font-bold bg-gradient-to-r from-cyan-400 to-purple-500 text-slate-950">
                    AI
                  </span>
                </h1>
              </Link>

              <p className="text-sm text-slate-300/90 leading-relaxed mb-8">
                Next-generation malware detection platform combining static PE inspection, 
                Random Forest ML classification, and Malix AI security assistance.
              </p>

              {/* 3 Feature Bullets */}
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 mt-1.5 shadow-[0_0_8px_#22d3ee] shrink-0" />
                  <div>
                    <h2 className="text-xs font-bold text-white uppercase tracking-wider font-display">
                      Dual-Engine Architecture
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Random Forest ML heuristics & ClamAV signatures.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-2.5 h-2.5 rounded-full bg-purple-400 mt-1.5 shadow-[0_0_8px_#8b5cf6] shrink-0" />
                  <div>
                    <h2 className="text-xs font-bold text-white uppercase tracking-wider font-display">
                      Malix AI Security Assistant
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Plain-English threat explanations & triage assistance.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 mt-1.5 shadow-[0_0_8px_#34d399] shrink-0" />
                  <div>
                    <h2 className="text-xs font-bold text-white uppercase tracking-wider font-display">
                      Secure File Handling
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Isolated inspection routines protecting system integrity.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Back to Landing Page link */}
            <div className="pt-8 border-t border-white/[0.06] mt-8">
              <Link
                href="/"
                className="text-xs text-slate-400 hover:text-cyan-400 transition-colors flex items-center gap-1.5 font-mono"
              >
                ← Back to Homepage
              </Link>
            </div>

          </div>

          {/* Right Column: Sign In Form */}
          <div className="lg:col-span-7 p-5 xs:p-7 sm:p-10 flex flex-col justify-center">
            
            <div className="mb-6">
              <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight font-display">
                Welcome Back
              </h2>
              <p className="text-xs sm:text-sm text-slate-400 mt-1">
                Enter your credentials to access the security dashboard.
              </p>
            </div>

            {/* Notice if Supabase is not configured */}
            {!isConfigured && (
              <div className="p-3.5 rounded-xl bg-amber-950/30 border border-amber-500/30 mb-6 text-xs text-amber-200/90 flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                <div>
                  <span className="font-bold text-amber-300 block">Supabase Not Connected:</span>
                  <span>
                    Environment variables are not configured in <code className="text-amber-300 font-mono">.env.local</code>.
                  </span>
                </div>
              </div>
            )}

            {/* Error Message Alert */}
            {errorMsg && (
              <div className="p-3.5 rounded-xl bg-rose-950/40 border border-rose-500/40 mb-6 text-xs text-rose-300 flex items-start gap-2.5 animate-in fade-in">
                <AlertCircle className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                <span>{errorMsg}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              
              {/* Email Address */}
              <div>
                <label className="block text-xs font-mono font-medium text-slate-300 mb-1.5">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="name@company.com"
                    className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[#050C17] border border-slate-700/80 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400 text-sm text-white placeholder-slate-500 transition-colors"
                    required
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-mono font-medium text-slate-300">
                    Password
                  </label>
                  <Link
                    href="/forgot-password"
                    className="text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
                  >
                    Forgot Password?
                  </Link>
                </div>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full pl-10 pr-10 py-2.5 rounded-xl bg-[#050C17] border border-slate-700/80 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400 text-sm text-white placeholder-slate-500 transition-colors"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 focus:outline-none"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Submit CTA Button */}
              <button
                type="submit"
                disabled={loading}
                className="w-full min-h-[44px] py-3 rounded-xl bg-gradient-to-r from-cyan-400 via-sky-500 to-purple-600 hover:from-cyan-300 hover:to-purple-500 text-slate-950 font-bold text-sm flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(34,211,238,0.3)] transition-all disabled:opacity-50 cursor-pointer active:scale-[0.99]"
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <span className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                    Authenticating...
                  </span>
                ) : (
                  <>
                    <span>Continue</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>

            </form>

            {/* Divider */}
            <div className="relative my-6 text-center">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-white/[0.08]" />
              </div>
              <span className="relative px-3 bg-[#070F1E] text-[10px] font-mono tracking-wider uppercase text-slate-500">
                Or Continue With
              </span>
            </div>

            {/* Social Auth Handlers */}
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={async () => {
                  setErrorMsg("");
                  const { error } = await signInWithOAuth("github", getRedirectTarget());
                  if (error) {
                    setErrorMsg(error.message);
                  }
                }}
                className="min-h-[44px] py-2.5 px-4 rounded-xl bg-[#050C17] border border-slate-800 hover:border-slate-700 text-xs font-medium text-slate-300 flex items-center justify-center gap-2 transition-colors cursor-pointer active:scale-95"
              >
                <Github className="w-4 h-4 text-slate-400" />
                <span>GitHub</span>
              </button>

              <button
                type="button"
                onClick={async () => {
                  setErrorMsg("");
                  const { error } = await signInWithOAuth("google", getRedirectTarget());
                  if (error) {
                    setErrorMsg(error.message);
                  }
                }}
                className="min-h-[44px] py-2.5 px-4 rounded-xl bg-[#050C17] border border-slate-800 hover:border-slate-700 text-xs font-medium text-slate-300 flex items-center justify-center gap-2 transition-colors cursor-pointer active:scale-95"
              >
                <Chrome className="w-4 h-4 text-slate-400" />
                <span>Google</span>
              </button>
            </div>

            {/* Sign Up Link */}
            <div className="mt-6 text-center text-xs text-slate-400">
              Don&apos;t have an account?{" "}
              <Link
                href="/signup"
                className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors"
              >
                Register for access
              </Link>
            </div>

          </div>

        </div>
      </div>
    </div>
  );
}

