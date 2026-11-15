"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, Sparkles, ArrowRight, Eye, EyeOff, Lock, Mail, User, AlertCircle, CheckCircle2 } from "lucide-react";
import { useAuth } from "@/context/AuthContext";

export default function SignupPage() {
  const router = useRouter();
  const { signUp, signInDemo, isConfigured } = useAuth();

  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [agreeTerms, setAgreeTerms] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg("");
    setSuccessMsg("");

    if (!fullName || !email || !password || !confirmPassword) {
      setErrorMsg("Please complete all required fields.");
      return;
    }

    if (password !== confirmPassword) {
      setErrorMsg("Passwords do not match.");
      return;
    }

    if (password.length < 8) {
      setErrorMsg("Password must be at least 8 characters.");
      return;
    }

    if (!agreeTerms) {
      setErrorMsg("Please acknowledge the terms and security guidelines.");
      return;
    }

    setLoading(true);

    const { error } = await signUp(email, password, fullName);

    if (error) {
      setErrorMsg(error.message);
      setLoading(false);
    } else {
      setSuccessMsg("Registration initiated. Please check your email to verify your account or proceed to login.");
      setLoading(false);
      setTimeout(() => {
        router.push("/login");
      }, 2500);
    }
  };

  const handleDemoAccess = () => {
    signInDemo();
    router.push("/dashboard");
  };

  // Password strength helper
  const getPasswordStrength = (pwd: string) => {
    let score = 0;
    if (pwd.length >= 8) score++;
    if (/[A-Z]/.test(pwd)) score++;
    if (/[0-9]/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;
    return score;
  };

  const pwdScore = getPasswordStrength(password);

  return (
    <div className="relative min-h-screen bg-[#040812] flex items-center justify-center p-4 sm:p-6 overflow-hidden">
      {/* Background radial glow */}
      <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[500px] bg-gradient-to-tr from-cyan-500/10 via-purple-600/15 to-transparent blur-[140px] pointer-events-none -z-10" />

      {/* Background Cyber Grid */}
      <div className="absolute inset-0 cyber-grid opacity-20 pointer-events-none" />

      {/* Main Authentication Card */}
      <div className="relative w-full max-w-4xl rounded-2xl p-[1px] bg-gradient-to-b from-purple-500/30 via-cyan-500/15 to-transparent shadow-[0_0_50px_rgba(0,0,0,0.8)]">
        <div className="rounded-2xl bg-[#070F1E]/95 backdrop-blur-2xl grid grid-cols-1 lg:grid-cols-12 overflow-hidden border border-white/[0.08]">
          
          {/* Left Column: Brand & Security Overview */}
          <div className="lg:col-span-5 p-8 sm:p-10 bg-gradient-to-b from-[#091528] to-[#060D19] flex flex-col justify-between border-b lg:border-b-0 lg:border-r border-white/[0.06]">
            
            <div>
              {/* Top Badge */}
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-950/60 border border-purple-500/30 text-xs font-mono text-purple-300 mb-6">
                <Shield className="w-3.5 h-3.5 text-purple-400" />
                <span>ANALYST REGISTRATION</span>
              </div>

              {/* Title & Brand */}
              <Link href="/" className="inline-block mb-3">
                <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white flex items-center gap-2 font-display">
                  <span>MALGUARD</span>
                  <span className="text-sm px-1.5 py-0.5 rounded font-mono font-bold bg-gradient-to-r from-cyan-400 to-purple-500 text-slate-950">
                    AI
                  </span>
                </h1>
              </Link>

              <p className="text-sm text-slate-300/90 leading-relaxed mb-8">
                Create an analyst account to access the MALGUARD AI security dashboard, 
                inspect suspicious artifacts, and explore threat telemetry.
              </p>

              {/* Features list */}
              <div className="space-y-4 font-mono text-xs text-slate-300">
                <div className="flex items-center gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
                  <span>Access Centralized Security Dashboard</span>
                </div>
                <div className="flex items-center gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-purple-400 shrink-0" />
                  <span>Track Static PE Inspections & Findings</span>
                </div>
                <div className="flex items-center gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>Explore Malix AI Security Explanations</span>
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

          {/* Right Column: Sign Up Form */}
          <div className="lg:col-span-7 p-8 sm:p-10 flex flex-col justify-center">
            
            <div className="mb-6">
              <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight font-display">
                Create Account
              </h2>
              <p className="text-xs sm:text-sm text-slate-400 mt-1">
                Enter your details to register as a security analyst.
              </p>
            </div>

            {/* Notice if Supabase is not configured */}
            {!isConfigured && (
              <div className="p-3.5 rounded-xl bg-amber-950/30 border border-amber-500/30 mb-6 text-xs text-amber-200/90 flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                <div>
                  <span className="font-bold text-amber-300 block">Supabase Configuration Required:</span>
                  <span>
                    To create live accounts, configure Supabase credentials in <code className="text-amber-300 font-mono">.env.local</code>. 
                    Alternatively, access the dashboard instantly using <strong>Demo Mode</strong> below.
                  </span>
                </div>
              </div>
            )}

            {/* Success Message */}
            {successMsg && (
              <div className="p-3.5 rounded-xl bg-emerald-950/40 border border-emerald-500/40 mb-6 text-xs text-emerald-300 flex items-start gap-2.5 animate-in fade-in">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                <span>{successMsg}</span>
              </div>
            )}

            {/* Error Message */}
            {errorMsg && (
              <div className="p-3.5 rounded-xl bg-rose-950/40 border border-rose-500/40 mb-6 text-xs text-rose-300 flex items-start gap-2.5 animate-in fade-in">
                <AlertCircle className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                <span>{errorMsg}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              
              {/* Full Name */}
              <div>
                <label className="block text-xs font-mono font-medium text-slate-300 mb-1.5">
                  Full Name
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Alex Vance"
                    className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[#050C17] border border-slate-700/80 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400 text-sm text-white placeholder-slate-500 transition-colors"
                    required
                  />
                </div>
              </div>

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
                    placeholder="analyst@company.com"
                    className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[#050C17] border border-slate-700/80 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400 text-sm text-white placeholder-slate-500 transition-colors"
                    required
                  />
                </div>
              </div>

              {/* Password */}
              <div>
                <label className="block text-xs font-mono font-medium text-slate-300 mb-1.5">
                  Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="At least 8 characters"
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

                {/* Password Strength Indicator */}
                {password && (
                  <div className="mt-2 space-y-1">
                    <div className="flex gap-1 h-1">
                      <div className={`flex-1 rounded-full ${pwdScore >= 1 ? "bg-rose-500" : "bg-slate-800"}`} />
                      <div className={`flex-1 rounded-full ${pwdScore >= 2 ? "bg-amber-500" : "bg-slate-800"}`} />
                      <div className={`flex-1 rounded-full ${pwdScore >= 3 ? "bg-cyan-400" : "bg-slate-800"}`} />
                      <div className={`flex-1 rounded-full ${pwdScore >= 4 ? "bg-emerald-400" : "bg-slate-800"}`} />
                    </div>
                    <span className="text-[10px] font-mono text-slate-400">
                      Strength: {pwdScore <= 1 ? "Weak" : pwdScore === 2 ? "Fair" : pwdScore === 3 ? "Good" : "Strong"}
                    </span>
                  </div>
                )}
              </div>

              {/* Confirm Password */}
              <div>
                <label className="block text-xs font-mono font-medium text-slate-300 mb-1.5">
                  Confirm Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type={showPassword ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Repeat password"
                    className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[#050C17] border border-slate-700/80 focus:border-cyan-400 focus:outline-none focus:ring-1 focus:ring-cyan-400 text-sm text-white placeholder-slate-500 transition-colors"
                    required
                  />
                </div>
              </div>

              {/* Terms Checkbox */}
              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="agreeTerms"
                  checked={agreeTerms}
                  onChange={(e) => setAgreeTerms(e.target.checked)}
                  className="w-4 h-4 rounded bg-[#050C17] border-slate-700 text-cyan-500 focus:ring-cyan-400"
                />
                <label htmlFor="agreeTerms" className="text-xs text-slate-300">
                  I agree to the secure artifact handling terms & guidelines.
                </label>
              </div>

              {/* Submit CTA */}
              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-xl bg-gradient-to-r from-purple-500 via-sky-500 to-cyan-400 hover:from-purple-400 hover:to-cyan-300 text-slate-950 font-bold text-sm flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(139,92,246,0.3)] transition-all disabled:opacity-50 cursor-pointer"
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <span className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                    Registering Analyst...
                  </span>
                ) : (
                  <>
                    <span>Create Analyst Account</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>

            </form>

            {/* Demo Access Button */}
            <div className="mt-4">
              <button
                type="button"
                onClick={handleDemoAccess}
                className="w-full py-2.5 rounded-xl bg-cyan-950/40 hover:bg-cyan-900/40 border border-cyan-500/30 text-xs font-mono text-cyan-300 font-semibold flex items-center justify-center gap-2 transition-colors cursor-pointer"
              >
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                <span>Explore in Demo Mode (Skip Setup)</span>
              </button>
            </div>

            {/* Back to Login Link */}
            <div className="mt-6 text-center text-xs text-slate-400">
              Already have an account?{" "}
              <Link
                href="/login"
                className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors"
              >
                Sign In
              </Link>
            </div>

          </div>

        </div>
      </div>
    </div>
  );
}

