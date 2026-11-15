"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { 
  Shield, 
  LayoutDashboard, 
  ShieldCheck, 
  Sparkles, 
  FileText, 
  Settings, 
  ChevronLeft, 
  ChevronRight, 
  LogOut, 
  User as UserIcon,
  ExternalLink
} from "lucide-react";
import { useAuth } from "@/context/AuthContext";

interface SidebarProps {
  collapsed: boolean;
  onToggleCollapse: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
  onOpenQuickScan?: () => void;
}

export default function Sidebar({
  collapsed,
  onToggleCollapse,
  mobileOpen,
  onCloseMobile,
  onOpenQuickScan,
}: SidebarProps) {
  const { user, signOut } = useAuth();
  const pathname = usePathname();

  const navItems = [
    { id: "overview", label: "Overview", icon: LayoutDashboard, href: "/dashboard" },
    { id: "scans", label: "Threat Scans", icon: ShieldCheck, href: "/scanner" },
    { id: "gemini", label: "Malix AI", icon: Sparkles, badge: "AI", href: "/copilot" },
    { id: "reports", label: "Threat Reports", icon: FileText, href: "/reports" },
    { id: "landing", label: "Back to Home", icon: ExternalLink, href: "/" },
  ];

  const userEmail = user?.email || "analyst@malguard.ai";
  const userInitials = userEmail.substring(0, 2).toUpperCase();

  return (
    <>
      {/* Mobile backdrop */}
      {mobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-40 lg:hidden"
        />
      )}

      {/* Sidebar container */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-40 bg-[#060D19]/95 backdrop-blur-2xl border-r border-white/[0.08] transition-all duration-300 flex flex-col justify-between ${
          collapsed ? "w-20" : "w-64"
        } ${mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}`}
      >
        {/* Top Header / Logo */}
        <div>
          <div className="h-16 flex items-center justify-between px-4 border-b border-white/[0.06]">
            <Link href="/" className="flex items-center gap-3 overflow-hidden">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 via-purple-600/20 to-transparent border border-cyan-400/40 text-cyan-400 flex items-center justify-center shrink-0 shadow-[0_0_15px_rgba(34,211,238,0.3)]">
                <Shield className="w-5 h-5" />
              </div>
              {!collapsed && (
                <div className="flex flex-col">
                  <div className="flex items-center gap-1.5">
                    <span className="font-bold text-lg tracking-tight text-white font-display">
                      MALGUARD
                    </span>
                    <span className="text-[11px] px-1.5 py-0.5 rounded font-mono font-bold bg-gradient-to-r from-cyan-400 to-purple-500 text-slate-950">
                      AI
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-cyan-400/90 font-medium tracking-wider uppercase">
                    Security Console
                  </span>
                </div>
              )}
            </Link>

            {/* Collapse toggle (desktop only) */}
            <button
              onClick={onToggleCollapse}
              className="hidden lg:flex p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60 transition-colors"
              title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            >
              {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
            </button>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href;

              return (
                <Link
                  key={item.id}
                  href={item.href}
                  onClick={onCloseMobile}
                  className={`flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all ${
                    isActive
                      ? "bg-gradient-to-r from-cyan-500/15 to-purple-500/10 text-cyan-300 border border-cyan-500/30 font-semibold"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                  }`}
                  title={collapsed ? item.label : undefined}
                >
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? "text-cyan-400" : "text-slate-400"}`} />
                  
                  {!collapsed && (
                    <div className="flex items-center justify-between w-full">
                      <span>{item.label}</span>
                      {item.badge && (
                        <span className="text-[10px] font-mono font-medium px-1.5 py-0.5 rounded bg-purple-950/80 border border-purple-500/40 text-purple-300">
                          {item.badge}
                        </span>
                      )}
                    </div>
                  )}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Bottom Section: Quick Scan & User Profile */}
        <div className="p-3 border-t border-white/[0.06] space-y-3">
          
          {/* Quick Scan Button */}
          {!collapsed ? (
            <Link
              href="/scanner"
              onClick={onCloseMobile}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-purple-500 hover:from-cyan-300 hover:to-purple-400 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(34,211,238,0.3)] transition-all cursor-pointer"
            >
              <Shield className="w-4 h-4" />
              <span>Quick Scan</span>
            </Link>
          ) : (
            <Link
              href="/scanner"
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-400 to-purple-500 text-slate-950 flex items-center justify-center shadow-md"
              title="Quick Scan"
            >
              <Shield className="w-4 h-4" />
            </Link>
          )}

          {/* User profile capsule */}
          <div className="p-2.5 rounded-xl bg-[#091526] border border-white/[0.06] flex items-center justify-between">
            <div className="flex items-center gap-2.5 overflow-hidden">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-500/30 to-purple-500/30 border border-cyan-400/30 text-cyan-300 flex items-center justify-center text-xs font-mono font-bold shrink-0">
                {userInitials}
              </div>
              {!collapsed && (
                <div className="truncate">
                  <div className="text-xs font-semibold text-white truncate font-display">
                    {user?.user_metadata?.full_name || "Security Analyst"}
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono truncate">
                    {userEmail}
                  </div>
                </div>
              )}
            </div>

            {/* Logout button */}
            <button
              onClick={signOut}
              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
              title="Sign Out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>

        </div>
      </aside>
    </>
  );
}

