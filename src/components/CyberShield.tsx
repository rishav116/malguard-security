"use client";

import React, { useEffect, useRef } from "react";
import { Shield, Lock, Cpu, Eye, Zap, CheckCircle2 } from "lucide-react";

export default function CyberShield() {
  const containerRef = useRef<HTMLDivElement>(null);
  const platformRef = useRef<HTMLDivElement>(null);
  const targetPos = useRef({ x: 0, y: 0 });
  const currentPos = useRef({ x: 0, y: 0 });
  const animIdRef = useRef<number | null>(null);
  const isLoopRunning = useRef(false);

  const startLoop = () => {
    if (isLoopRunning.current) return;
    isLoopRunning.current = true;

    const loop = () => {
      const ease = 0.08;
      const dx = targetPos.current.x - currentPos.current.x;
      const dy = targetPos.current.y - currentPos.current.y;

      if (Math.abs(dx) > 0.002 || Math.abs(dy) > 0.002) {
        currentPos.current.x += dx * ease;
        currentPos.current.y += dy * ease;

        const rotateX = -currentPos.current.y * 14;
        const rotateY = currentPos.current.x * 16;

        if (platformRef.current) {
          platformRef.current.style.transform = `perspective(1000px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) translateZ(0)`;
        }
        animIdRef.current = requestAnimationFrame(loop);
      } else {
        currentPos.current.x = targetPos.current.x;
        currentPos.current.y = targetPos.current.y;
        if (platformRef.current) {
          const rotateX = -currentPos.current.y * 14;
          const rotateY = currentPos.current.x * 16;
          platformRef.current.style.transform = `perspective(1000px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) translateZ(0)`;
        }
        isLoopRunning.current = false;
        animIdRef.current = null;
      }
    };

    animIdRef.current = requestAnimationFrame(loop);
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;
    const x = (e.clientX - centerX) / (rect.width / 2);
    const y = (e.clientY - centerY) / (rect.height / 2);
    targetPos.current = { x: Math.max(-1, Math.min(1, x)), y: Math.max(-1, Math.min(1, y)) };
    startLoop();
  };

  const handleMouseLeave = () => {
    targetPos.current = { x: 0, y: 0 };
    startLoop();
  };

  useEffect(() => {
    return () => {
      if (animIdRef.current) {
        cancelAnimationFrame(animIdRef.current);
      }
    };
  }, []);

  return (
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className="relative flex items-center justify-center w-full max-w-[300px] xs:max-w-[360px] sm:max-w-[500px] h-[360px] xs:h-[420px] sm:h-[540px] select-none perspective-[1200px] mx-auto"
    >
      {/* Ambient background glow behind shield */}
      <div className="absolute w-[220px] h-[220px] xs:w-[280px] xs:h-[280px] sm:w-[420px] sm:h-[420px] rounded-full bg-gradient-to-tr from-cyan-500/20 via-purple-600/25 to-blue-600/10 blur-[60px] sm:blur-[80px] pointer-events-none animate-pulse duration-[5000ms] will-change-transform" />

      {/* Outer cyber ring with rotating tick marks */}
      <div className="absolute w-[260px] h-[260px] xs:w-[320px] xs:h-[320px] sm:w-[440px] sm:h-[440px] rounded-full border border-cyan-500/15 pointer-events-none flex items-center justify-center animate-[spin_60s_linear_infinite] will-change-transform">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-2.5 sm:w-3 h-1 bg-cyan-400 shadow-[0_0_8px_#22d3ee]" />
        <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-2.5 sm:w-3 h-1 bg-cyan-400 shadow-[0_0_8px_#22d3ee]" />
        <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-2.5 sm:h-3 bg-purple-400 shadow-[0_0_8px_#8b5cf6]" />
        <div className="absolute right-0 top-1/2 -translate-y-1/2 w-1 h-2.5 sm:h-3 bg-purple-400 shadow-[0_0_8px_#8b5cf6]" />
      </div>

      {/* Middle dashed tech ring with reverse spin */}
      <div className="absolute w-[210px] h-[210px] xs:w-[260px] xs:h-[260px] sm:w-[380px] sm:h-[380px] rounded-full border border-dashed border-purple-500/20 pointer-events-none animate-[spin_40s_linear_infinite_reverse] will-change-transform" />

      {/* Main 3D Card / Shield Platform */}
      <div
        ref={platformRef}
        className="relative z-10 flex items-center justify-center will-change-transform"
        style={{
          transform: "perspective(1000px) rotateX(0deg) rotateY(0deg) translateZ(0)",
          transformStyle: "preserve-3d",
          backfaceVisibility: "hidden",
          WebkitBackfaceVisibility: "hidden",
        }}
      >
        {/* Holographic Shield Base */}
        <div className="relative w-[180px] h-[225px] xs:w-[220px] xs:h-[275px] sm:w-[280px] sm:h-[350px] flex items-center justify-center">
          {/* SVG Shield Base with Glowing Gradients */}
          <svg
            viewBox="0 0 200 240"
            className="w-full h-full filter drop-shadow-[0_0_35px_rgba(34,211,238,0.4)]"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <defs>
              {/* Outer gradient */}
              <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#22D3EE" stopOpacity="0.85" />
                <stop offset="50%" stopColor="#8B5CF6" stopOpacity="0.6" />
                <stop offset="100%" stopColor="#0F172A" stopOpacity="0.9" />
              </linearGradient>

              {/* Inner glass fill */}
              <linearGradient id="innerFill" x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="#0B1A30" stopOpacity="0.85" />
                <stop offset="50%" stopColor="#060E1A" stopOpacity="0.92" />
                <stop offset="100%" stopColor="#08101E" stopOpacity="0.95" />
              </linearGradient>

              {/* Honeycomb Pattern */}
              <pattern id="hexGrid" width="16" height="27.7" patternUnits="userSpaceOnUse" patternTransform="scale(0.8)">
                <path
                  d="M8 0 L16 4.6 L16 13.9 L8 18.5 L0 13.9 L0 4.6 Z"
                  fill="none"
                  stroke="rgba(34, 211, 238, 0.12)"
                  strokeWidth="0.8"
                />
                <path
                  d="M8 27.7 L16 23.1 L16 13.9 L8 18.5 L0 13.9 L0 23.1 Z"
                  fill="none"
                  stroke="rgba(34, 211, 238, 0.12)"
                  strokeWidth="0.8"
                />
              </pattern>

              {/* Glow filter */}
              <filter id="neonGlow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {/* Background Shield Body */}
            <path
              d="M100 12 L178 44 C178 132 100 216 100 228 C100 216 22 132 22 44 L100 12 Z"
              fill="url(#innerFill)"
              stroke="url(#shieldGrad)"
              strokeWidth="2.5"
            />

            {/* Hex Mesh Overlay on Shield */}
            <path
              d="M100 18 L170 47 C170 126 100 204 100 214 C100 204 30 126 30 47 L100 18 Z"
              fill="url(#hexGrid)"
              opacity="0.9"
            />

            {/* Circuit Trace Details */}
            <path
              d="M100 35 L100 190"
              stroke="rgba(34, 211, 238, 0.25)"
              strokeWidth="1.5"
              strokeDasharray="4 4"
            />
            <path
              d="M60 80 L100 110 L140 80"
              stroke="rgba(139, 92, 246, 0.4)"
              strokeWidth="1.2"
              fill="none"
            />
            <path
              d="M50 120 L100 155 L150 120"
              stroke="rgba(34, 211, 238, 0.35)"
              strokeWidth="1.2"
              fill="none"
            />

            {/* Shield Corner Brackets / Bevel Accent */}
            <path
              d="M100 12 L115 18 L100 24 L85 18 Z"
              fill="#22D3EE"
              filter="url(#neonGlow)"
            />
            <circle cx="100" cy="110" r="28" fill="rgba(34, 211, 238, 0.08)" stroke="rgba(34, 211, 238, 0.4)" strokeWidth="1" />
            <circle cx="100" cy="110" r="18" fill="rgba(139, 92, 246, 0.15)" stroke="rgba(139, 92, 246, 0.5)" strokeWidth="1" />
          </svg>

          {/* Central AI Neural Core Pulse */}
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <div className="relative flex items-center justify-center">
              {/* Core reactor glow */}
              <div className="w-14 h-14 rounded-full bg-cyan-400/20 blur-md animate-ping duration-[3000ms]" />
              <div className="absolute w-12 h-12 rounded-full bg-gradient-to-tr from-cyan-400 to-purple-600 flex items-center justify-center shadow-[0_0_25px_#22D3EE] border border-cyan-200/50">
                <Shield className="w-6 h-6 text-slate-950 fill-white" />
              </div>
            </div>
          </div>

          {/* Vertical Scanning Laser Beam Effect */}
          <div className="absolute inset-0 overflow-hidden pointer-events-none rounded-[35%] opacity-75">
            <div className="w-full h-1 bg-gradient-to-r from-transparent via-cyan-300 to-transparent shadow-[0_0_15px_#22D3EE] animate-scanline" />
          </div>
        </div>

        {/* Orbiting Telemetry Floating Badges (3D depth layers) */}
        
        {/* Badge 1: Top-Right (AI Architecture) */}
        <div
          className="absolute -top-2 right-0 sm:-right-12 glass-panel px-2.5 sm:px-3 py-1 sm:py-1.5 rounded-full flex items-center gap-1.5 sm:gap-2 border border-cyan-400/30 shadow-[0_4px_20px_rgba(34,211,238,0.25)] transition-transform duration-300"
          style={{ transform: "translateZ(40px)" }}
        >
          <span className="w-1.5 h-1.5 sm:w-2 sm:h-2 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_8px_#22d3ee] shrink-0" />
          <span className="text-[10px] xs:text-xs font-mono text-cyan-300 font-semibold tracking-wide flex items-center gap-1 whitespace-nowrap">
            <Cpu className="w-3 h-3 sm:w-3.5 sm:h-3.5 text-cyan-400 shrink-0" />
            <span>Multi-Engine Analysis</span>
          </span>
        </div>

        {/* Badge 2: Bottom-Left (Suspicious Pattern Detection - replaces zero-day claim) */}
        <div
          className="absolute -bottom-2 left-0 sm:-left-12 glass-panel-purple px-2.5 sm:px-3 py-1 sm:py-1.5 rounded-full flex items-center gap-1.5 sm:gap-2 border border-purple-500/30 shadow-[0_4px_20px_rgba(139,92,246,0.25)] transition-transform duration-300"
          style={{ transform: "translateZ(35px)" }}
        >
          <span className="w-1.5 h-1.5 sm:w-2 sm:h-2 rounded-full bg-purple-400 animate-pulse shadow-[0_0_8px_#8b5cf6] shrink-0" />
          <span className="text-[10px] xs:text-xs font-mono text-purple-300 font-semibold tracking-wide flex items-center gap-1 whitespace-nowrap">
            <Zap className="w-3 h-3 sm:w-3.5 sm:h-3.5 text-purple-400 shrink-0" />
            <span className="hidden xs:inline">Suspicious Pattern Detection</span>
            <span className="xs:hidden">Pattern Detection</span>
          </span>
        </div>

        {/* Badge 3: Top-Left (PE Entropy Analysis) */}
        <div
          className="hidden sm:flex absolute top-16 -left-16 glass-panel px-3 py-1.5 rounded-lg items-center gap-2 border border-cyan-500/20 shadow-lg text-[11px] font-mono text-slate-300"
          style={{ transform: "translateZ(25px)" }}
        >
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          <span>PE Entropy Analysis</span>
        </div>

        {/* Badge 4: Bottom-Right (Malix Assistant) */}
        <div
          className="hidden sm:flex absolute bottom-12 -right-14 glass-panel px-3 py-1.5 rounded-lg items-center gap-2 border border-cyan-500/20 shadow-lg text-[11px] font-mono text-slate-300"
          style={{ transform: "translateZ(30px)" }}
        >
          <Eye className="w-3.5 h-3.5 text-cyan-400" />
          <span>Malix AI Assistant</span>
        </div>
      </div>
    </div>
  );
}
