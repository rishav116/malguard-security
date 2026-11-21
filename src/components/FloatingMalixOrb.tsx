"use client";

import React, { useState, useEffect, useRef } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import {
  Sparkles,
  X,
  Send,
  Trash2,
  Maximize2,
  Square,
  AlertCircle,
  HelpCircle,
  Bot,
  User,
  ArrowRight,
} from "lucide-react";
import {
  streamCopilotMessage,
  ChatMessage,
  StreamMetadata,
} from "@/lib/api/copilotService";
import { useAuth } from "@/context/AuthContext";
import { MarkdownMessage } from "@/components/copilot/MarkdownMessage";

/**
 * 3D Spherical Floating Malix AI Orb SVG
 * Faithful reproduction of the 3D crystal sphere with cyan/magenta rim lighting,
 * specular reflections, stylized gradient "M", orbital ring, and "Malix AI" typography.
 */
export function MalixSphereOrbSvg({ className = "w-full h-full" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 120 120"
      className={className}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        {/* Outer Dual-Tone Neon Rim Gradient */}
        <linearGradient id="orbOuterRim" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#00F0FF" />
          <stop offset="35%" stopColor="#38BDF8" />
          <stop offset="70%" stopColor="#A855F7" />
          <stop offset="100%" stopColor="#F43F5E" />
        </linearGradient>

        {/* Deep Obsidian Sphere Body Radial Fill */}
        <radialGradient id="sphereObsidian" cx="36%" cy="32%" r="66%">
          <stop offset="0%" stopColor="#1E3252" />
          <stop offset="32%" stopColor="#0B1628" />
          <stop offset="70%" stopColor="#050913" />
          <stop offset="100%" stopColor="#010307" />
        </radialGradient>

        {/* Stylized "M" Logo Gradient */}
        <linearGradient id="mGradient" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#00E5FF" />
          <stop offset="42%" stopColor="#38BDF8" />
          <stop offset="75%" stopColor="#C084FC" />
          <stop offset="100%" stopColor="#F43F5E" />
        </linearGradient>

        {/* 3D Orbital Ring Gradient */}
        <linearGradient id="ringGradient" x1="0%" y1="50%" x2="100%" y2="50%">
          <stop offset="0%" stopColor="#00F5FF" stopOpacity="0.95" />
          <stop offset="40%" stopColor="#38BDF8" stopOpacity="0.85" />
          <stop offset="75%" stopColor="#E879F9" stopOpacity="0.9" />
          <stop offset="100%" stopColor="#F43F5E" stopOpacity="0.9" />
        </linearGradient>

        {/* Top-Left Glossy Specular Glass Reflection */}
        <linearGradient id="topGlassHighlight" x1="25%" y1="0%" x2="60%" y2="80%">
          <stop offset="0%" stopColor="#FFFFFF" stopOpacity="0.75" />
          <stop offset="35%" stopColor="#FFFFFF" stopOpacity="0.25" />
          <stop offset="80%" stopColor="#FFFFFF" stopOpacity="0" />
        </linearGradient>

        {/* Bottom Ambient Glow Radial */}
        <radialGradient id="bottomInternalGlow" cx="50%" cy="88%" r="45%">
          <stop offset="0%" stopColor="#818CF8" stopOpacity="0.4" />
          <stop offset="50%" stopColor="#00F0FF" stopOpacity="0.2" />
          <stop offset="100%" stopColor="#000000" stopOpacity="0" />
        </radialGradient>

        {/* Ring Glow Filter */}
        <filter id="ringGlowFilter" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="1.2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Main Sphere Shadow/Glow Base */}
      <circle cx="60" cy="60" r="54" fill="url(#sphereObsidian)" />
      <circle cx="60" cy="60" r="54" fill="url(#bottomInternalGlow)" />

      {/* Back Half of the 3D Orbital Ring (Passes behind right leg of M) */}
      <g transform="rotate(-18 60 56)">
        <path
          d="M 28 56 A 34 8.5 0 0 1 92 56"
          stroke="url(#ringGradient)"
          strokeWidth="2.2"
          strokeLinecap="round"
          opacity="0.65"
        />
      </g>

      {/* Stylized Modern Futuristic "M" Logo */}
      <path
        d="M 37 68 L 37 39 Q 37 36 40 36 L 46 36 Q 48.5 36 50 38.5 L 60 52 L 70 38.5 Q 71.5 36 74 36 L 80 36 Q 83 36 83 39 L 83 68 Q 83 70.5 80.5 70.5 L 75 70.5 Q 72.5 70.5 72.5 68 L 72.5 48 L 63 60.5 Q 61.5 62.5 60 62.5 Q 58.5 62.5 57 60.5 L 47.5 48 L 47.5 68 Q 47.5 70.5 45 70.5 L 39.5 70.5 Q 37 70.5 37 68 Z"
        fill="url(#mGradient)"
        filter="drop-shadow(0 0 4px rgba(0, 229, 255, 0.45))"
      />

      {/* Front Half of the 3D Orbital Ring (Crosses in front of M with neon glow) */}
      <g transform="rotate(-18 60 56)">
        <path
          d="M 92 56 A 34 8.5 0 0 1 28 56"
          stroke="url(#ringGradient)"
          strokeWidth="2.6"
          strokeLinecap="round"
          filter="url(#ringGlowFilter)"
        />
      </g>

      {/* Text "Malix AI" centered beneath M */}
      <text
        x="60"
        y="91"
        textAnchor="middle"
        fill="#FFFFFF"
        fontSize="12.5"
        fontWeight="700"
        fontFamily="var(--font-geist-sans), 'Inter', sans-serif"
        letterSpacing="0.03em"
        filter="drop-shadow(0 1px 3px rgba(0,0,0,0.8))"
      >
        Malix AI
      </text>

      {/* Glossy Curved Glass Specular Highlight (Top-Left) */}
      <ellipse
        cx="46"
        cy="24"
        rx="28"
        ry="13"
        transform="rotate(-26 46 24)"
        fill="url(#topGlassHighlight)"
      />

      {/* Delicate Outer Glass Border */}
      <circle
        cx="60"
        cy="60"
        r="54"
        fill="none"
        stroke="url(#orbOuterRim)"
        strokeWidth="2.2"
        opacity="0.9"
      />

      {/* Bottom Right Subtle Rim Highlight */}
      <path
        d="M 82 98 A 54 54 0 0 0 110 74"
        fill="none"
        stroke="#F43F5E"
        strokeWidth="2.5"
        strokeLinecap="round"
        opacity="0.75"
        filter="blur(0.8px)"
      />
    </svg>
  );
}

function generateMessageId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
}

function getMessageTimestamp(): string {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export default function FloatingMalixOrb() {
  const pathname = usePathname();
  const { session } = useAuth();

  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<
    Array<ChatMessage & { id: string; timestamp: string; isStreaming?: boolean }>
  >([
    {
      id: "initial-greeting",
      role: "model",
      content:
        "Hello Analyst! I am **Malix AI Security Assistant**.\n\nI can explain PE header entropy, dissect suspicious imports, and decode threat signatures in **English, Hindi, or Hinglish**.\n\nHow can I assist your investigation today?",
      timestamp: "Just now",
    },
  ]);
  const [inputValue, setInputValue] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const abortControllerRef = useRef<AbortController | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Suggested prompt chips for rapid analysis
  const quickPrompts = [
    "Yeh file safe hai kya?",
    "Explain Shannon PE Entropy",
    "How does Random Forest detect malware?",
    "What are suspicious PE imports?",
  ];

  // Auto-scroll chat to latest token
  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, isOpen, isSending]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [isOpen]);

  const handleSendMessage = async (textToSend?: string) => {
    const prompt = (textToSend || inputValue).trim();
    if (!prompt || isSending) return;

    setErrorMessage(null);
    setInputValue("");

    const userMessageId = generateMessageId("user");
    const botMessageId = generateMessageId("model");

    const newMessages = [
      ...messages,
      {
        id: userMessageId,
        role: "user" as const,
        content: prompt,
        timestamp: getMessageTimestamp(),
      },
    ];

    setMessages(newMessages);
    setIsSending(true);

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    // Add placeholder streaming message
    setMessages((prev) => [
      ...prev,
      {
        id: botMessageId,
        role: "model",
        content: "",
        timestamp: getMessageTimestamp(),
        isStreaming: true,
      },
    ]);

    try {
      const chatHistory: ChatMessage[] = newMessages.map((m) => ({
        role: m.role,
        content: m.content,
      }));

      await streamCopilotMessage(
        prompt,
        {
          onToken: (token: string) => {
            setMessages((prev) =>
              prev.map((msg) =>
                msg.id === botMessageId
                  ? { ...msg, content: msg.content + token }
                  : msg
              )
            );
          },
          onMetadata: () => {},
          onDone: () => {
            setMessages((prev) =>
              prev.map((msg) =>
                msg.id === botMessageId ? { ...msg, isStreaming: false } : msg
              )
            );
            setIsSending(false);
          },
          onError: (err: string) => {
            setErrorMessage(err);
            setIsSending(false);
            setMessages((prev) =>
              prev.map((msg) =>
                msg.id === botMessageId
                  ? {
                      ...msg,
                      content:
                        msg.content ||
                        (err.includes("401") || err.toLowerCase().includes("unauthorized")
                          ? "Please log in to your account to query Malix AI Security Assistant."
                          : `Unable to contact Malix AI detection backend right now (${err || "backend unreachable"}). Ensure the FastAPI server is running.`),
                      isStreaming: false,
                    }
                  : msg
              )
            );
          },
        },
        {
          history: chatHistory.slice(0, -1),
          authToken: session?.access_token,
          signal: abortController.signal,
        }
      );
    } catch (err: unknown) {
      if ((err as Error)?.name !== "AbortError") {
        setErrorMessage((err as Error)?.message || "Failed to transmit prompt");
      }
      setIsSending(false);
    }
  };

  const handleStopStreaming = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
      setIsSending(false);
    }
  };

  const handleClearHistory = () => {
    setMessages([
      {
        id: "cleared-greeting",
        role: "model",
        content:
          "Conversation cleared. Ask me any question about malware detection, reverse engineering, or system security!",
        timestamp: "Just now",
      },
    ]);
    setErrorMessage(null);
  };

  // Hide on full copilot page to prevent redundant overlay
  if (pathname === "/copilot") {
    return null;
  }

  return (
    <>
      {/* 1. Floating Malix Chat Drawer */}
      {isOpen && (
        <div
          className="fixed bottom-16 xs:bottom-20 right-2 xs:right-4 sm:right-6 z-50 w-[360px] sm:w-[420px] max-w-[calc(100vw-16px)] xs:max-w-[calc(100vw-32px)] h-[520px] sm:h-[560px] max-h-[calc(100dvh-100px)] flex flex-col rounded-2xl bg-[#071120]/95 backdrop-blur-xl border border-cyan-500/30 shadow-[0_12px_45px_rgba(0,0,0,0.85),0_0_35px_rgba(34,211,238,0.25)] overflow-hidden animate-in fade-in slide-in-from-bottom-5 duration-200"
          role="dialog"
          aria-label="Malix AI Floating Window"
        >
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 bg-[#091528] border-b border-cyan-500/20">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-full overflow-hidden shadow-[0_0_12px_rgba(34,211,238,0.5)] shrink-0">
                <MalixSphereOrbSvg />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="font-bold text-sm text-white font-display">Malix AI Assistant</span>
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_6px_#34d399]" />
                </div>
                <div className="text-[10px] text-cyan-300/80 font-mono">
                  Online • Security Intelligence Core
                </div>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <Link
                href="/copilot"
                target="_blank"
                className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-300 hover:bg-white/[0.06] transition-colors"
                title="Open in Full Screen"
              >
                <Maximize2 className="w-4 h-4" />
              </Link>
              <button
                onClick={handleClearHistory}
                className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-white/[0.06] transition-colors"
                title="Clear Chat History"
              >
                <Trash2 className="w-4 h-4" />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.06] transition-colors"
                title="Close Window"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Chat Message List */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3.5 scrollbar-thin">
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex gap-2.5 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
              >
                {msg.role === "model" && (
                  <div className="w-7 h-7 rounded-full overflow-hidden shrink-0 mt-0.5 shadow-[0_0_8px_rgba(34,211,238,0.4)]">
                    <MalixSphereOrbSvg />
                  </div>
                )}

                <div
                  className={`max-w-[85%] rounded-xl px-3.5 py-2.5 text-xs sm:text-sm leading-relaxed ${
                    msg.role === "user"
                      ? "bg-gradient-to-r from-cyan-600/90 to-blue-600/90 text-white shadow-[0_2px_12px_rgba(34,211,238,0.25)] rounded-tr-none"
                      : "bg-[#0c1a30] border border-cyan-500/20 text-slate-200 shadow-md rounded-tl-none"
                  }`}
                >
                  {msg.role === "model" ? (
                    <MarkdownMessage content={msg.content} isStreaming={msg.isStreaming} />
                  ) : (
                    <p className="whitespace-pre-wrap">{msg.content}</p>
                  )}
                  <div
                    className={`mt-1 text-[10px] ${
                      msg.role === "user" ? "text-cyan-200/80 text-right" : "text-slate-400 text-left"
                    }`}
                  >
                    {msg.timestamp}
                  </div>
                </div>

                {msg.role === "user" && (
                  <div className="w-7 h-7 rounded-full bg-cyan-500/20 border border-cyan-400/40 flex items-center justify-center shrink-0 mt-0.5 text-cyan-300">
                    <User className="w-4 h-4" />
                  </div>
                )}
              </div>
            ))}

            {errorMessage && (
              <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                <span>{errorMessage}</span>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Quick Prompts Carousel (when message count is small) */}
          {messages.length <= 3 && !isSending && (
            <div className="px-3 py-2 bg-[#060D1A]/80 border-t border-white/[0.05] overflow-x-auto flex gap-1.5 scrollbar-none">
              {quickPrompts.map((prompt, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSendMessage(prompt)}
                  className="whitespace-nowrap px-2.5 py-1 rounded-full bg-cyan-950/60 hover:bg-cyan-900/80 border border-cyan-500/30 text-[11px] font-mono text-cyan-300 transition-colors flex items-center gap-1"
                >
                  <Sparkles className="w-3 h-3 text-cyan-400" />
                  <span>{prompt}</span>
                </button>
              ))}
            </div>
          )}

          {/* Input Bar */}
          <div className="p-3 bg-[#081324] border-t border-cyan-500/20 flex items-center gap-2">
            <input
              ref={inputRef}
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  handleSendMessage();
                }
              }}
              placeholder="Ask Malix AI about file risks, entropy..."
              disabled={isSending}
              className="flex-1 bg-[#050B16] border border-cyan-500/25 focus:border-cyan-400 rounded-xl px-3.5 py-2 text-xs sm:text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none transition-colors"
            />

            {isSending ? (
              <button
                onClick={handleStopStreaming}
                className="p-2 rounded-xl bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-300 transition-colors"
                title="Stop Generating"
              >
                <Square className="w-4 h-4 fill-current" />
              </button>
            ) : (
              <button
                onClick={() => handleSendMessage()}
                disabled={!inputValue.trim()}
                className="p-2 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 text-slate-950 font-bold transition-transform active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed shadow-[0_0_12px_rgba(34,211,238,0.3)]"
                title="Send Prompt"
              >
                <Send className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      )}

      {/* 2. Floating 3D Spherical Malix AI Orb */}
      <aside
        aria-label="Malix AI trigger"
        className="fixed bottom-4 right-4 sm:bottom-6 sm:right-6 z-50 flex items-center justify-center select-none"
      >
        {/* Subtle Ambient Glow Halo */}
        <div
          className="absolute inset-0.5 rounded-full bg-gradient-to-tr from-cyan-500/20 via-purple-600/20 to-rose-500/10 blur-sm pointer-events-none"
          aria-hidden="true"
        />

        {/* Trigger Button with 3D Spherical Orb */}
        <button
          onClick={() => setIsOpen((prev) => !prev)}
          className="group relative w-[48px] h-[48px] sm:w-16 sm:h-16 rounded-full transition-all duration-150 hover:scale-105 active:scale-95 focus:outline-none animate-orb-float animate-orb-glow cursor-pointer"
          aria-label={isOpen ? "Close Malix AI" : "Open Malix AI"}
          title={isOpen ? "Close Malix AI" : "Ask Malix AI Security Assistant"}
        >
          {/* 3D Sphere SVG */}
          <MalixSphereOrbSvg className="w-full h-full drop-shadow-[0_0_5px_rgba(34,211,238,0.4)]" />

          {/* Hover Tooltip Pill */}
          <span className="pointer-events-none absolute -top-8 right-1/2 translate-x-1/2 whitespace-nowrap px-2.5 py-1 rounded-full bg-[#071120]/95 border border-cyan-400/40 text-[11px] font-mono text-cyan-300 shadow-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200">
            {isOpen ? "Close Malix AI" : "✨ Ask Malix AI"}
          </span>
        </button>
      </aside>
    </>
  );
}
