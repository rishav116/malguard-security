"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/context/AuthContext";
import Sidebar from "@/components/dashboard/Sidebar";
import DashboardHeader from "@/components/dashboard/DashboardHeader";
import {
  Sparkles,
  User,
  Send,
  Trash2,
  Copy,
  Check,
  AlertCircle,
  FileCode,
  HelpCircle,
  RefreshCw,
  Globe,
  Layers,
  ArrowRight,
  Square,
} from "lucide-react";
import {
  streamCopilotMessage,
  fetchSuggestedQuestions,
  ChatMessage,
  SuggestedQuestionItem,
  SuggestedQuestionsData,
} from "@/lib/api/copilotService";
import { fetchUserScans, PersistedScanItem } from "@/lib/api/scannerService";
import { formatDeterministicTime } from "@/lib/utils/timeFormat";
import { MarkdownMessage } from "@/components/copilot/MarkdownMessage";

function CopilotContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { user, session, loading } = useAuth();

  // Hydration safety flag
  const [isMounted, setIsMounted] = useState(false);

  // Layout state
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  // Chat State
  const [messages, setMessages] = useState<
    Array<ChatMessage & { groundedScan?: string; timestamp?: string; isStreaming?: boolean }>
  >([
    {
      role: "model",
      content:
        "Hello Analyst! I am **MALGUARD AI Security Assistant**, powered by Malix AI.\n\nI can analyze Windows PE headers, dissect Shannon entropy, explain Random Forest model predictions, and suggest incident containment strategies.\n\nYou can speak to me in **English, Hindi (हिंदी), or Hinglish** (e.g., *'Yeh file safe hai kya?'*).\n\nSelect a scan from your scan history above to ground our conversation, or ask any general reverse engineering question!",
      timestamp: "", // Initial empty string to guarantee identical SSR and client HTML
    },
  ]);
  const [inputValue, setInputValue] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Streaming cancellation ref
  const abortControllerRef = useRef<AbortController | null>(null);

  // Scan Grounding State
  const [userScans, setUserScans] = useState<PersistedScanItem[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [isLoadingScans, setIsLoadingScans] = useState(false);

  // Suggested Questions
  const [suggestedQuestions, setSuggestedQuestions] = useState<SuggestedQuestionsData | null>(null);
  const [activeLangTab, setActiveLangTab] = useState<"english" | "hinglish" | "hindi">("english");
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Scroll to bottom on new token/message
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isSending]);

  // Client hydration mount effect
  useEffect(() => {
    const timer = setTimeout(() => {
      setIsMounted(true);
      setMessages((prev) => [
        {
          ...prev[0],
          timestamp: formatDeterministicTime(new Date()),
        },
        ...prev.slice(1),
      ]);
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  // Cleanup abort controller on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  // Auth Protection
  useEffect(() => {
    if (!loading && !user) {
      router.push("/login?redirectTo=/copilot");
    }
  }, [user, loading, router]);

  // Load User's Scans for Grounding
  useEffect(() => {
    if (user && session?.access_token) {
      let isCancelled = false;
      const timer = setTimeout(() => {
        if (!isCancelled) setIsLoadingScans(true);
      }, 0);

      fetchUserScans(session.access_token, { limit: 50 }).then((res) => {
        if (isCancelled) return;
        setIsLoadingScans(false);
        if (res.success && res.data) {
          setUserScans(res.data);
          const queryScanId = searchParams.get("scanId");
          if (queryScanId && res.data.some((s) => s.id === queryScanId)) {
            setSelectedScanId(queryScanId);
          }
        }
      });

      return () => {
        isCancelled = true;
        clearTimeout(timer);
      };
    }
  }, [user, session, searchParams]);

  // Load Suggested Questions
  useEffect(() => {
    fetchSuggestedQuestions().then((res) => {
      if (res.success && res.data) {
        setSuggestedQuestions(res.data);
      }
    });
  }, []);

  // Pre-fill prompt from URL query if present
  useEffect(() => {
    const q = searchParams.get("q");
    if (q) {
      const timer = setTimeout(() => {
        setInputValue(q);
      }, 0);
      return () => clearTimeout(timer);
    }
  }, [searchParams]);

  // Handle Stop Streaming
  const handleStopStreaming = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setIsSending(false);
    setMessages((prev) =>
      prev.map((m) => (m.isStreaming ? { ...m, isStreaming: false } : m))
    );
  };

  // Handle Send with progressive real-time SSE streaming
  const handleSendMessage = async (customMessage?: string) => {
    const messageToSend = (customMessage || inputValue).trim();
    if (!messageToSend || isSending) return;

    // Abort any previous pending stream
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    setErrorMessage(null);
    setInputValue("");

    // Find selected scan name for UI tag
    const activeScan = userScans.find((s) => s.id === selectedScanId);
    const scanLabel = activeScan ? activeScan.file_name : undefined;

    const userTimestamp = formatDeterministicTime(new Date());

    // Prepare conversational history (keep last 4 turns)
    const newHistory: ChatMessage[] = [
      ...messages
        .filter((m) => m.content.trim().length > 0)
        .map((m) => ({ role: m.role, content: m.content })),
      { role: "user", content: messageToSend },
    ];

    // Append user message AND immediate placeholder bot message for responsive loading feedback
    setMessages((prev) => [
      ...prev,
      {
        role: "user",
        content: messageToSend,
        groundedScan: scanLabel,
        timestamp: userTimestamp,
      },
      {
        role: "model",
        content: "", // Starts empty to display immediate typing indicator
        groundedScan: scanLabel,
        timestamp: userTimestamp,
        isStreaming: true,
      },
    ]);

    setIsSending(true);

    try {
      await streamCopilotMessage(
        messageToSend,
        {
          onToken: (token: string) => {
            setMessages((prev) => {
              const updated = [...prev];
              const lastIdx = updated.length - 1;
              if (lastIdx >= 0 && updated[lastIdx].role === "model") {
                updated[lastIdx] = {
                  ...updated[lastIdx],
                  content: updated[lastIdx].content + token,
                  isStreaming: true,
                };
              }
              return updated;
            });
          },
          onMetadata: (meta) => {
            if (meta.scan_context?.file_name) {
              setMessages((prev) => {
                const updated = [...prev];
                const lastIdx = updated.length - 1;
                if (lastIdx >= 0 && updated[lastIdx].role === "model") {
                  updated[lastIdx] = {
                    ...updated[lastIdx],
                    groundedScan: meta.scan_context!.file_name,
                  };
                }
                return updated;
              });
            }
          },
          onDone: () => {
            setIsSending(false);
            setMessages((prev) => {
              const updated = [...prev];
              const lastIdx = updated.length - 1;
              if (lastIdx >= 0 && updated[lastIdx].role === "model") {
                updated[lastIdx] = {
                  ...updated[lastIdx],
                  isStreaming: false,
                };
              }
              return updated;
            });
          },
          onError: (err: string) => {
            setErrorMessage(err);
            setIsSending(false);
            const isAuthError =
              err.toLowerCase().includes("authentication") ||
              err.toLowerCase().includes("session") ||
              err.toLowerCase().includes("sign in") ||
              err.toLowerCase().includes("log in") ||
              err.includes("401");

            setMessages((prev) => {
              const updated = [...prev];
              const lastIdx = updated.length - 1;
              if (lastIdx >= 0 && updated[lastIdx].role === "model") {
                if (!updated[lastIdx].content) {
                  const errorMsg = isAuthError
                    ? `⚠️ **Authentication Required**\n\nYour session is either missing or has expired.\n\nPlease [sign in to your account](/login?redirectTo=/copilot) to continue chatting with Malix AI Assistant.`
                    : `⚠️ *Assistant Error:* ${err}\n\nPlease check connection or try again.`;
                  updated[lastIdx] = {
                    ...updated[lastIdx],
                    content: errorMsg,
                    isStreaming: false,
                  };
                } else {
                  updated[lastIdx] = {
                    ...updated[lastIdx],
                    isStreaming: false,
                  };
                }
              }
              return updated;
            });
          },
        },
        {
          history: newHistory.slice(-4),
          scanId: selectedScanId || undefined,
          authToken: session?.access_token,
          signal: abortController.signal,
        }
      );
    } catch (err: unknown) {
      if ((err as Error).name !== "AbortError") {
        setErrorMessage((err as Error).message);
      }
      setIsSending(false);
    }
  };

  const handleCopy = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleClearHistory = () => {
    handleStopStreaming();
    setErrorMessage(null);
    setMessages([
      {
        role: "model",
        content:
          "Chat session refreshed. Select a scan artifact above or ask a new malware analysis question in English, Hindi, or Hinglish.",
        timestamp: formatDeterministicTime(new Date()),
      },
    ]);
  };

  const activeScan = userScans.find((s) => s.id === selectedScanId);

  return (
    <div className="min-h-screen bg-[#040812] text-slate-100 flex flex-col font-sans relative overflow-x-hidden">
      {/* Background radial glows */}
      <div className="absolute top-1/4 left-1/3 w-[600px] h-[400px] bg-purple-600/10 blur-[140px] pointer-events-none -z-10" />
      <div className="absolute bottom-1/4 right-1/4 w-[500px] h-[350px] bg-cyan-500/10 blur-[130px] pointer-events-none -z-10" />
      <div className="absolute inset-0 cyber-grid opacity-15 pointer-events-none -z-10" />

      {/* Sidebar Navigation */}
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        mobileOpen={mobileSidebarOpen}
        onCloseMobile={() => setMobileSidebarOpen(false)}
        onOpenQuickScan={() => router.push("/scanner")}
      />

      {/* Main Container */}
      <div
        className={`flex-1 flex flex-col transition-all duration-300 min-w-0 ${
          sidebarCollapsed ? "lg:pl-20" : "lg:pl-64"
        }`}
      >
        <DashboardHeader onToggleMobileSidebar={() => setMobileSidebarOpen(true)} />

        <main className="flex-1 flex flex-col p-3 xs:p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto space-y-4">
          
          {/* Top Bar / Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/[0.08] pb-4">
            <div>
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-purple-500/15 border border-purple-400/30 text-purple-400 shadow-[0_0_15px_rgba(168,85,247,0.3)]">
                  <Sparkles className="w-5 h-5" />
                </div>
                <div>
                  <h1 className="text-xl sm:text-2xl font-bold text-white font-display flex items-center gap-2">
                    <span>Malix AI Security Assistant</span>
                    <span className="text-xs px-2.5 py-0.5 rounded-full font-mono font-semibold bg-purple-500/20 text-purple-300 border border-purple-400/30">
                      STREAMING • COGNITIVE
                    </span>
                  </h1>
                  <p className="text-xs text-slate-400 font-mono flex items-center gap-2 pt-0.5">
                    <span>Real-Time Cognitive Threat Intelligence</span>
                    <span>•</span>
                    <span className="text-cyan-400 flex items-center gap-1">
                      <Globe className="w-3 h-3" /> English • Hinglish • हिंदी
                    </span>
                  </p>
                </div>
              </div>
            </div>

            {/* Actions: Clear session */}
            <div className="flex items-center gap-2">
              <button
                onClick={handleClearHistory}
                className="px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-white/[0.08] text-xs text-slate-300 flex items-center gap-1.5 transition-colors"
                title="Clear current chat conversation"
              >
                <Trash2 className="w-3.5 h-3.5 text-slate-400" />
                <span>Reset Chat</span>
              </button>
            </div>
          </div>

          {/* Grounding Scan Selector Bar */}
          <div className="p-3.5 rounded-xl bg-[#070F1E] border border-cyan-500/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-lg">
            <div className="flex items-center gap-2 text-xs font-mono">
              <Layers className="w-4 h-4 text-cyan-400 shrink-0" />
              <span className="text-slate-300 font-semibold">Active Grounding Scan:</span>
              <span className="text-slate-500 text-xs hidden md:inline">
                (Grounds analysis on real PE features, entropy & ML probabilities)
              </span>
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <select
                value={selectedScanId}
                onChange={(e) => setSelectedScanId(e.target.value)}
                disabled={isLoadingScans || isSending}
                aria-label="Active Grounding Scan"
                className="w-full sm:w-72 px-3 py-1.5 rounded-lg bg-[#040812] border border-white/[0.12] focus:border-cyan-400 text-xs text-slate-200 font-mono focus:outline-none"
              >
                <option value="">None (General Security Discussion)</option>
                {userScans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.file_name} ({s.verdict}) — {s.sha256.substring(0, 8)}...
                  </option>
                ))}
              </select>

              {activeScan && (
                <button
                  onClick={() => setSelectedScanId("")}
                  disabled={isSending}
                  className="px-2 py-1.5 rounded-lg bg-red-950/40 border border-red-500/30 text-red-400 text-xs hover:bg-red-900/40 disabled:opacity-40"
                  title="Remove scan grounding"
                >
                  ✕
                </button>
              )}
            </div>
          </div>

          {/* Suggested Questions Section */}
          {suggestedQuestions && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-mono text-slate-400 flex items-center gap-1.5">
                  <HelpCircle className="w-3.5 h-3.5 text-purple-400" />
                  Suggested Inquiries:
                </span>

                {/* Language Switcher Tabs */}
                <div className="flex items-center gap-1 p-0.5 bg-[#060D19] rounded-lg border border-white/[0.08] text-xs font-mono">
                  <button
                    onClick={() => setActiveLangTab("english")}
                    className={`px-2.5 py-0.5 rounded transition-all ${
                      activeLangTab === "english"
                        ? "bg-purple-600 text-white font-bold"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    English
                  </button>
                  <button
                    onClick={() => setActiveLangTab("hinglish")}
                    className={`px-2.5 py-0.5 rounded transition-all ${
                      activeLangTab === "hinglish"
                        ? "bg-cyan-600 text-white font-bold"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Hinglish
                  </button>
                  <button
                    onClick={() => setActiveLangTab("hindi")}
                    className={`px-2.5 py-0.5 rounded transition-all ${
                      activeLangTab === "hindi"
                        ? "bg-purple-600 text-white font-bold"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    हिंदी
                  </button>
                </div>
              </div>

              {/* Chips Carousel */}
              <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-thin">
                {suggestedQuestions.categories[activeLangTab]?.map((q: SuggestedQuestionItem) => (
                  <button
                    key={q.id}
                    onClick={() => handleSendMessage(q.prompt)}
                    disabled={isSending}
                    className="shrink-0 px-3 py-1.5 rounded-lg bg-[#070F1E] hover:bg-[#0c182e] border border-white/[0.08] hover:border-purple-400/40 text-xs text-slate-300 font-mono transition-all flex items-center gap-1.5 group disabled:opacity-40"
                  >
                    <span>{q.title}</span>
                    <ArrowRight className="w-3 h-3 text-slate-500 group-hover:text-cyan-400 transition-colors" />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Chat Messages Container */}
          <div className="flex-1 min-h-[300px] h-[52vh] sm:h-[55vh] md:h-[580px] overflow-y-auto rounded-2xl bg-[#070F1E]/80 border border-white/[0.08] p-3 xs:p-4 sm:p-6 space-y-4 shadow-inner">
            {messages.map((msg, idx) => (
              <div
                key={idx}
                className={`flex gap-2.5 sm:gap-4 ${
                  msg.role === "user" ? "justify-end" : "justify-start"
                }`}
              >
                {/* Bot Avatar */}
                {msg.role === "model" && (
                  <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-xl bg-purple-500/20 border border-purple-400/40 text-purple-300 flex items-center justify-center shrink-0 shadow-[0_0_10px_rgba(168,85,247,0.3)]">
                    <Sparkles className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
                  </div>
                )}

                {/* Message Bubble */}
                <div
                  className={`max-w-[90%] sm:max-w-[78%] rounded-2xl p-3.5 sm:p-4 text-xs sm:text-sm leading-relaxed relative group ${
                    msg.role === "user"
                      ? "bg-gradient-to-r from-cyan-600/90 to-blue-600/90 text-white rounded-tr-none shadow-md"
                      : "bg-[#0A1426] border border-purple-500/20 text-slate-200 rounded-tl-none shadow-xl"
                  }`}
                >
                  {/* Grounded Tag */}
                  {msg.groundedScan && (
                    <div className="flex items-center gap-1.5 pb-2 text-xs font-mono text-cyan-300 border-b border-white/[0.08] mb-2">
                      <FileCode className="w-3 h-3" />
                      <span>Grounded on: {msg.groundedScan}</span>
                    </div>
                  )}

                  {/* Immediate Typing Indicator (shown before first token arrives) */}
                  {msg.role === "model" && msg.isStreaming && !msg.content ? (
                    <div className="flex items-center gap-2 py-1 text-purple-300 font-mono text-xs">
                      <span className="inline-block w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                      <span className="inline-flex gap-1 items-center">
                        <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-bounce [animation-delay:-0.3s]" />
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce [animation-delay:-0.15s]" />
                        <span className="w-1.5 h-1.5 rounded-full bg-purple-300 animate-bounce" />
                      </span>
                      <span className="text-xs text-slate-400 ml-1">Analyzing PE indicators with Malix...</span>
                    </div>
                  ) : msg.role === "model" ? (
                    /* Render Markdown with Cyber Neon syntax highlighting & styling */
                    <MarkdownMessage
                      content={msg.content}
                      isStreaming={msg.isStreaming}
                    />
                  ) : (
                    /* User Message Content */
                    <div className="whitespace-pre-wrap font-sans text-xs sm:text-sm leading-relaxed">
                      {msg.content}
                    </div>
                  )}

                  {/* Timestamp & Copy button */}
                  <div className="flex items-center justify-between pt-2 mt-1 border-t border-white/[0.04] text-[11px] text-slate-400 font-mono">
                    <span>{isMounted ? (msg.timestamp || "") : ""}</span>
                    {msg.content && (
                      <button
                        onClick={() => handleCopy(msg.content, idx)}
                        className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:text-white"
                        title="Copy text"
                      >
                        {copiedIndex === idx ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3 text-slate-400" />
                        )}
                      </button>
                    )}
                  </div>
                </div>

                {/* User Avatar */}
                {msg.role === "user" && (
                  <div className="w-8 h-8 rounded-xl bg-cyan-500/20 border border-cyan-400/40 text-cyan-300 flex items-center justify-center shrink-0">
                    <User className="w-4 h-4" />
                  </div>
                )}
              </div>
            ))}

            <div ref={messagesEndRef} />
          </div>

          {/* Error Notice */}
          {errorMessage && (
            <div className="p-3 rounded-xl bg-red-950/60 border border-red-500/30 text-red-300 text-xs font-mono flex items-center justify-between gap-3 shadow-lg">
              <div className="flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
                <span>{errorMessage}</span>
              </div>
              {(errorMessage.toLowerCase().includes("session") ||
                errorMessage.toLowerCase().includes("authentication") ||
                errorMessage.toLowerCase().includes("sign in") ||
                errorMessage.toLowerCase().includes("log in") ||
                errorMessage.includes("401")) && (
                <button
                  type="button"
                  onClick={() => router.push("/login?redirectTo=/copilot")}
                  className="px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 border border-red-400/40 text-white font-semibold text-xs shrink-0 transition-colors cursor-pointer"
                >
                  Log In
                </button>
              )}
            </div>
          )}

          {/* Prompt Input Form */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="relative rounded-2xl bg-[#070F1E] border border-white/[0.12] focus-within:border-cyan-400/80 p-2 shadow-2xl transition-all"
          >
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                disabled={isSending}
                placeholder={
                  activeScan
                    ? `Ask Malix about ${activeScan.file_name} in English, Hinglish or Hindi...`
                    : "Ask Malix AI in English, Hinglish, or Hindi (max 2000 chars)..."
                }
                className="flex-1 bg-transparent px-3 py-2 text-xs sm:text-sm text-white placeholder-slate-500 focus:outline-none font-sans"
              />

              {/* Stop button while streaming */}
              {isSending ? (
                <button
                  type="button"
                  onClick={handleStopStreaming}
                  className="px-3.5 py-2 rounded-xl bg-red-950/60 hover:bg-red-900/80 border border-red-500/40 text-red-300 text-xs font-mono flex items-center gap-1.5 transition-all shadow-[0_0_10px_rgba(239,68,68,0.25)] shrink-0"
                  title="Stop generating response"
                >
                  <Square className="w-3.5 h-3.5 fill-current" />
                  <span>Stop</span>
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={!inputValue.trim()}
                  className="px-4 py-2 rounded-xl bg-gradient-to-r from-purple-600 to-cyan-500 hover:from-purple-500 hover:to-cyan-400 disabled:opacity-40 text-white font-semibold text-xs flex items-center gap-1.5 transition-all shadow-[0_0_15px_rgba(34,211,238,0.3)] shrink-0"
                >
                  <span>Send</span>
                  <Send className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Bottom Bar: Character counter & Info */}
            <div className="flex items-center justify-between px-3 pt-1 text-[10px] font-mono text-slate-500">
              <div className="flex items-center gap-2">
                <span>Fast Real-Time Streaming</span>
                {activeScan && (
                  <span className="text-cyan-400">
                    • Active Artifact: {activeScan.file_name}
                  </span>
                )}
              </div>
              <div>{inputValue.length}/2000</div>
            </div>
          </form>

        </main>
      </div>
    </div>
  );
}

export default function CopilotPage() {
  return (
    <React.Suspense
      fallback={
        <div className="flex h-screen w-full items-center justify-center bg-[#050B14] text-cyan-400 font-mono text-sm">
          Loading Malix AI Copilot...
        </div>
      }
    >
      <CopilotContent />
    </React.Suspense>
  );
}
