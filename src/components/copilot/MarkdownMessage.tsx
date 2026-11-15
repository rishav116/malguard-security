"use client";

import React, { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Copy, Check, Terminal, Code } from "lucide-react";

interface MarkdownMessageProps {
  content: string;
  isStreaming?: boolean;
}

function CodeBlock({
  language,
  value,
}: {
  language?: string;
  value: string;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const displayLang = language ? language.toUpperCase() : "CODE / TELEMETRY";

  return (
    <div className="relative my-3 rounded-xl bg-[#030712] border border-white/[0.1] overflow-hidden shadow-2xl group">
      {/* Code Header Bar */}
      <div className="flex items-center justify-between px-3.5 py-1.5 bg-[#060D1A] border-b border-white/[0.06] text-xs font-mono text-slate-400">
        <div className="flex items-center gap-1.5">
          <Terminal className="w-3 h-3 text-cyan-400" />
          <span className="font-semibold text-slate-300">{displayLang}</span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 px-2 py-0.5 rounded bg-white/[0.04] hover:bg-white/[0.08] text-slate-400 hover:text-white transition-colors"
          title="Copy code"
        >
          {copied ? (
            <>
              <Check className="w-2.5 h-2.5 text-emerald-400" />
              <span className="text-emerald-400 font-semibold">Copied!</span>
            </>
          ) : (
            <>
              <Copy className="w-2.5 h-2.5" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>

      {/* Code Content */}
      <pre className="p-3.5 overflow-x-auto text-xs font-mono text-cyan-200 leading-relaxed scrollbar-thin">
        <code>{value}</code>
      </pre>
    </div>
  );
}

export const MarkdownMessage: React.FC<MarkdownMessageProps> = ({
  content,
  isStreaming = false,
}) => {
  return (
    <div className="font-sans text-xs sm:text-sm text-slate-200 leading-relaxed space-y-2 markdown-copilot-body">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          // Paragraphs
          p: ({ children }) => (
            <p className="leading-relaxed text-slate-200 text-xs sm:text-sm my-1.5 last:mb-0 first:mt-0">
              {children}
            </p>
          ),

          // Headings
          h1: ({ children }) => (
            <h1 className="text-base sm:text-lg font-bold text-white font-display mt-3.5 mb-1.5 pb-1 border-b border-purple-500/20 flex items-center gap-2">
              {children}
            </h1>
          ),
          h2: ({ children }) => (
            <h2 className="text-sm sm:text-base font-bold text-cyan-300 font-display mt-3 mb-1.5 flex items-center gap-1.5">
              {children}
            </h2>
          ),
          h3: ({ children }) => (
            <h3 className="text-xs sm:text-sm font-semibold text-purple-300 font-display mt-2.5 mb-1">
              {children}
            </h3>
          ),

          // Bold & Emphasis
          strong: ({ children }) => (
            <strong className="font-semibold text-white">
              {children}
            </strong>
          ),
          em: ({ children }) => (
            <em className="italic text-cyan-200/90">{children}</em>
          ),

          // Lists
          ul: ({ children }) => (
            <ul className="my-2 space-y-1.5 pl-4 list-disc marker:text-cyan-400 text-xs sm:text-sm text-slate-200">
              {children}
            </ul>
          ),
          ol: ({ children }) => (
            <ol className="my-2 space-y-1.5 pl-4 list-decimal marker:text-purple-400 text-xs sm:text-sm text-slate-200">
              {children}
            </ol>
          ),
          li: ({ children }) => (
            <li className="leading-relaxed pl-1">{children}</li>
          ),

          // Blockquote
          blockquote: ({ children }) => (
            <blockquote className="my-2.5 pl-3.5 py-1.5 border-l-2 border-purple-400 bg-purple-950/20 rounded-r-lg text-slate-300 text-xs sm:text-sm italic">
              {children}
            </blockquote>
          ),

          // Horizontal Rule
          hr: () => <hr className="my-3 border-white/[0.08]" />,

          // Links
          a: ({ href, children }) => (
            <a
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-cyan-400 hover:text-cyan-300 underline underline-offset-2 transition-colors font-medium"
            >
              {children}
            </a>
          ),

          // Tables
          table: ({ children }) => (
            <div className="my-3 overflow-x-auto rounded-xl border border-white/[0.08] shadow-lg">
              <table className="w-full text-xs font-mono border-collapse">
                {children}
              </table>
            </div>
          ),
          thead: ({ children }) => (
            <thead className="bg-[#071120] text-cyan-300 border-b border-white/[0.1]">
              {children}
            </thead>
          ),
          tbody: ({ children }) => (
            <tbody className="divide-y divide-white/[0.04] bg-[#040814]/80">
              {children}
            </tbody>
          ),
          tr: ({ children }) => (
            <tr className="hover:bg-white/[0.02] transition-colors">
              {children}
            </tr>
          ),
          th: ({ children }) => (
            <th className="px-3 py-2 text-left font-semibold">{children}</th>
          ),
          td: ({ children }) => (
            <td className="px-3 py-2 text-slate-300 whitespace-nowrap">
              {children}
            </td>
          ),

          // Code
          code: ({ className, children, ...props }) => {
            const rawContent = String(children || "");
            const match = /language-(\w+)/.exec(className || "");
            const isMultiLine = rawContent.includes("\n");

            if (match || isMultiLine) {
              return (
                <CodeBlock
                  language={match ? match[1] : undefined}
                  value={rawContent.replace(/\n$/, "")}
                />
              );
            }

            return (
              <code
                className="px-1.5 py-0.5 rounded bg-[#040814] border border-cyan-500/30 text-cyan-300 font-mono text-xs font-medium"
                {...props}
              >
                {children}
              </code>
            );
          },
        }}
      >
        {content}
      </ReactMarkdown>

      {/* Progressive streaming cursor */}
      {isStreaming && (
        <span className="inline-block w-2 h-3.5 bg-cyan-400 ml-1 animate-pulse align-middle shadow-[0_0_8px_#22d3ee]" />
      )}
    </div>
  );
};

