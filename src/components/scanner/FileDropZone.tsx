"use client";

import React, { useState, useRef, useCallback } from "react";
import { UploadCloud, FileCode2, Shield, AlertTriangle, Binary, CheckCircle2 } from "lucide-react";

interface FileDropZoneProps {
  onFileSelected: (file: File) => void;
  isProcessing: boolean;
  disabled?: boolean;
}

export default function FileDropZone({
  onFileSelected,
  isProcessing,
  disabled = false,
}: FileDropZoneProps) {
  const [isDragOver, setIsDragOver] = useState(false);
  const [dropError, setDropError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateAndPassFile = useCallback(
    (file: File) => {
      setDropError(null);
      const lower = file.name.toLowerCase();
      const isExe = lower.endsWith(".exe");
      const isDll = lower.endsWith(".dll");

      if (!isExe && !isDll) {
        setDropError(
          `Invalid file format: "${file.name}". MALGUARD AI only inspects Windows PE binaries (.exe and .dll).`
        );
        return;
      }

      const MAX_SIZE = 10 * 1024 * 1024;
      if (file.size > MAX_SIZE) {
        const sizeMb = (file.size / (1024 * 1024)).toFixed(2);
        setDropError(
          `File size limit exceeded: "${file.name}" is ${sizeMb} MB. Maximum allowed size is 10 MB.`
        );
        return;
      }

      onFileSelected(file);
    },
    [onFileSelected]
  );

  const handleDragEnter = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled && !isProcessing) {
      setIsDragOver(true);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);

    if (disabled || isProcessing) return;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      validateAndPassFile(file);
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      validateAndPassFile(file);
    }
    // Reset so the same file can be re-selected if needed
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const handleClickBrowse = () => {
    if (!disabled && !isProcessing && fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  return (
    <div className="w-full">
      {/* Drop Target Container */}
      <div
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={handleClickBrowse}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            handleClickBrowse();
          }
        }}
        className={`relative group rounded-2xl p-5 xs:p-8 sm:p-12 text-center transition-all duration-300 cursor-pointer select-none overflow-hidden border-2 border-dashed ${
          isDragOver
            ? "border-cyan-400 bg-cyan-950/40 shadow-[0_0_35px_rgba(34,211,238,0.35)]"
            : "border-slate-700/80 hover:border-cyan-500/50 bg-[#071120]/80 hover:bg-[#0a182d]/90 shadow-[0_8px_32px_rgba(0,0,0,0.5)]"
        } ${isProcessing ? "opacity-60 pointer-events-none" : ""}`}
      >
        {/* Subtle background glow */}
        <div
          className={`absolute inset-0 bg-gradient-to-tr from-cyan-500/10 via-purple-600/10 to-transparent transition-opacity duration-300 pointer-events-none ${
            isDragOver ? "opacity-100" : "opacity-40 group-hover:opacity-70"
          }`}
        />

        {/* Hidden native input */}
        <input
          ref={fileInputRef}
          type="file"
          accept=".exe,.dll"
          onChange={handleFileInputChange}
          className="hidden"
          disabled={disabled || isProcessing}
        />

        <div className="relative z-10 flex flex-col items-center justify-center">
          {/* Animated Cyber Icon Badge */}
          <div
            className={`w-16 h-16 sm:w-20 sm:h-20 rounded-2xl flex items-center justify-center mb-4 sm:mb-5 transition-transform duration-300 border ${
              isDragOver
                ? "bg-cyan-500/20 border-cyan-400 text-cyan-300 scale-110 shadow-[0_0_25px_rgba(34,211,238,0.5)]"
                : "bg-slate-900/80 border-slate-700 group-hover:border-cyan-500/40 text-cyan-400 group-hover:scale-105 shadow-[0_0_15px_rgba(34,211,238,0.15)]"
            }`}
          >
            {isDragOver ? (
              <FileCode2 className="w-8 h-8 sm:w-10 sm:h-10 animate-pulse text-cyan-300" />
            ) : (
              <UploadCloud className="w-8 h-8 sm:w-10 sm:h-10 text-cyan-400 group-hover:-translate-y-1 transition-transform duration-300" />
            )}
          </div>

          {/* Call to action text */}
          <h3 className="text-xl sm:text-2xl font-bold text-white mb-2 font-display">
            {isDragOver ? (
              <span className="text-cyan-300">Drop PE Binary to Analyze</span>
            ) : (
              <span>Drag & Drop Binary or <span className="text-cyan-400 underline decoration-cyan-400/40 underline-offset-4">Browse</span></span>
            )}
          </h3>

          <p className="text-sm text-slate-400 max-w-md mx-auto mb-6 leading-relaxed">
            Upload a Windows PE executable or library for client-side static header analysis,
            cryptographic SHA-256 fingerprinting, and structural validation.
          </p>

          {/* Format pills */}
          <div className="flex flex-wrap items-center justify-center gap-2.5">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-900/90 border border-cyan-500/30 text-xs font-mono text-cyan-300">
              <Binary className="w-3.5 h-3.5 text-cyan-400" />
              <span>.EXE Executables</span>
            </span>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-900/90 border border-purple-500/30 text-xs font-mono text-purple-300">
              <Binary className="w-3.5 h-3.5 text-purple-400" />
              <span>.DLL Libraries</span>
            </span>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-900/90 border border-slate-700 text-xs font-mono text-slate-400">
              <Shield className="w-3.5 h-3.5 text-slate-400" />
              <span>Max 10 MB</span>
            </span>
          </div>
        </div>
      </div>

      {/* Drop Error Alert */}
      {dropError && (
        <div className="mt-4 p-4 rounded-xl bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs flex items-start gap-3 animate-in fade-in slide-in-from-top-1 duration-200">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div className="flex-1">
            <span className="font-semibold block mb-0.5">File Validation Warning</span>
            <span>{dropError}</span>
          </div>
          <button
            onClick={() => setDropError(null)}
            className="text-rose-400 hover:text-white text-xs font-mono underline"
          >
            Dismiss
          </button>
        </div>
      )}
    </div>
  );
}

