"use client";

import { useState, useRef, useCallback } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Upload,
  X,
  Scan,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Minus,
  FileText,
  ArrowLeft,
  Loader2,
  Info,
} from "lucide-react";
import type {
  ScanResult,
  ScanResponse,
  CategoryResult,
  ScanFinding,
  Severity,
} from "@/lib/types";

type InputMode = "paste" | "upload";

interface UploadedFile {
  name: string;
  content: string;
  size: number;
}

// ─── Severity helpers ──────────────────────────────────────────────────────

function severityColors(severity: Severity) {
  switch (severity) {
    case "critical":
      return {
        bg: "bg-[var(--accent-red-bg)]",
        text: "text-[var(--accent-red)]",
        border: "border-[rgba(255,68,68,0.3)]",
        badge:
          "bg-[var(--accent-red-bg)] text-[var(--accent-red)] border border-[rgba(255,68,68,0.4)]",
      };
    case "high":
      return {
        bg: "bg-[var(--accent-yellow-bg)]",
        text: "text-[var(--accent-yellow)]",
        border: "border-[rgba(255,170,0,0.3)]",
        badge:
          "bg-[var(--accent-yellow-bg)] text-[var(--accent-yellow)] border border-[rgba(255,170,0,0.4)]",
      };
    case "medium":
      return {
        bg: "bg-blue-950/40",
        text: "text-blue-300",
        border: "border-blue-700/30",
        badge: "bg-blue-950/40 text-blue-300 border border-blue-700/30",
      };
    case "low":
      return {
        bg: "bg-gray-900/60",
        text: "text-gray-400",
        border: "border-gray-700/30",
        badge: "bg-gray-900/60 text-gray-400 border border-gray-700/30",
      };
  }
}

function categoryStatusColors(status: CategoryResult["status"]) {
  switch (status) {
    case "block":
      return { icon: XCircle, color: "text-[var(--accent-red)]" };
    case "warn":
      return { icon: AlertTriangle, color: "text-[var(--accent-yellow)]" };
    case "clean":
      return { icon: CheckCircle, color: "text-[var(--accent-green)]" };
  }
}

// ─── Sub-components ────────────────────────────────────────────────────────

function FindingCard({ finding }: { finding: ScanFinding }) {
  const colors = severityColors(finding.severity);
  return (
    <div
      style={{ backgroundColor: "var(--bg-primary)", border: "1px solid var(--border)" }}
      className="rounded-lg overflow-hidden"
    >
      <div className="px-4 py-3 flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span
              className={`text-xs font-semibold px-2 py-0.5 rounded-full uppercase tracking-wide ${colors.badge}`}
            >
              {finding.severity}
            </span>
            <span
              style={{ color: "var(--text-primary)" }}
              className="text-sm font-medium"
            >
              {finding.name}
            </span>
          </div>
          <p
            style={{ color: "var(--text-secondary)" }}
            className="text-xs leading-relaxed"
          >
            {finding.description}
          </p>
        </div>
        <span
          style={{
            color: "var(--text-muted)",
            backgroundColor: "var(--bg-card)",
            border: "1px solid var(--border)",
          }}
          className="text-xs px-2 py-1 rounded font-mono flex-shrink-0"
        >
          L{finding.lineNumber}
        </span>
      </div>
      <div
        style={{ backgroundColor: "var(--bg-secondary)", borderTop: "1px solid var(--border)" }}
        className="px-4 py-2.5"
      >
        <p
          style={{ color: "var(--text-muted)" }}
          className="text-xs font-mono mb-0.5"
        >
          Line {finding.lineNumber}:
        </p>
        <code
          className={`text-xs font-mono break-all ${colors.text}`}
        >
          {finding.lineContent}
        </code>
      </div>
    </div>
  );
}

function CategoryBlock({ cat }: { cat: CategoryResult }) {
  const [expanded, setExpanded] = useState(false);
  const statusColors = categoryStatusColors(cat.status);
  const StatusIcon = statusColors.icon;

  return (
    <div
      style={{
        backgroundColor: "var(--bg-card)",
        border: "1px solid var(--border)",
      }}
      className="rounded-xl overflow-hidden"
    >
      <button
        className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-white/5 transition-colors"
        onClick={() => cat.findings.length > 0 && setExpanded((v) => !v)}
        disabled={cat.findings.length === 0}
      >
        <div className="flex items-center gap-3">
          <StatusIcon size={18} strokeWidth={2} className={statusColors.color} />
          <div>
            <span
              style={{ color: "var(--text-primary)" }}
              className="font-medium text-sm"
            >
              {cat.label}
            </span>
            <p
              style={{ color: "var(--text-muted)" }}
              className="text-xs mt-0.5"
            >
              {cat.description}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          {cat.findings.length > 0 && (
            <span
              style={{
                backgroundColor:
                  cat.status === "block"
                    ? "var(--accent-red-bg)"
                    : "var(--accent-yellow-bg)",
                color:
                  cat.status === "block"
                    ? "var(--accent-red)"
                    : "var(--accent-yellow)",
                border:
                  cat.status === "block"
                    ? "1px solid rgba(255,68,68,0.3)"
                    : "1px solid rgba(255,170,0,0.3)",
              }}
              className="text-xs font-medium px-2.5 py-1 rounded-full"
            >
              {cat.findings.length} finding{cat.findings.length !== 1 ? "s" : ""}
            </span>
          )}
          {cat.findings.length > 0 && (
            expanded ? (
              <ChevronUp size={16} style={{ color: "var(--text-muted)" }} />
            ) : (
              <ChevronDown size={16} style={{ color: "var(--text-muted)" }} />
            )
          )}
          {cat.findings.length === 0 && (
            <span
              style={{ color: "var(--accent-green)" }}
              className="text-xs font-medium"
            >
              Clean
            </span>
          )}
        </div>
      </button>

      {expanded && cat.findings.length > 0 && (
        <div
          style={{ borderTop: "1px solid var(--border)" }}
          className="p-4 space-y-3"
        >
          {cat.findings.map((finding, i) => (
            <FindingCard key={`${finding.patternId}-${i}`} finding={finding} />
          ))}
        </div>
      )}
    </div>
  );
}

function RatingBadge({ rating }: { rating: ScanResult["rating"] }) {
  if (rating === "BLOCK") {
    return (
      <div className="flex flex-col items-center gap-3">
        <ShieldX size={52} className="text-[var(--accent-red)]" strokeWidth={1.5} />
        <div
          style={{
            backgroundColor: "var(--accent-red-bg)",
            border: "2px solid var(--accent-red)",
            color: "var(--accent-red)",
          }}
          className="px-10 py-3 rounded-xl text-3xl font-bold tracking-widest"
        >
          BLOCK
        </div>
        <p style={{ color: "var(--text-secondary)" }} className="text-sm text-center max-w-xs">
          Critical threats detected. Do not install this skill.
        </p>
      </div>
    );
  }
  if (rating === "WARN") {
    return (
      <div className="flex flex-col items-center gap-3">
        <ShieldAlert size={52} className="text-[var(--accent-yellow)]" strokeWidth={1.5} />
        <div
          style={{
            backgroundColor: "var(--accent-yellow-bg)",
            border: "2px solid var(--accent-yellow)",
            color: "var(--accent-yellow)",
          }}
          className="px-10 py-3 rounded-xl text-3xl font-bold tracking-widest"
        >
          WARN
        </div>
        <p style={{ color: "var(--text-secondary)" }} className="text-sm text-center max-w-xs">
          Suspicious patterns found. Review carefully before installing.
        </p>
      </div>
    );
  }
  return (
    <div className="flex flex-col items-center gap-3">
      <ShieldCheck size={52} className="text-[var(--accent-green)]" strokeWidth={1.5} />
      <div
        style={{
          backgroundColor: "var(--accent-green-bg)",
          border: "2px solid var(--accent-green)",
          color: "var(--accent-green)",
        }}
        className="px-10 py-3 rounded-xl text-3xl font-bold tracking-widest"
      >
        PASS
      </div>
      <p style={{ color: "var(--text-secondary)" }} className="text-sm text-center max-w-xs">
        No threats detected. Skill appears safe.
      </p>
    </div>
  );
}

function StatPill({
  count,
  label,
  variant,
}: {
  count: number;
  label: string;
  variant: "critical" | "high" | "medium" | "low";
}) {
  const colors = severityColors(variant);
  if (count === 0) return null;
  return (
    <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg ${colors.badge}`}>
      <span className="text-lg font-bold">{count}</span>
      <span className="text-xs font-medium opacity-80">{label}</span>
    </div>
  );
}

// ─── Main Scanner Page ─────────────────────────────────────────────────────

export default function ScanPage() {
  const [mode, setMode] = useState<InputMode>("paste");
  const [pasteContent, setPasteContent] = useState("");
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  const handleFileUpload = useCallback((files: FileList | File[]) => {
    const allowed = [".md", ".sh", ".js", ".ts", ".py", ".txt"];
    const toProcess = Array.from(files).filter((f) =>
      allowed.some((ext) => f.name.toLowerCase().endsWith(ext))
    );

    if (toProcess.length === 0) {
      setError("Only .md, .sh, .js, .ts, .py files are supported.");
      return;
    }

    Promise.all(
      toProcess.map(
        (file) =>
          new Promise<UploadedFile>((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) =>
              resolve({
                name: file.name,
                content: e.target?.result as string,
                size: file.size,
              });
            reader.onerror = reject;
            reader.readAsText(file);
          })
      )
    ).then((results) => {
      setUploadedFiles((prev) => {
        const existing = new Set(prev.map((f) => f.name));
        const fresh = results.filter((f) => !existing.has(f.name));
        return [...prev, ...fresh].slice(0, 10);
      });
      setError(null);
    });
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      handleFileUpload(e.dataTransfer.files);
    },
    [handleFileUpload]
  );

  const removeFile = (name: string) => {
    setUploadedFiles((prev) => prev.filter((f) => f.name !== name));
  };

  const handleScan = async () => {
    setError(null);
    setResult(null);

    const files: Array<{ name: string; content: string }> = [];

    if (mode === "paste") {
      if (!pasteContent.trim()) {
        setError("Please paste skill content before scanning.");
        return;
      }
      files.push({ name: "pasted-skill.md", content: pasteContent });
    } else {
      if (uploadedFiles.length === 0) {
        setError("Please upload at least one file before scanning.");
        return;
      }
      files.push(...uploadedFiles.map((f) => ({ name: f.name, content: f.content })));
    }

    setIsScanning(true);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ files }),
      });

      const data: ScanResponse = await res.json();

      if (!data.success || !data.result) {
        setError(data.error ?? "Unknown error occurred");
        return;
      }

      setResult(data.result);
      setTimeout(() => {
        resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 100);
    } catch (e) {
      setError(`Network error: ${e instanceof Error ? e.message : "Failed to reach scan API"}`);
    } finally {
      setIsScanning(false);
    }
  };

  const handleReset = () => {
    setResult(null);
    setError(null);
    setPasteContent("");
    setUploadedFiles([]);
  };

  return (
    <div
      style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-primary)" }}
      className="min-h-screen"
    >
      {/* Nav */}
      <nav
        style={{
          borderBottom: "1px solid var(--border)",
          backgroundColor: "var(--bg-primary)",
        }}
        className="sticky top-0 z-50"
      >
        <div className="max-w-4xl mx-auto px-6 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
            <ArrowLeft size={16} style={{ color: "var(--text-muted)" }} />
            <ShieldCheck size={20} style={{ color: "var(--accent-blue)" }} strokeWidth={2} />
            <span className="font-semibold text-sm tracking-tight">ClawGuard</span>
          </Link>
          <span
            style={{
              color: "var(--text-muted)",
              backgroundColor: "var(--bg-card)",
              border: "1px solid var(--border)",
            }}
            className="text-xs px-3 py-1 rounded-full"
          >
            Skill Security Scanner
          </span>
        </div>
      </nav>

      <main className="max-w-4xl mx-auto px-6 py-10">
        <div className="mb-8">
          <h1
            style={{ color: "var(--text-primary)" }}
            className="text-3xl font-bold tracking-tight mb-2"
          >
            Scan a skill
          </h1>
          <p style={{ color: "var(--text-secondary)" }} className="text-base">
            Paste or upload skill files to run a full security analysis.
          </p>
        </div>

        {/* Input mode tabs */}
        <div
          style={{
            backgroundColor: "var(--bg-card)",
            border: "1px solid var(--border)",
          }}
          className="rounded-xl p-1 flex gap-1 mb-6 w-fit"
        >
          {(["paste", "upload"] as InputMode[]).map((m) => (
            <button
              key={m}
              onClick={() => { setMode(m); setError(null); }}
              style={
                mode === m
                  ? {
                      backgroundColor: "var(--bg-secondary)",
                      color: "var(--text-primary)",
                      border: "1px solid var(--border)",
                    }
                  : { color: "var(--text-muted)" }
              }
              className="px-5 py-2 rounded-lg text-sm font-medium capitalize transition-all"
            >
              {m === "paste" ? "Paste content" : "Upload files"}
            </button>
          ))}
        </div>

        {/* Input area */}
        {mode === "paste" ? (
          <div className="mb-6">
            <div className="flex items-center justify-between mb-2">
              <label
                style={{ color: "var(--text-secondary)" }}
                className="text-sm font-medium"
              >
                Skill content (SKILL.md + any referenced scripts)
              </label>
              {pasteContent && (
                <button
                  onClick={() => setPasteContent("")}
                  style={{ color: "var(--text-muted)" }}
                  className="text-xs hover:text-white transition-colors flex items-center gap-1"
                >
                  <X size={12} />
                  Clear
                </button>
              )}
            </div>
            <textarea
              value={pasteContent}
              onChange={(e) => setPasteContent(e.target.value)}
              placeholder={`# My Skill\n\nPaste the full contents of SKILL.md and any referenced shell scripts or JavaScript files here...\n\n---\n\n# install.sh\n#!/bin/bash\n...`}
              style={{
                backgroundColor: "var(--bg-card)",
                border: "1px solid var(--border)",
                color: "var(--text-primary)",
                resize: "vertical",
              }}
              className="w-full h-72 rounded-xl p-4 text-sm font-mono placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent-blue)] transition-colors"
              spellCheck={false}
            />
            <p style={{ color: "var(--text-muted)" }} className="text-xs mt-2">
              Tip: Separate multiple files with a comment header like{" "}
              <code
                style={{
                  backgroundColor: "var(--bg-card)",
                  border: "1px solid var(--border)",
                  color: "var(--text-secondary)",
                }}
                className="px-1.5 py-0.5 rounded text-xs"
              >
                # filename.sh
              </code>
            </p>
          </div>
        ) : (
          <div className="mb-6">
            {/* Drop zone */}
            <div
              onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              style={{
                backgroundColor: isDragging ? "var(--accent-blue-bg)" : "var(--bg-card)",
                border: `2px dashed ${isDragging ? "var(--accent-blue)" : "var(--border)"}`,
                transition: "all 0.15s ease",
              }}
              className="rounded-xl p-10 flex flex-col items-center justify-center gap-3 cursor-pointer hover:border-[var(--accent-blue)] group"
            >
              <Upload
                size={32}
                style={{ color: isDragging ? "var(--accent-blue)" : "var(--text-muted)" }}
                strokeWidth={1.5}
                className="group-hover:text-[var(--accent-blue)] transition-colors"
              />
              <div className="text-center">
                <p style={{ color: "var(--text-primary)" }} className="font-medium mb-1">
                  Drop files here or click to browse
                </p>
                <p style={{ color: "var(--text-muted)" }} className="text-sm">
                  Supports .md, .sh, .js, .ts, .py — up to 10 files
                </p>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                className="hidden"
                multiple
                accept=".md,.sh,.js,.ts,.py,.txt"
                onChange={(e) => e.target.files && handleFileUpload(e.target.files)}
              />
            </div>

            {/* Uploaded files list */}
            {uploadedFiles.length > 0 && (
              <div className="mt-4 space-y-2">
                {uploadedFiles.map((file) => (
                  <div
                    key={file.name}
                    style={{
                      backgroundColor: "var(--bg-card)",
                      border: "1px solid var(--border)",
                    }}
                    className="flex items-center justify-between px-4 py-3 rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <FileText size={16} style={{ color: "var(--accent-blue)" }} />
                      <div>
                        <span
                          style={{ color: "var(--text-primary)" }}
                          className="text-sm font-medium"
                        >
                          {file.name}
                        </span>
                        <span
                          style={{ color: "var(--text-muted)" }}
                          className="text-xs ml-3"
                        >
                          {(file.size / 1024).toFixed(1)} KB
                        </span>
                      </div>
                    </div>
                    <button
                      onClick={() => removeFile(file.name)}
                      style={{ color: "var(--text-muted)" }}
                      className="hover:text-[var(--accent-red)] transition-colors p-1"
                    >
                      <X size={16} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Error */}
        {error && (
          <div
            style={{
              backgroundColor: "var(--accent-red-bg)",
              border: "1px solid rgba(255,68,68,0.3)",
              color: "var(--accent-red)",
            }}
            className="flex items-start gap-3 px-4 py-3 rounded-xl mb-6 text-sm"
          >
            <AlertTriangle size={16} strokeWidth={2} className="flex-shrink-0 mt-0.5" />
            {error}
          </div>
        )}

        {/* Scan button */}
        <div className="flex items-center gap-4">
          <button
            onClick={handleScan}
            disabled={isScanning}
            style={{
              backgroundColor: isScanning ? "var(--bg-card)" : "var(--accent-blue)",
              color: isScanning ? "var(--text-muted)" : "white",
              border: isScanning ? "1px solid var(--border)" : "none",
            }}
            className="flex items-center gap-2.5 px-6 py-3 rounded-xl font-semibold text-sm transition-all disabled:cursor-not-allowed scanning-pulse"
          >
            {isScanning ? (
              <>
                <Loader2 size={18} className="animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Scan size={18} strokeWidth={2} />
                Run security scan
              </>
            )}
          </button>
          {result && (
            <button
              onClick={handleReset}
              style={{ color: "var(--text-muted)", border: "1px solid var(--border)" }}
              className="px-4 py-3 rounded-xl text-sm hover:text-white transition-colors"
            >
              New scan
            </button>
          )}
        </div>

        {/* Results */}
        {result && (
          <div ref={resultsRef} className="mt-12 fade-in">
            {/* Rating header */}
            <div
              style={{
                backgroundColor: "var(--bg-card)",
                border: "1px solid var(--border)",
              }}
              className="rounded-2xl p-8 mb-6"
            >
              <div className="flex flex-col md:flex-row items-center justify-between gap-8">
                <RatingBadge rating={result.rating} />

                <div className="flex flex-col gap-4">
                  <div className="flex items-center gap-3 flex-wrap justify-center md:justify-start">
                    <StatPill count={result.criticalCount} label="Critical" variant="critical" />
                    <StatPill count={result.highCount} label="High" variant="high" />
                    <StatPill count={result.mediumCount} label="Medium" variant="medium" />
                    <StatPill count={result.lowCount} label="Low" variant="low" />
                    {result.totalFindings === 0 && (
                      <div className="flex items-center gap-2 text-[var(--accent-green)]">
                        <CheckCircle size={18} strokeWidth={2} />
                        <span className="text-sm font-medium">No findings</span>
                      </div>
                    )}
                  </div>
                  <div
                    style={{ color: "var(--text-muted)" }}
                    className="text-xs space-y-1"
                  >
                    <div className="flex items-center gap-1.5">
                      <FileText size={12} />
                      Scanned: {result.filesScanned.join(", ")}
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Minus size={12} />
                      {new Date(result.scannedAt).toLocaleString()}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Disclaimer */}
            <div
              style={{
                backgroundColor: "var(--accent-blue-bg)",
                border: "1px solid rgba(68,136,255,0.2)",
                color: "var(--text-secondary)",
              }}
              className="flex items-start gap-3 px-4 py-3 rounded-xl mb-6 text-sm"
            >
              <Info size={16} strokeWidth={2} className="flex-shrink-0 mt-0.5 text-[var(--accent-blue)]" />
              <p>
                This is a static pattern scanner, not a sandbox. A PASS result
                means no known-bad patterns were detected — it does not
                guarantee the skill is safe. Always review code manually for
                high-stakes installs.
              </p>
            </div>

            {/* Category blocks */}
            <h2
              style={{ color: "var(--text-primary)" }}
              className="text-lg font-semibold mb-4"
            >
              Threat categories
            </h2>
            <div className="space-y-3">
              {result.categories.map((cat) => (
                <CategoryBlock key={cat.category} cat={cat} />
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
