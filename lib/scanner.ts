import { THREAT_PATTERNS } from "./patterns";
import {
  CATEGORY_META,
  type CategoryResult,
  type OverallRating,
  type ScanFinding,
  type ScanRequest,
  type ScanResult,
  type ThreatCategory,
} from "./types";

function maskSensitiveMatch(line: string, matched: string): string {
  if (matched.length <= 8) return "*".repeat(matched.length);
  const visible = 4;
  return (
    matched.slice(0, visible) +
    "*".repeat(Math.min(matched.length - visible * 2, 20)) +
    matched.slice(-visible)
  );
}

function scanFile(
  filename: string,
  content: string
): ScanFinding[] {
  const findings: ScanFinding[] = [];
  const lines = content.split("\n");

  for (const pattern of THREAT_PATTERNS) {
    // Reset lastIndex for global regexes
    pattern.pattern.lastIndex = 0;

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];
      // Reset between lines
      pattern.pattern.lastIndex = 0;

      const match = pattern.pattern.exec(line);
      if (match) {
        const matchedText = match[0];
        const displayMatch = pattern.maskMatch
          ? maskSensitiveMatch(matchedText, matchedText)
          : matchedText;

        // Trim line content to 200 chars for display
        const lineContent =
          line.length > 200 ? line.slice(0, 197) + "..." : line;

        findings.push({
          patternId: pattern.id,
          category: pattern.category,
          severity: pattern.severity,
          name: pattern.name,
          description: pattern.description,
          lineNumber: lineIndex + 1,
          lineContent: lineContent.trim(),
          matchedText: displayMatch,
        });

        // Reset for next line search
        pattern.pattern.lastIndex = 0;
      }
    }
  }

  return findings;
}

function deriveRating(
  criticalCount: number,
  highCount: number
): OverallRating {
  if (criticalCount > 0) return "BLOCK";
  if (highCount > 0) return "WARN";
  return "PASS";
}

function categoryStatus(findings: ScanFinding[]): "clean" | "warn" | "block" {
  const hasCritical = findings.some((f) => f.severity === "critical");
  const hasHigh = findings.some((f) => f.severity === "high");
  if (hasCritical) return "block";
  if (hasHigh) return "warn";
  if (findings.length > 0) return "warn";
  return "clean";
}

export function runScan(request: ScanRequest): ScanResult {
  const allFindings: ScanFinding[] = [];

  for (const file of request.files) {
    const fileFindings = scanFile(file.name, file.content);
    allFindings.push(...fileFindings);
  }

  // Deduplicate: same pattern on same line of same finding content
  const seen = new Set<string>();
  const deduped = allFindings.filter((f) => {
    const key = `${f.patternId}:${f.lineNumber}:${f.lineContent.slice(0, 60)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const criticalCount = deduped.filter((f) => f.severity === "critical").length;
  const highCount = deduped.filter((f) => f.severity === "high").length;
  const mediumCount = deduped.filter((f) => f.severity === "medium").length;
  const lowCount = deduped.filter((f) => f.severity === "low").length;

  const allCategories: ThreatCategory[] = [
    "exfiltration",
    "crypto_wallet",
    "obfuscation",
    "env_harvesting",
    "shell_injection",
    "hidden_network",
    "reverse_shell",
    "download_execute",
    "file_destruction",
    "persistence",
    "privilege_escalation",
    "powershell",
    "browser_theft",
    "clipboard_hijack",
    "windows_lolbins",
    "network_listener",
  ];

  const categories: CategoryResult[] = allCategories.map((cat) => {
    const catFindings = deduped.filter((f) => f.category === cat);
    const meta = CATEGORY_META[cat];
    return {
      category: cat,
      label: meta.label,
      description: meta.description,
      findings: catFindings,
      status: categoryStatus(catFindings),
    };
  });

  return {
    rating: deriveRating(criticalCount, highCount),
    totalFindings: deduped.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    categories,
    scannedAt: new Date().toISOString(),
    filesScanned: request.files.map((f) => f.name),
  };
}
