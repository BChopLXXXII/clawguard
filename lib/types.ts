export type Severity = "critical" | "high" | "medium" | "low";

export type ThreatCategory =
  | "exfiltration"
  | "crypto_wallet"
  | "obfuscation"
  | "env_harvesting"
  | "shell_injection"
  | "hidden_network";

export type OverallRating = "PASS" | "WARN" | "BLOCK";

export interface ThreatPattern {
  id: string;
  category: ThreatCategory;
  severity: Severity;
  name: string;
  description: string;
  pattern: RegExp;
  maskMatch?: boolean;
}

export interface ScanFinding {
  patternId: string;
  category: ThreatCategory;
  severity: Severity;
  name: string;
  description: string;
  lineNumber: number;
  lineContent: string;
  matchedText: string;
}

export interface CategoryResult {
  category: ThreatCategory;
  label: string;
  description: string;
  findings: ScanFinding[];
  status: "clean" | "warn" | "block";
}

export interface ScanResult {
  rating: OverallRating;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  categories: CategoryResult[];
  scannedAt: string;
  filesScanned: string[];
}

export interface ScanRequest {
  files: Array<{
    name: string;
    content: string;
  }>;
}

export interface ScanResponse {
  success: boolean;
  result?: ScanResult;
  error?: string;
}

export const CATEGORY_META: Record<
  ThreatCategory,
  { label: string; description: string }
> = {
  exfiltration: {
    label: "Data Exfiltration",
    description:
      "Outbound data transmission to external servers via HTTP/curl/wget",
  },
  crypto_wallet: {
    label: "Crypto & Wallet Access",
    description:
      "Access to cryptocurrency wallets, seed phrases, or keychain files",
  },
  obfuscation: {
    label: "Code Obfuscation",
    description:
      "Base64/hex encoded payloads, eval chains, or hidden executable code",
  },
  env_harvesting: {
    label: "Environment Harvesting",
    description:
      "Collecting API keys, tokens, or secrets from environment variables",
  },
  shell_injection: {
    label: "Shell Injection",
    description:
      "Dangerous command execution via eval, exec, or child_process",
  },
  hidden_network: {
    label: "Hidden Network Calls",
    description: "DNS exfiltration, IP-based callbacks, or encoded URLs",
  },
};
