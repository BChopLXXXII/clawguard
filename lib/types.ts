export type Severity = "critical" | "high" | "medium" | "low";

export type ThreatCategory =
  | "exfiltration"
  | "crypto_wallet"
  | "obfuscation"
  | "env_harvesting"
  | "shell_injection"
  | "hidden_network"
  | "reverse_shell"
  | "download_execute"
  | "file_destruction"
  | "persistence"
  | "privilege_escalation"
  | "powershell"
  | "browser_theft"
  | "clipboard_hijack"
  | "windows_lolbins"
  | "network_listener";

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
  reverse_shell: {
    label: "Reverse Shell",
    description:
      "Outbound shell connections giving an attacker remote command execution",
  },
  download_execute: {
    label: "Download & Execute",
    description:
      "Fetching remote code and piping it directly into a shell interpreter",
  },
  file_destruction: {
    label: "File Destruction",
    description:
      "Dangerous file deletion, disk wiping, or recursive removal commands",
  },
  persistence: {
    label: "Persistence & Backdoors",
    description:
      "Installing cron jobs, systemd services, or startup items to survive reboots",
  },
  privilege_escalation: {
    label: "Privilege Escalation",
    description:
      "Attempts to gain elevated permissions via sudo, setuid, or permission changes",
  },
  powershell: {
    label: "PowerShell Threats",
    description:
      "Malicious PowerShell patterns including encoded commands, bypass flags, and hidden execution",
  },
  browser_theft: {
    label: "Browser Data Theft",
    description:
      "Accessing browser cookies, saved passwords, history, or extension data",
  },
  clipboard_hijack: {
    label: "Clipboard Hijack",
    description:
      "Reading or replacing clipboard contents, often used for crypto address swaps",
  },
  windows_lolbins: {
    label: "Windows LOLBins",
    description:
      "Abuse of legitimate Windows binaries (certutil, mshta, bitsadmin, regsvr32) for malicious purposes",
  },
  network_listener: {
    label: "Network Listener",
    description:
      "Opening ports to listen for inbound connections, often used for reverse shells or C2",
  },
};
