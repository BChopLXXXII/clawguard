/**
 * run-scanner-test.mjs
 *
 * Tests the scanner engine against malicious-skill.md and clean-skill.md
 * using plain Node.js (no TypeScript transpilation needed for the test runner).
 *
 * Run: node test/run-scanner-test.mjs
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");

// ─── Inline the scanner logic (avoids needing ts-node) ──────────────────────

const THREAT_PATTERNS = [
  // EXFILTRATION
  {
    id: "exfil-curl-post",
    category: "exfiltration",
    severity: "critical",
    name: "curl POST to external URL",
    description: "Data is being POSTed to an external server via curl.",
    pattern: /curl\s+(?:-[a-zA-Z\s\S]*?)?(?:-X\s+POST|--request\s+POST|--data(?:-urlencode|-binary|)\s|--form\s|-F\s|-d\s)[^\n]*(?:http[s]?:\/\/(?!localhost|127\.0\.0\.1)[^\s'"]+)/gi,
  },
  {
    id: "exfil-wget-post",
    category: "exfiltration",
    severity: "critical",
    name: "wget POST to external URL",
    description: "Data is being POSTed to an external server via wget.",
    pattern: /wget\s+(?:--post-data|--post-file)\s*=?\s*[^\n]*(?:http[s]?:\/\/(?!localhost|127\.0\.0\.1)[^\s'"]+)/gi,
  },
  {
    id: "exfil-fetch-post",
    category: "exfiltration",
    severity: "high",
    name: "fetch() POST to external URL",
    description: "JavaScript fetch() call POSTing data to an external URL.",
    pattern: /fetch\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1)[^'"`\s]+['"`]\s*,\s*\{[^}]*method\s*:\s*['"`]POST['"`]/gi,
  },
  {
    id: "exfil-axios-post",
    category: "exfiltration",
    severity: "high",
    name: "axios POST to external URL",
    description: "axios.post() sending data to an external server.",
    pattern: /axios\.post\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1)[^'"`\s]+['"`]/gi,
  },
  {
    id: "exfil-nc-exfil",
    category: "exfiltration",
    severity: "critical",
    name: "netcat data exfiltration",
    description: "Data piped to netcat (nc) for transmission.",
    pattern: /(?:cat\s+\S+\s*\|\s*nc|nc\s+\S+\s+\d+\s*<)/gi,
  },
  // CRYPTO
  {
    id: "crypto-bitcoin-dir",
    category: "crypto_wallet",
    severity: "critical",
    name: "Bitcoin wallet directory access",
    description: "Skill is accessing the .bitcoin directory.",
    pattern: /\.bitcoin(?:\/|\\)/gi,
  },
  {
    id: "crypto-wallet-dat",
    category: "crypto_wallet",
    severity: "critical",
    name: "wallet.dat file access",
    description: "wallet.dat is the primary Bitcoin Core wallet file.",
    pattern: /wallet\.dat/gi,
  },
  {
    id: "crypto-seed-phrase",
    category: "crypto_wallet",
    severity: "critical",
    name: "Seed phrase pattern",
    description: "Skill is searching for mnemonic seed phrases.",
    pattern: /(?:seed.?phrase|mnemonic|recovery.?words?|secret.?recovery|wallet.?seed)/gi,
  },
  {
    id: "crypto-aws-credentials",
    category: "env_harvesting",
    severity: "critical",
    name: "AWS credentials file access",
    description: "Skill is accessing the AWS credentials file.",
    pattern: /~\/\.aws\/credentials|\.aws\/config/gi,
  },
  {
    id: "crypto-metamask",
    category: "crypto_wallet",
    severity: "critical",
    name: "MetaMask vault access",
    description: "Skill is targeting the MetaMask browser extension vault.",
    pattern: /(?:metamask|Local\s+Storage\/[a-z]+\.metamask|chrome.*metamask.*vault)/gi,
  },
  // OBFUSCATION
  {
    id: "obfus-base64-eval",
    category: "obfuscation",
    severity: "critical",
    name: "Base64 decode + eval chain",
    description: "A base64-encoded payload is being decoded and immediately executed.",
    pattern: /(?:eval|exec)\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode|base64_decode)\s*\(/gi,
  },
  {
    id: "obfus-base64-pipe-sh",
    category: "obfuscation",
    severity: "critical",
    name: "Base64 piped to shell",
    description: "A base64-encoded string is being decoded and piped directly to a shell.",
    pattern: /echo\s+['"]?[A-Za-z0-9+/=]{20,}['"]?\s*\|\s*(?:base64\s+-d|base64\s+--decode)\s*\|\s*(?:bash|sh|zsh|python|node)/gi,
  },
  {
    id: "obfus-fromcharcode",
    category: "obfuscation",
    severity: "high",
    name: "String.fromCharCode execution chain",
    description: "String.fromCharCode() used to hide URLs or commands.",
    pattern: /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){4,}\d+\s*\)/gi,
  },
  // ENV HARVESTING
  {
    id: "env-printenv-send",
    category: "env_harvesting",
    severity: "critical",
    name: "printenv piped to network",
    description: "All environment variables are being printed and piped to a network command.",
    pattern: /(?:printenv|env)\s*(?:\||\s+\|)\s*(?:curl|wget|nc|ncat|socat|python|node)/gi,
  },
  {
    id: "env-api-key-harvest",
    category: "env_harvesting",
    severity: "critical",
    name: "API key environment harvest",
    description: "The skill is collecting API keys or tokens from environment variables.",
    pattern: /\$(?:AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|NPM_TOKEN|PYPI_TOKEN|STRIPE_(?:SECRET_KEY|API_KEY)|DATABASE_URL|SECRET_KEY|PRIVATE_KEY)/gi,
  },
  {
    id: "env-ssh-key-access",
    category: "env_harvesting",
    severity: "critical",
    name: "SSH private key access",
    description: "Skill is reading SSH private keys.",
    pattern: /~\/\.ssh\/(?:id_rsa|id_ed25519|id_ecdsa|identity)(?:\s|$|'|")/gi,
  },
  // SHELL INJECTION
  {
    id: "shell-child-process-exec",
    category: "shell_injection",
    severity: "high",
    name: "child_process.exec() usage",
    description: "Node.js child_process.exec() spawns a shell and executes commands.",
    pattern: /(?:child_process|require\s*\(\s*['"]child_process['"]\s*\))[\s\S]{0,50}\.exec\s*\(/gi,
  },
  {
    id: "shell-subprocess-shell-true",
    category: "shell_injection",
    severity: "high",
    name: "Python subprocess with shell=True",
    description: "subprocess with shell=True enables injection.",
    pattern: /subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/gi,
  },
  {
    id: "shell-os-system",
    category: "shell_injection",
    severity: "medium",
    name: "os.system() call",
    description: "Python os.system() executes a command through the system shell.",
    pattern: /os\.system\s*\(\s*(?!\s*['"`][^'"`]*['"`]\s*\))/gi,
  },
  // HIDDEN NETWORK
  {
    id: "net-raw-ip-callback",
    category: "hidden_network",
    severity: "high",
    name: "Raw IP address callback",
    description: "Connections to raw IP addresses suggest intentional obfuscation.",
    pattern: /(?:curl|wget|fetch|http\.get|axios\.get)\s*\(\s*['"`]https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,
  },
  {
    id: "net-encoded-url",
    category: "hidden_network",
    severity: "high",
    name: "URL-encoded or obfuscated endpoint",
    description: "A URL is being constructed through encoding to evade static URL detection.",
    pattern: /(?:decodeURIComponent|unescape|atob)\s*\(\s*['"`][A-Za-z0-9%+/=]{10,}['"`]\s*\)/gi,
  },
];

function scanContent(filename, content) {
  const findings = [];
  const lines = content.split("\n");

  for (const pattern of THREAT_PATTERNS) {
    pattern.pattern.lastIndex = 0;
    for (let i = 0; i < lines.length; i++) {
      pattern.pattern.lastIndex = 0;
      const match = pattern.pattern.exec(lines[i]);
      if (match) {
        findings.push({
          pattern: pattern.id,
          severity: pattern.severity,
          category: pattern.category,
          name: pattern.name,
          lineNumber: i + 1,
          line: lines[i].trim().slice(0, 120),
        });
        pattern.pattern.lastIndex = 0;
      }
    }
  }
  return findings;
}

function rate(findings) {
  if (findings.some((f) => f.severity === "critical")) return "BLOCK";
  if (findings.some((f) => f.severity === "high")) return "WARN";
  return "PASS";
}

// ─── Run tests ───────────────────────────────────────────────────────────────

const COLORS = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  green: "\x1b[32m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
  white: "\x1b[37m",
};

function c(color, text) {
  return `${COLORS[color]}${text}${COLORS.reset}`;
}

function printResults(label, filename, findings) {
  const rating = rate(findings);
  const ratingColor = rating === "BLOCK" ? "red" : rating === "WARN" ? "yellow" : "green";

  console.log("");
  console.log(c("bold", `═══ ${label} (${filename}) ═══`));
  console.log(`Rating: ${c(ratingColor, c("bold", rating))}`);
  console.log(`Findings: ${findings.length}`);

  if (findings.length === 0) {
    console.log(c("green", "  ✓ No threats detected"));
    return;
  }

  const bySeverity = ["critical", "high", "medium", "low"];
  for (const sev of bySeverity) {
    const group = findings.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    const sevColor = sev === "critical" ? "red" : sev === "high" ? "yellow" : "cyan";
    console.log(`\n  ${c(sevColor, sev.toUpperCase())} (${group.length}):`);
    for (const f of group) {
      console.log(`    ${c("bold", f.name)} [${c("gray", f.category)}]`);
      console.log(`    ${c("gray", `Line ${f.lineNumber}:`)} ${c("white", f.line.slice(0, 100))}`);
    }
  }
}

let exitCode = 0;

// Test 1: malicious skill — expect BLOCK
const maliciousContent = readFileSync(
  resolve(__dirname, "malicious-skill.md"),
  "utf8"
);
const maliciousFindings = scanContent("malicious-skill.md", maliciousContent);
const maliciousRating = rate(maliciousFindings);
printResults("MALICIOUS SKILL TEST", "malicious-skill.md", maliciousFindings);

if (maliciousRating === "BLOCK") {
  console.log(c("green", "\n  ✓ PASS: Correctly rated as BLOCK"));
} else {
  console.log(c("red", `\n  ✗ FAIL: Expected BLOCK, got ${maliciousRating}`));
  exitCode = 1;
}

// Test 2: clean skill — expect PASS
const cleanContent = readFileSync(
  resolve(__dirname, "clean-skill.md"),
  "utf8"
);
const cleanFindings = scanContent("clean-skill.md", cleanContent);
const cleanRating = rate(cleanFindings);
printResults("CLEAN SKILL TEST", "clean-skill.md", cleanFindings);

if (cleanRating === "PASS") {
  console.log(c("green", "\n  ✓ PASS: Correctly rated as PASS"));
} else {
  console.log(c("red", `\n  ✗ FAIL: Expected PASS, got ${cleanRating}`));
  if (cleanFindings.length > 0) {
    console.log(c("yellow", "  False positives detected — review patterns:"));
    cleanFindings.forEach((f) => {
      console.log(`    [${f.severity}] ${f.name} — line ${f.lineNumber}: ${f.line.slice(0, 80)}`);
    });
  }
  exitCode = 1;
}

console.log("");
if (exitCode === 0) {
  console.log(c("green", c("bold", "All scanner tests passed.")));
} else {
  console.log(c("red", c("bold", "Some scanner tests failed.")));
}
console.log("");

process.exit(exitCode);
