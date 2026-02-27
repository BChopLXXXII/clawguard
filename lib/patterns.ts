import type { ThreatPattern } from "./types";

export const THREAT_PATTERNS: ThreatPattern[] = [
  // ─── EXFILTRATION ──────────────────────────────────────────────────────────
  {
    id: "exfil-curl-post",
    category: "exfiltration",
    severity: "critical",
    name: "curl POST to external URL",
    description:
      "Data is being POSTed to an external server via curl. This is a common method for exfiltrating credentials or environment data.",
    pattern:
      /curl\s+(?:-[a-zA-Z\s\S]*?)?(?:-X\s+POST|--request\s+POST|--data(?:-urlencode|-binary|)\s|--form\s|-F\s|-d\s)[^\n]*(?:http[s]?:\/\/(?!localhost|127\.0\.0\.1)[^\s'"]+)/gi,
    maskMatch: false,
  },
  {
    id: "exfil-wget-post",
    category: "exfiltration",
    severity: "critical",
    name: "wget POST to external URL",
    description:
      "Data is being POSTed to an external server via wget. Strongly indicative of credential or data exfiltration.",
    pattern:
      /wget\s+(?:--post-data|--post-file)\s*=?\s*[^\n]*(?:http[s]?:\/\/(?!localhost|127\.0\.0\.1)[^\s'"]+)/gi,
    maskMatch: false,
  },
  {
    id: "exfil-fetch-post",
    category: "exfiltration",
    severity: "high",
    name: "fetch() POST to external URL",
    description:
      "JavaScript fetch() call POSTing data to an external URL. Could be sending harvested data to an attacker-controlled server.",
    pattern:
      /fetch\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1)[^'"`\s]+['"`]\s*,\s*\{[^}]*method\s*:\s*['"`]POST['"`]/gi,
    maskMatch: false,
  },
  {
    id: "exfil-axios-post",
    category: "exfiltration",
    severity: "high",
    name: "axios POST to external URL",
    description:
      "axios.post() sending data to an external server. May be exfiltrating collected secrets or environment data.",
    pattern:
      /axios\.post\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1)[^'"`\s]+['"`]/gi,
    maskMatch: false,
  },
  {
    id: "exfil-nc-exfil",
    category: "exfiltration",
    severity: "critical",
    name: "netcat data exfiltration",
    description:
      "Data piped to netcat (nc) for transmission to an external host. Classic shell-based exfiltration technique.",
    pattern: /(?:cat\s+\S+\s*\|\s*nc|nc\s+\S+\s+\d+\s*<)/gi,
    maskMatch: false,
  },

  // ─── CRYPTO / WALLET ───────────────────────────────────────────────────────
  {
    id: "crypto-bitcoin-dir",
    category: "crypto_wallet",
    severity: "critical",
    name: "Bitcoin wallet directory access",
    description:
      "Skill is accessing the .bitcoin directory which contains wallet files, private keys, and transaction history.",
    pattern: /\.bitcoin(?:\/|\\)/gi,
    maskMatch: false,
  },
  {
    id: "crypto-ethereum-dir",
    category: "crypto_wallet",
    severity: "critical",
    name: "Ethereum keystore access",
    description:
      "Skill is accessing the Ethereum keystore directory which stores encrypted private keys.",
    pattern: /\.ethereum(?:\/|\\)keystore/gi,
    maskMatch: false,
  },
  {
    id: "crypto-wallet-dat",
    category: "crypto_wallet",
    severity: "critical",
    name: "wallet.dat file access",
    description:
      "wallet.dat is the primary Bitcoin Core wallet file containing private keys. Accessing it is a strong indicator of theft.",
    pattern: /wallet\.dat/gi,
    maskMatch: false,
  },
  {
    id: "crypto-seed-phrase",
    category: "crypto_wallet",
    severity: "critical",
    name: "Seed phrase pattern",
    description:
      "Skill is searching for or manipulating mnemonic seed phrases (12/24 word recovery phrases used for crypto wallets).",
    pattern:
      /(?:seed.?phrase|mnemonic|recovery.?words?|secret.?recovery|wallet.?seed)/gi,
    maskMatch: false,
  },
  {
    id: "crypto-keychain-access",
    category: "crypto_wallet",
    severity: "high",
    name: "macOS Keychain access",
    description:
      "Skill is accessing the macOS Keychain which stores passwords, certificates, and private keys.",
    pattern:
      /security\s+find-(?:generic|internet)-password|\/Library\/Keychains\//gi,
    maskMatch: false,
  },
  {
    id: "crypto-metamask",
    category: "crypto_wallet",
    severity: "critical",
    name: "MetaMask vault access",
    description:
      "Skill is targeting the MetaMask browser extension vault, which contains encrypted private keys.",
    pattern:
      /(?:metamask|Local\s+Storage\/[a-z]+\.metamask|chrome.*metamask.*vault)/gi,
    maskMatch: false,
  },

  // ─── OBFUSCATION ───────────────────────────────────────────────────────────
  {
    id: "obfus-base64-eval",
    category: "obfuscation",
    severity: "critical",
    name: "Base64 decode + eval chain",
    description:
      "A base64-encoded payload is being decoded and immediately executed. This is the canonical technique for hiding malicious code from static analysis.",
    pattern:
      /(?:eval|exec)\s*\(\s*(?:atob|Buffer\.from|base64\.b64decode|base64_decode)\s*\(/gi,
    maskMatch: false,
  },
  {
    id: "obfus-base64-pipe-sh",
    category: "obfuscation",
    severity: "critical",
    name: "Base64 piped to shell",
    description:
      "A base64-encoded string is being decoded and piped directly to a shell interpreter, hiding the actual commands being executed.",
    pattern:
      /echo\s+['"]?[A-Za-z0-9+/=]{20,}['"]?\s*\|\s*(?:base64\s+-d|base64\s+--decode)\s*\|\s*(?:bash|sh|zsh|python|node)/gi,
    maskMatch: true,
  },
  {
    id: "obfus-hex-exec",
    category: "obfuscation",
    severity: "high",
    name: "Hex-encoded execution",
    description:
      "Hex-encoded strings are being decoded and executed, concealing the actual commands from plain-text analysis.",
    pattern:
      /(?:printf|echo)\s+['"]\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}['"]?\s*\|/gi,
    maskMatch: true,
  },
  {
    id: "obfus-fromcharcode",
    category: "obfuscation",
    severity: "high",
    name: "String.fromCharCode execution chain",
    description:
      "JavaScript String.fromCharCode() is used to construct strings from character codes, a technique to hide URLs or commands from static analysis.",
    pattern: /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){4,}\d+\s*\)/gi,
    maskMatch: true,
  },
  {
    id: "obfus-rot13",
    category: "obfuscation",
    severity: "medium",
    name: "ROT13 / Caesar cipher decode",
    description:
      "ROT13 or Caesar cipher decoding combined with execution is used to obfuscate strings like URLs or commands.",
    pattern: /(?:tr\s+['"]?[A-Za-z]+['"]?\s+['"]?[A-Za-z]+['"]?|rot13)/gi,
    maskMatch: false,
  },

  // ─── ENVIRONMENT HARVESTING ─────────────────────────────────────────────────
  {
    id: "env-printenv-send",
    category: "env_harvesting",
    severity: "critical",
    name: "printenv piped to network",
    description:
      "All environment variables are being printed and piped to a network command, exposing API keys, tokens, and secrets.",
    pattern:
      /(?:printenv|env)\s*(?:\||\s+\|)\s*(?:curl|wget|nc|ncat|socat|python|node)/gi,
    maskMatch: false,
  },
  {
    id: "env-api-key-harvest",
    category: "env_harvesting",
    severity: "critical",
    name: "API key environment harvest",
    description:
      "The skill is collecting API keys, tokens, or secrets from environment variables and likely exfiltrating them.",
    pattern:
      /\$(?:AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|NPM_TOKEN|PYPI_TOKEN|STRIPE_(?:SECRET_KEY|API_KEY)|DATABASE_URL|SECRET_KEY|PRIVATE_KEY)/gi,
    maskMatch: true,
  },
  {
    id: "env-dotenv-read-send",
    category: "env_harvesting",
    severity: "high",
    name: ".env file exfiltration",
    description:
      "A .env file is being read and the contents appear to be transmitted externally, exposing all stored secrets.",
    pattern:
      /(?:cat|type)\s+\.env(?:\s*\||\s*>|\s*&&)[^\n]*(?:curl|wget|nc|http)/gi,
    maskMatch: false,
  },
  {
    id: "env-ssh-key-access",
    category: "env_harvesting",
    severity: "critical",
    name: "SSH private key access",
    description:
      "Skill is reading SSH private keys from the .ssh directory, which could be used to gain unauthorized access to servers.",
    pattern: /~\/\.ssh\/(?:id_rsa|id_ed25519|id_ecdsa|identity)(?:\s|$|'|")/gi,
    maskMatch: false,
  },
  {
    id: "env-aws-credentials",
    category: "env_harvesting",
    severity: "critical",
    name: "AWS credentials file access",
    description:
      "Skill is accessing the AWS credentials file which contains access keys for cloud infrastructure.",
    pattern: /~\/\.aws\/credentials|\.aws\/config/gi,
    maskMatch: false,
  },

  // ─── SHELL INJECTION ────────────────────────────────────────────────────────
  {
    id: "shell-eval-var",
    category: "shell_injection",
    severity: "high",
    name: "eval() with variable input",
    description:
      "eval() is being called with variable or dynamic content, which can execute arbitrary code if the input is attacker-controlled.",
    pattern: /\beval\s*\(\s*(?!\s*['"`][^'"`]*['"`]\s*\))\$?[a-zA-Z_]/gi,
    maskMatch: false,
  },
  {
    id: "shell-child-process-exec",
    category: "shell_injection",
    severity: "high",
    name: "child_process.exec() usage",
    description:
      "Node.js child_process.exec() spawns a shell and executes commands. When combined with user input, this enables command injection.",
    pattern: /(?:child_process|require\s*\(\s*['"]child_process['"]\s*\))[\s\S]{0,50}\.exec\s*\(/gi,
    maskMatch: false,
  },
  {
    id: "shell-backtick-complex",
    category: "shell_injection",
    severity: "medium",
    name: "Backtick command substitution",
    description:
      "Backtick command substitution is being used to execute commands and embed their output. Complex or obfuscated backtick chains are suspicious.",
    pattern: /`[^`]{30,}`/gi,
    maskMatch: false,
  },
  {
    id: "shell-subprocess-shell-true",
    category: "shell_injection",
    severity: "high",
    name: "Python subprocess with shell=True",
    description:
      "subprocess.call/run/Popen with shell=True interprets the command through a shell, enabling injection if any input is dynamic.",
    pattern:
      /subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/gi,
    maskMatch: false,
  },
  {
    id: "shell-os-system",
    category: "shell_injection",
    severity: "medium",
    name: "os.system() call",
    description:
      "Python os.system() executes a command through the system shell. Dangerous when called with dynamic or user-controlled input.",
    pattern: /os\.system\s*\(\s*(?!\s*['"`][^'"`]*['"`]\s*\))/gi,
    maskMatch: false,
  },

  // ─── HIDDEN NETWORK CALLS ──────────────────────────────────────────────────
  {
    id: "net-dns-exfil",
    category: "hidden_network",
    severity: "critical",
    name: "DNS exfiltration pattern",
    description:
      "Data is being embedded in DNS hostnames and resolved, a technique to exfiltrate data through DNS queries that bypass HTTP monitoring.",
    pattern:
      /(?:nslookup|dig|host)\s+(?:\$|`)[^\s]+\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/gi,
    maskMatch: false,
  },
  {
    id: "net-raw-ip-callback",
    category: "hidden_network",
    severity: "high",
    name: "Raw IP address callback",
    description:
      "Connections to raw IP addresses (instead of domain names) are harder to block with hostname-based firewalls and suggest intentional obfuscation.",
    pattern:
      /(?:curl|wget|fetch|http\.get|axios\.get)\s*\(\s*['"`]https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,
    maskMatch: false,
  },
  {
    id: "net-encoded-url",
    category: "hidden_network",
    severity: "high",
    name: "URL-encoded or obfuscated endpoint",
    description:
      "A URL is being constructed through encoding or concatenation to evade static URL detection. Attackers use this to hide their C2 server addresses.",
    pattern:
      /(?:decodeURIComponent|unescape|atob)\s*\(\s*['"`][A-Za-z0-9%+/=]{10,}['"`]\s*\)/gi,
    maskMatch: true,
  },
  {
    id: "net-tor-onion",
    category: "hidden_network",
    severity: "critical",
    name: "Tor .onion address",
    description:
      "Connection to a Tor .onion hidden service. Legitimate skills have no need to contact Tor infrastructure.",
    pattern: /https?:\/\/[a-z2-7]{16,56}\.onion/gi,
    maskMatch: false,
  },
  {
    id: "net-interactsh-pingback",
    category: "hidden_network",
    severity: "critical",
    name: "Out-of-band callback (interactsh/burp)",
    description:
      "Connection to a known out-of-band interaction testing endpoint. These are used to confirm code execution on a victim's machine.",
    pattern: /(?:oastify\.com|interactsh\.com|burpcollaborator\.net|\.ngrok\.io)/gi,
    maskMatch: false,
  },
];
