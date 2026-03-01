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
    pattern: /`(?:cat|curl|wget|whoami|id|uname|hostname|ls|pwd|env|printenv|ifconfig|ip\s+addr|nc|ncat|base64|python|node|bash|sh|dd|chmod|chown)\b[^`]*`/gi,
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

  // ─── REVERSE SHELL ───────────────────────────────────────────────────────
  {
    id: "revshell-bash-tcp",
    category: "reverse_shell",
    severity: "critical",
    name: "Bash TCP reverse shell",
    description:
      "Bash is opening a TCP connection and redirecting stdin/stdout to a remote host, giving the attacker an interactive shell.",
    pattern: /bash\s+-i\s+>&?\s*\/dev\/tcp\/\S+\/\d+/gi,
    maskMatch: false,
  },
  {
    id: "revshell-python",
    category: "reverse_shell",
    severity: "critical",
    name: "Python reverse shell",
    description:
      "Python socket connecting back to an attacker with shell spawning. Classic reverse shell technique.",
    pattern: /socket\.(?:socket|create_connection)\s*\([^)]*\)[\s\S]{0,200}(?:subprocess|os\.dup2|pty\.spawn)/gi,
    maskMatch: false,
  },
  {
    id: "revshell-nc-shell",
    category: "reverse_shell",
    severity: "critical",
    name: "Netcat reverse shell",
    description:
      "Netcat piping a shell to a remote host, giving the attacker command execution on the victim's machine.",
    pattern: /nc\s+(?:-[a-zA-Z]\s+)*\S+\s+\d+\s+-e\s+(?:\/bin\/(?:bash|sh|zsh)|cmd\.exe)/gi,
    maskMatch: false,
  },
  {
    id: "revshell-mkfifo",
    category: "reverse_shell",
    severity: "critical",
    name: "Named pipe reverse shell (mkfifo)",
    description:
      "Using mkfifo to create a named pipe for a reverse shell connection. Bypasses simple netcat -e detection.",
    pattern: /mkfifo\s+\S+\s*;[^;]*nc\s+\S+\s+\d+/gi,
    maskMatch: false,
  },
  {
    id: "revshell-perl",
    category: "reverse_shell",
    severity: "critical",
    name: "Perl reverse shell",
    description:
      "Perl socket-based reverse shell connecting back to an attacker-controlled server.",
    pattern: /perl\s+-e\s+['"].*?(?:Socket|IO::Socket)[\s\S]*?(?:exec|system|open.*?\|)/gi,
    maskMatch: false,
  },
  {
    id: "revshell-ruby",
    category: "reverse_shell",
    severity: "critical",
    name: "Ruby reverse shell",
    description:
      "Ruby TCPSocket-based reverse shell spawning a shell to a remote attacker.",
    pattern: /ruby\s+-e\s+['"].*?TCPSocket[\s\S]*?(?:exec|spawn|system)/gi,
    maskMatch: false,
  },
  {
    id: "revshell-php",
    category: "reverse_shell",
    severity: "critical",
    name: "PHP reverse shell",
    description:
      "PHP fsockopen-based reverse shell piping commands to a remote host.",
    pattern: /fsockopen\s*\(\s*['"][^'"]+['"]\s*,\s*\d+[\s\S]{0,200}(?:exec|shell_exec|system|passthru|proc_open)/gi,
    maskMatch: false,
  },
  {
    id: "revshell-devtcp",
    category: "reverse_shell",
    severity: "critical",
    name: "/dev/tcp or /dev/udp connection",
    description:
      "Direct connection using bash's /dev/tcp or /dev/udp pseudo-device. Almost always a reverse shell or exfiltration.",
    pattern: /\/dev\/(?:tcp|udp)\/\S+\/\d+/gi,
    maskMatch: false,
  },

  // ─── DOWNLOAD & EXECUTE ──────────────────────────────────────────────────
  {
    id: "dlexec-curl-pipe-sh",
    category: "download_execute",
    severity: "critical",
    name: "curl piped to shell",
    description:
      "Downloading a script and piping it directly to a shell interpreter. The user cannot review the code before it executes.",
    pattern: /curl\s+(?:-[a-zA-Z]+\s+)*(?:-s\s+)?(?:https?:\/\/\S+)\s*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python[23]?|node|perl|ruby)/gi,
    maskMatch: false,
  },
  {
    id: "dlexec-wget-pipe-sh",
    category: "download_execute",
    severity: "critical",
    name: "wget piped to shell",
    description:
      "Downloading a script via wget and piping it directly to a shell. Classic remote code execution pattern.",
    pattern: /wget\s+(?:-[a-zA-Z]+\s+)*(?:-q\s+)?(?:-O\s*-?\s+)?(?:https?:\/\/\S+)\s*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python[23]?|node|perl|ruby)/gi,
    maskMatch: false,
  },
  {
    id: "dlexec-curl-exec",
    category: "download_execute",
    severity: "critical",
    name: "curl output executed via eval/source",
    description:
      "Downloading code and executing it via eval or source. Hides the payload from the user entirely.",
    pattern: /(?:eval|source|\.)\s+(?:"\$\(|<\()?\s*curl\s+(?:-[a-zA-Z]+\s+)*https?:\/\/\S+/gi,
    maskMatch: false,
  },
  {
    id: "dlexec-wget-exec",
    category: "download_execute",
    severity: "critical",
    name: "wget download then execute",
    description:
      "Downloading a file with wget and immediately executing it. Two-stage remote code execution.",
    pattern: /wget\s+(?:-[a-zA-Z]+\s+)*https?:\/\/\S+\s*(?:&&|;)\s*(?:chmod\s+\+x\s+\S+\s*(?:&&|;)\s*)?(?:bash|sh|\.\/)/gi,
    maskMatch: false,
  },
  {
    id: "dlexec-python-urlopen",
    category: "download_execute",
    severity: "critical",
    name: "Python URL fetch + exec",
    description:
      "Python downloading code from a URL and executing it. Remote code execution via urllib/requests.",
    pattern: /(?:urllib\.request\.urlopen|requests\.get)\s*\([^)]+\)[\s\S]{0,100}(?:exec|eval|compile)\s*\(/gi,
    maskMatch: false,
  },
  {
    id: "dlexec-node-eval-http",
    category: "download_execute",
    severity: "critical",
    name: "Node.js HTTP fetch + eval",
    description:
      "Fetching code over HTTP and evaluating it in Node.js. Remote code execution via dynamic eval.",
    pattern: /(?:https?\.get|fetch|axios\.get)\s*\([^)]*\)[\s\S]{0,200}(?:eval|Function|vm\.runIn)/gi,
    maskMatch: false,
  },

  // ─── FILE DESTRUCTION ────────────────────────────────────────────────────
  {
    id: "destroy-rm-rf-root",
    category: "file_destruction",
    severity: "critical",
    name: "Recursive force delete from root or home",
    description:
      "rm -rf targeting root (/) or home directory. Will destroy the entire filesystem or user data.",
    pattern: /rm\s+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(?:\/\s|\/\*|~\/|\/home|\/etc|\/var|\$HOME)/gi,
    maskMatch: false,
  },
  {
    id: "destroy-shred",
    category: "file_destruction",
    severity: "critical",
    name: "Secure file shredding",
    description:
      "Using shred to permanently destroy file contents beyond recovery. Legitimate skills don't need to securely wipe files.",
    pattern: /shred\s+(?:-[a-zA-Z]+\s+)*\S+/gi,
    maskMatch: false,
  },
  {
    id: "destroy-dd-zero",
    category: "file_destruction",
    severity: "critical",
    name: "Disk overwrite with dd",
    description:
      "Using dd to write zeros or random data to a disk or partition. Will destroy all data on the target device.",
    pattern: /dd\s+if=\/dev\/(?:zero|urandom|random)\s+of=(?:\/dev\/[a-z]+|\/)/gi,
    maskMatch: false,
  },
  {
    id: "destroy-mkfs",
    category: "file_destruction",
    severity: "critical",
    name: "Filesystem format command",
    description:
      "Formatting a disk or partition. Will destroy all data on the target device.",
    pattern: /mkfs(?:\.[a-z0-9]+)?\s+(?:-[a-zA-Z]+\s+)*\/dev\/[a-z]+/gi,
    maskMatch: false,
  },
  {
    id: "destroy-wipe-cmd",
    category: "file_destruction",
    severity: "critical",
    name: "Disk wipe utility",
    description:
      "Using a disk wipe utility (wipefs, blkdiscard) to destroy partition data or trim entire blocks.",
    pattern: /(?:wipefs|blkdiscard)\s+(?:-[a-zA-Z]+\s+)*\/dev\/[a-z]+/gi,
    maskMatch: false,
  },
  {
    id: "destroy-truncate-critical",
    category: "file_destruction",
    severity: "high",
    name: "Truncating critical files",
    description:
      "Truncating system or user files to zero bytes, destroying their contents.",
    pattern: /(?:truncate\s+-s\s*0|>\s*(?:\/etc\/|~\/\.|\/home\/))\S+/gi,
    maskMatch: false,
  },

  // ─── PERSISTENCE & BACKDOORS ─────────────────────────────────────────────
  {
    id: "persist-crontab-add",
    category: "persistence",
    severity: "critical",
    name: "Crontab modification",
    description:
      "Adding or modifying cron jobs to execute code on a schedule. Used to maintain persistence after initial compromise.",
    pattern: /(?:crontab\s+-[lr]|echo\s+['"][^'"]*['"].*?\|\s*crontab|\/etc\/cron\.[a-z]+\/)/gi,
    maskMatch: false,
  },
  {
    id: "persist-systemd-service",
    category: "persistence",
    severity: "critical",
    name: "Systemd service creation",
    description:
      "Creating or modifying systemd service files to run code at boot. Classic Linux persistence technique.",
    pattern: /(?:\/etc\/systemd\/system\/\S+\.service|systemctl\s+(?:enable|daemon-reload)|\.service\b[\s\S]{0,100}ExecStart)/gi,
    maskMatch: false,
  },
  {
    id: "persist-launchagent",
    category: "persistence",
    severity: "critical",
    name: "macOS LaunchAgent/Daemon",
    description:
      "Creating LaunchAgent or LaunchDaemon plist files for macOS persistence across reboots.",
    pattern: /(?:\/Library\/Launch(?:Agents|Daemons)\/|~\/Library\/LaunchAgents\/)\S+\.plist/gi,
    maskMatch: false,
  },
  {
    id: "persist-bashrc-inject",
    category: "persistence",
    severity: "critical",
    name: "Shell profile injection",
    description:
      "Appending commands to shell profile files (.bashrc, .zshrc, .profile) to execute on every new shell session.",
    pattern: /(?:>>|tee\s+-a)\s*(?:~\/)?\.(?:bashrc|zshrc|profile|bash_profile|zprofile|bash_login)/gi,
    maskMatch: false,
  },
  {
    id: "persist-authorized-keys",
    category: "persistence",
    severity: "critical",
    name: "SSH authorized_keys modification",
    description:
      "Adding SSH public keys to authorized_keys for persistent remote access without a password.",
    pattern: /(?:>>|tee\s+-a)\s*(?:~\/)?\.ssh\/authorized_keys/gi,
    maskMatch: false,
  },
  {
    id: "persist-windows-startup",
    category: "persistence",
    severity: "critical",
    name: "Windows startup folder or registry",
    description:
      "Adding entries to Windows startup folder or Run registry keys for boot persistence.",
    pattern: /(?:Start\s*Menu\\Programs\\Startup|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)/gi,
    maskMatch: false,
  },
  {
    id: "persist-at-job",
    category: "persistence",
    severity: "high",
    name: "Scheduled task via at/schtasks",
    description:
      "Using at (Unix) or schtasks (Windows) to schedule future command execution.",
    pattern: /(?:\bat\s+(?:now|\d{1,2}:\d{2})|schtasks\s+\/create\s+)/gi,
    maskMatch: false,
  },

  // ─── PRIVILEGE ESCALATION ────────────────────────────────────────────────
  {
    id: "privesc-sudo-nopasswd",
    category: "privilege_escalation",
    severity: "critical",
    name: "Sudo NOPASSWD configuration",
    description:
      "Modifying sudoers to allow passwordless sudo. Grants permanent root access without authentication.",
    pattern: /(?:\/etc\/sudoers|NOPASSWD\s*:\s*ALL|visudo)/gi,
    maskMatch: false,
  },
  {
    id: "privesc-chmod-suid",
    category: "privilege_escalation",
    severity: "critical",
    name: "SUID/SGID bit manipulation",
    description:
      "Setting SUID or SGID bits on files to escalate privileges. Allows execution as the file owner (often root).",
    pattern: /chmod\s+(?:[0-7]*[4-7][0-7]{2}|[ug]\+s)\s+\S+/gi,
    maskMatch: false,
  },
  {
    id: "privesc-chmod-777",
    category: "privilege_escalation",
    severity: "high",
    name: "World-writable permissions (777)",
    description:
      "Setting files or directories to world-writable (777). Any user on the system can modify these files.",
    pattern: /chmod\s+(?:-R\s+)?777\s+\S+/gi,
    maskMatch: false,
  },
  {
    id: "privesc-chown-root",
    category: "privilege_escalation",
    severity: "high",
    name: "Ownership change to root",
    description:
      "Changing file ownership to root. Combined with SUID, this enables privilege escalation.",
    pattern: /chown\s+(?:-R\s+)?root(?::root)?\s+\S+/gi,
    maskMatch: false,
  },
  {
    id: "privesc-sudo-pipe",
    category: "privilege_escalation",
    severity: "critical",
    name: "Piping to sudo or su",
    description:
      "Piping commands to sudo or su for elevated execution. Often used to run downloaded scripts as root.",
    pattern: /\|\s*sudo\s+(?:bash|sh|zsh|python|tee)|echo\s+['"][^'"]*['"]\s*\|\s*su(?:do)?\s/gi,
    maskMatch: false,
  },
  {
    id: "privesc-passwd-shadow",
    category: "privilege_escalation",
    severity: "critical",
    name: "Password file access",
    description:
      "Reading or modifying /etc/passwd or /etc/shadow to add users, change passwords, or harvest credentials.",
    pattern: /(?:cat|head|tail|less|more|vim?|nano|sed|awk)\s+\/etc\/(?:passwd|shadow)|\/etc\/shadow/gi,
    maskMatch: false,
  },

  // ─── POWERSHELL THREATS ──────────────────────────────────────────────────
  {
    id: "ps-encoded-command",
    category: "powershell",
    severity: "critical",
    name: "PowerShell encoded command",
    description:
      "Running PowerShell with a base64-encoded command to hide the actual payload from inspection.",
    pattern: /powershell(?:\.exe)?\s+(?:-[a-zA-Z]+\s+)*-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{10,}/gi,
    maskMatch: true,
  },
  {
    id: "ps-execution-bypass",
    category: "powershell",
    severity: "critical",
    name: "PowerShell execution policy bypass",
    description:
      "Bypassing PowerShell's execution policy to run unsigned scripts. Standard technique in malware deployment.",
    pattern: /powershell(?:\.exe)?\s+(?:-[a-zA-Z]+\s+)*-(?:ep|executionpolicy)\s+(?:bypass|unrestricted)/gi,
    maskMatch: false,
  },
  {
    id: "ps-hidden-window",
    category: "powershell",
    severity: "critical",
    name: "Hidden PowerShell window",
    description:
      "Running PowerShell with a hidden window so the user can't see what's executing.",
    pattern: /powershell(?:\.exe)?\s+(?:-[a-zA-Z]+\s+)*-(?:w|windowstyle)\s+(?:hidden|minimized)/gi,
    maskMatch: false,
  },
  {
    id: "ps-download-string",
    category: "powershell",
    severity: "critical",
    name: "PowerShell download and execute",
    description:
      "Using PowerShell's WebClient or Invoke-WebRequest to download and execute remote code.",
    pattern: /(?:Net\.WebClient\)\.DownloadString|Invoke-(?:WebRequest|RestMethod|Expression)|IEX\s*\(\s*\(?\s*New-Object)\s*\(?/gi,
    maskMatch: false,
  },
  {
    id: "ps-disable-defender",
    category: "powershell",
    severity: "critical",
    name: "Disabling Windows Defender",
    description:
      "Attempting to disable Windows Defender real-time protection. Malware does this to avoid detection.",
    pattern: /Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true|DisableAntiSpyware/gi,
    maskMatch: false,
  },
  {
    id: "ps-amsi-bypass",
    category: "powershell",
    severity: "critical",
    name: "AMSI bypass attempt",
    description:
      "Attempting to bypass Windows Antimalware Scan Interface (AMSI) to evade malware detection.",
    pattern: /(?:amsiInitFailed|AmsiScanBuffer|amsi\.dll|System\.Management\.Automation\.AmsiUtils)/gi,
    maskMatch: false,
  },
  {
    id: "ps-credential-harvest",
    category: "powershell",
    severity: "critical",
    name: "PowerShell credential harvesting",
    description:
      "Using PowerShell to extract credentials from Windows Credential Manager, SAM, or LSASS.",
    pattern: /(?:Get-Credential|ConvertFrom-SecureString|mimikatz|Invoke-Mimikatz|sekurlsa|SAM\s+database)/gi,
    maskMatch: false,
  },

  // ─── BROWSER DATA THEFT ──────────────────────────────────────────────────
  {
    id: "browser-chrome-cookies",
    category: "browser_theft",
    severity: "critical",
    name: "Chrome cookies database access",
    description:
      "Accessing Chrome's Cookies SQLite database to steal session cookies for logged-in accounts.",
    pattern: /(?:Chrome|Chromium|BraveSoftware)[\\/](?:User\s*Data|Default)[\\/](?:Cookies|Login\s*Data|Web\s*Data|History)/gi,
    maskMatch: false,
  },
  {
    id: "browser-firefox-profiles",
    category: "browser_theft",
    severity: "critical",
    name: "Firefox profile data access",
    description:
      "Accessing Firefox profile directory to steal cookies, saved passwords, or browsing history.",
    pattern: /(?:\.mozilla\/firefox|Firefox[\\/]Profiles)[\\/][\s\S]{0,50}(?:cookies\.sqlite|logins\.json|key[34]\.db|places\.sqlite)/gi,
    maskMatch: false,
  },
  {
    id: "browser-safari-data",
    category: "browser_theft",
    severity: "critical",
    name: "Safari browser data access",
    description:
      "Accessing Safari's data stores to steal cookies, passwords, or browsing history.",
    pattern: /(?:\/Safari\/(?:Cookies|LocalStorage|Databases)|Cookies\.binarycookies)/gi,
    maskMatch: false,
  },
  {
    id: "browser-extension-data",
    category: "browser_theft",
    severity: "high",
    name: "Browser extension data access",
    description:
      "Accessing browser extension storage or local data. Could be stealing extension-specific credentials or data.",
    pattern: /(?:chrome-extension:\/\/|moz-extension:\/\/|Extensions[\\/])[a-zA-Z0-9]{10,}[\\/](?:Local\s*Storage|IndexedDB|leveldb)/gi,
    maskMatch: false,
  },
  {
    id: "browser-password-decrypt",
    category: "browser_theft",
    severity: "critical",
    name: "Browser password decryption",
    description:
      "Attempting to decrypt saved browser passwords using OS-level crypto APIs.",
    pattern: /(?:CryptUnprotectData|SecKeychainFindGenericPassword|gnome-keyring|kwallet)[\s\S]{0,100}(?:password|login|credential)/gi,
    maskMatch: false,
  },

  // ─── CLIPBOARD HIJACK ────────────────────────────────────────────────────
  {
    id: "clip-read-clipboard",
    category: "clipboard_hijack",
    severity: "high",
    name: "Clipboard content reading",
    description:
      "Reading clipboard contents, potentially to capture copied passwords, crypto addresses, or sensitive text.",
    pattern: /(?:pbpaste|xclip\s+-o|xsel\s+--clipboard\s+--output|Get-Clipboard|win32clipboard|pyperclip\.paste|clipboard\.readText)/gi,
    maskMatch: false,
  },
  {
    id: "clip-write-clipboard",
    category: "clipboard_hijack",
    severity: "high",
    name: "Clipboard content replacement",
    description:
      "Writing to the clipboard, potentially replacing a copied crypto address with an attacker's address.",
    pattern: /(?:pbcopy|xclip\s+-selection|xsel\s+--clipboard\s+--input|Set-Clipboard|pyperclip\.copy|clipboard\.writeText)/gi,
    maskMatch: false,
  },
  {
    id: "clip-crypto-swap",
    category: "clipboard_hijack",
    severity: "critical",
    name: "Crypto address clipboard monitor",
    description:
      "Monitoring clipboard for cryptocurrency addresses and replacing them with an attacker's address. Classic crypto theft technique.",
    pattern: /(?:clipboard|pbpaste|xclip)[\s\S]{0,200}(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})/gi,
    maskMatch: true,
  },

  // ─── WINDOWS LOLBINS ─────────────────────────────────────────────────────
  {
    id: "lolbin-certutil-decode",
    category: "windows_lolbins",
    severity: "critical",
    name: "certutil download/decode",
    description:
      "Using certutil to download files or decode base64 payloads. A classic Windows 'living off the land' technique for malware delivery.",
    pattern: /certutil(?:\.exe)?\s+(?:-[a-zA-Z]+\s+)*(?:-urlcache\s+-(?:split\s+)?f|-decode|-decodehex)\s+/gi,
    maskMatch: false,
  },
  {
    id: "lolbin-mshta",
    category: "windows_lolbins",
    severity: "critical",
    name: "mshta.exe execution",
    description:
      "mshta.exe executes HTA files or inline VBScript/JScript. Commonly abused to download and run malicious payloads.",
    pattern: /mshta(?:\.exe)?\s+(?:vbscript:|javascript:|https?:\/\/)/gi,
    maskMatch: false,
  },
  {
    id: "lolbin-regsvr32",
    category: "windows_lolbins",
    severity: "critical",
    name: "regsvr32.exe remote script",
    description:
      "regsvr32 loading a remote script or scrobj.dll to execute arbitrary code. Bypasses application whitelisting.",
    pattern: /regsvr32(?:\.exe)?\s+(?:\/s\s+)?(?:\/n\s+)?(?:\/u\s+)?(?:\/i:https?:\/\/\S+\s+)?(?:scrobj\.dll|https?:\/\/)/gi,
    maskMatch: false,
  },
  {
    id: "lolbin-bitsadmin",
    category: "windows_lolbins",
    severity: "critical",
    name: "bitsadmin file download",
    description:
      "Using bitsadmin to download files in the background. Commonly used by malware to fetch second-stage payloads.",
    pattern: /bitsadmin(?:\.exe)?\s+(?:\/transfer|\/create|\/addfile|\/resume)\s+/gi,
    maskMatch: false,
  },
  {
    id: "lolbin-rundll32",
    category: "windows_lolbins",
    severity: "high",
    name: "rundll32.exe suspicious execution",
    description:
      "rundll32 executing a DLL function or JavaScript. Can be abused to run arbitrary code while appearing legitimate.",
    pattern: /rundll32(?:\.exe)?\s+(?:javascript:|shell32\.dll,ShellExec_RunDLL|url\.dll,FileProtocolHandler)/gi,
    maskMatch: false,
  },
  {
    id: "lolbin-wmic-process",
    category: "windows_lolbins",
    severity: "critical",
    name: "WMIC process creation",
    description:
      "Using WMIC to create processes or execute commands remotely. Common in lateral movement and privilege escalation.",
    pattern: /wmic(?:\.exe)?\s+(?:\/node:\S+\s+)?process\s+call\s+create/gi,
    maskMatch: false,
  },
  {
    id: "lolbin-cmd-hidden",
    category: "windows_lolbins",
    severity: "high",
    name: "cmd.exe hidden or encoded execution",
    description:
      "Running cmd.exe with /c to execute commands, especially combined with other LOLBins or obfuscation.",
    pattern: /cmd(?:\.exe)?\s+\/c\s+(?:echo\s+[^\n]*\|\s*(?:powershell|cmd)|start\s+\/min|certutil|bitsadmin|mshta|regsvr32|rundll32|wmic)/gi,
    maskMatch: false,
  },
  {
    id: "lolbin-reg-add",
    category: "windows_lolbins",
    severity: "high",
    name: "Registry modification via reg.exe",
    description:
      "Modifying Windows registry keys, potentially for persistence, disabling security features, or privilege escalation.",
    pattern: /reg(?:\.exe)?\s+add\s+(?:"?HK(?:CU|LM|CR|U|CC)\\[^"]*(?:Run|RunOnce|Image\s*File|Debugger|DisableAntiSpyware|DisableRealtimeMonitoring))/gi,
    maskMatch: false,
  },
  {
    id: "lolbin-cscript-wscript",
    category: "windows_lolbins",
    severity: "high",
    name: "cscript/wscript execution",
    description:
      "Running VBScript or JScript via Windows Script Host. Often used to execute downloaded malicious scripts.",
    pattern: /(?:cscript|wscript)(?:\.exe)?\s+(?:\/\/[a-zA-Z]+\s+)*(?:https?:\/\/\S+|\S+\.(?:vbs|js|wsf|wsh))/gi,
    maskMatch: false,
  },

  // ─── NETWORK LISTENER ────────────────────────────────────────────────────
  {
    id: "netlistener-nc-listen",
    category: "network_listener",
    severity: "critical",
    name: "Netcat listener",
    description:
      "Opening a netcat listener on a port to accept inbound connections. Used for reverse shells, file transfers, or C2.",
    pattern: /nc(?:at)?\s+(?:-[a-zA-Z]+\s+)*-l(?:p)?\s+(?:-[a-zA-Z]+\s+)*\d+/gi,
    maskMatch: false,
  },
  {
    id: "netlistener-socat",
    category: "network_listener",
    severity: "critical",
    name: "socat listener/relay",
    description:
      "Using socat to create a network listener or relay. More powerful than netcat and can create encrypted tunnels.",
    pattern: /socat\s+(?:TCP-LISTEN|UDP-LISTEN|OPENSSL-LISTEN):\d+/gi,
    maskMatch: false,
  },
  {
    id: "netlistener-python-server",
    category: "network_listener",
    severity: "high",
    name: "Python network server",
    description:
      "Starting a Python HTTP or socket server. Could be used to serve malicious files or accept exfiltrated data.",
    pattern: /python[23]?\s+-m\s+(?:http\.server|SimpleHTTPServer|socketserver)\s+\d+/gi,
    maskMatch: false,
  },
  {
    id: "netlistener-ncat-listen",
    category: "network_listener",
    severity: "critical",
    name: "ncat/nmap listener with shell",
    description:
      "Using ncat (nmap's netcat) to create a listener with shell execution capabilities.",
    pattern: /ncat\s+(?:-[a-zA-Z]+\s+)*(?:--listen|--exec|--sh-exec|-l|-e)\s+/gi,
    maskMatch: false,
  },

  // ─── ADDITIONAL QUICK WINS ───────────────────────────────────────────────
  {
    id: "dlexec-chmod-downloaded",
    category: "download_execute",
    severity: "critical",
    name: "chmod +x on downloaded file",
    description:
      "Making a downloaded file executable. Two-step pattern: download then execute.",
    pattern: /(?:curl|wget)\s+[^\n]*(?:&&|;)\s*chmod\s+\+x\s+\S+/gi,
    maskMatch: false,
  },
  {
    id: "privesc-chmod-sensitive",
    category: "privilege_escalation",
    severity: "high",
    name: "Dangerous permission change (666/o+w)",
    description:
      "Setting sensitive files to world-writable (666) or adding other-write permissions, making them modifiable by any user.",
    pattern: /chmod\s+(?:-R\s+)?(?:666|o\+w)\s+\S+/gi,
    maskMatch: false,
  },
  {
    id: "shell-docker-escape",
    category: "privilege_escalation",
    severity: "critical",
    name: "Docker privilege escalation",
    description:
      "Running Docker with host filesystem mount or privileged mode. Can escape container isolation and compromise the host.",
    pattern: /docker\s+run\s+(?:-[a-zA-Z]+\s+)*(?:--privileged|-v\s+\/:\S)/gi,
    maskMatch: false,
  },
];
