import Link from "next/link";
import {
  ShieldCheck,
  AlertTriangle,
  Eye,
  Wifi,
  Key,
  Code2,
  Terminal,
  Bitcoin,
  ArrowRight,
  Github,
  Zap,
  Radio,
  Download,
  Trash2,
  Clock,
  ShieldAlert,
  Monitor,
  Globe,
  Clipboard,
  Wrench,
  Server,
} from "lucide-react";

const THREAT_CATEGORIES = [
  {
    icon: Wifi,
    label: "Data Exfiltration",
    description:
      "Detects curl/wget/fetch POST requests sending data to external servers",
    color: "red",
  },
  {
    icon: Bitcoin,
    label: "Crypto & Wallet",
    description:
      "Flags access to .bitcoin, .ethereum, keychain files, and seed phrases",
    color: "yellow",
  },
  {
    icon: Eye,
    label: "Code Obfuscation",
    description:
      "Identifies base64+eval chains, hex-encoded strings, and character code tricks",
    color: "purple",
  },
  {
    icon: Key,
    label: "Env Harvesting",
    description:
      "Catches API key, token, and .env file collection sent to external endpoints",
    color: "orange",
  },
  {
    icon: Terminal,
    label: "Shell Injection",
    description:
      "Spots dangerous eval(), child_process.exec(), and shell=True patterns",
    color: "blue",
  },
  {
    icon: Code2,
    label: "Hidden Network",
    description:
      "Reveals DNS exfiltration, raw IP callbacks, and Tor .onion connections",
    color: "red",
  },
  {
    icon: Radio,
    label: "Reverse Shell",
    description:
      "Detects bash/python/netcat/perl/ruby/PHP reverse shell connections",
    color: "red",
  },
  {
    icon: Download,
    label: "Download & Execute",
    description:
      "Catches curl|bash, wget|sh, and remote code fetch+eval patterns",
    color: "red",
  },
  {
    icon: Trash2,
    label: "File Destruction",
    description:
      "Flags rm -rf, disk wipes, shred, dd overwrite, and format commands",
    color: "red",
  },
  {
    icon: Clock,
    label: "Persistence",
    description:
      "Detects crontab, systemd, LaunchAgent, shell profile, and startup backdoors",
    color: "purple",
  },
  {
    icon: ShieldAlert,
    label: "Privilege Escalation",
    description:
      "Catches sudo NOPASSWD, SUID/SGID, chmod 777, and password file access",
    color: "orange",
  },
  {
    icon: Monitor,
    label: "PowerShell Threats",
    description:
      "Encoded commands, execution bypass, hidden windows, AMSI bypass, Defender disable",
    color: "blue",
  },
  {
    icon: Globe,
    label: "Browser Theft",
    description:
      "Detects access to Chrome/Firefox/Safari cookies, passwords, and extension data",
    color: "yellow",
  },
  {
    icon: Clipboard,
    label: "Clipboard Hijack",
    description:
      "Catches clipboard monitoring and crypto address replacement attacks",
    color: "orange",
  },
  {
    icon: Wrench,
    label: "Windows LOLBins",
    description:
      "certutil, mshta, regsvr32, bitsadmin, rundll32, WMIC, and registry abuse",
    color: "blue",
  },
  {
    icon: Server,
    label: "Network Listener",
    description:
      "Detects netcat/socat/ncat listeners and Python servers opening ports",
    color: "red",
  },
];

const COLOR_MAP: Record<string, { badge: string; icon: string }> = {
  red: {
    badge: "bg-[var(--accent-red-bg)] text-[var(--accent-red)] border border-[var(--accent-red)]/20",
    icon: "text-[var(--accent-red)]",
  },
  yellow: {
    badge: "bg-[var(--accent-yellow-bg)] text-[var(--accent-yellow)] border border-[var(--accent-yellow)]/20",
    icon: "text-[var(--accent-yellow)]",
  },
  purple: {
    badge: "bg-purple-950/40 text-purple-300 border border-purple-700/20",
    icon: "text-purple-400",
  },
  orange: {
    badge: "bg-orange-950/40 text-orange-300 border border-orange-700/20",
    icon: "text-orange-400",
  },
  blue: {
    badge: "bg-[var(--accent-blue-bg)] text-[var(--accent-blue)] border border-[var(--accent-blue)]/20",
    icon: "text-[var(--accent-blue)]",
  },
};

export default function LandingPage() {
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
        className="sticky top-0 z-50 backdrop-blur-sm"
      >
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck
              size={22}
              style={{ color: "var(--accent-blue)" }}
              strokeWidth={2}
            />
            <span className="font-semibold text-base tracking-tight">
              ClawGuard
            </span>
          </div>
          <div className="flex items-center gap-6">
            <Link
              href="/scan"
              style={{ color: "var(--text-secondary)" }}
              className="text-sm hover:text-white transition-colors"
            >
              Scanner
            </Link>
            <a
              href="https://github.com/BChopLXXXII/clawguard"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: "var(--text-secondary)" }}
              className="text-sm hover:text-white transition-colors flex items-center gap-1.5"
            >
              <Github size={15} />
              GitHub
            </a>
            <Link
              href="/scan"
              style={{
                backgroundColor: "var(--accent-blue)",
                color: "white",
              }}
              className="px-4 py-2 rounded-lg text-sm font-medium hover:opacity-90 transition-opacity"
            >
              Scan a skill
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="max-w-6xl mx-auto px-6 pt-24 pb-20 text-center">
        {/* Alert banner */}
        <div
          style={{
            backgroundColor: "var(--accent-red-bg)",
            border: "1px solid rgba(255,68,68,0.3)",
            color: "var(--accent-red)",
          }}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium mb-8"
        >
          <AlertTriangle size={14} strokeWidth={2.5} />
          Malicious skills are actively targeting ClawHub users
        </div>

        <h1
          style={{ color: "var(--text-primary)" }}
          className="text-5xl font-bold tracking-tight leading-tight mb-6 max-w-4xl mx-auto"
        >
          Scan any ClawHub skill for threats
          <span style={{ color: "var(--accent-blue)" }}> before you install it</span>
        </h1>

        <p
          style={{ color: "var(--text-secondary)" }}
          className="text-xl max-w-2xl mx-auto mb-10 leading-relaxed"
        >
          ClawGuard statically analyzes skills across 16 threat categories
          including reverse shells, persistence, privilege escalation, and more
          — in seconds, with no account required.
        </p>

        <div className="flex items-center justify-center gap-4">
          <Link
            href="/scan"
            style={{ backgroundColor: "var(--accent-blue)", color: "white" }}
            className="inline-flex items-center gap-2 px-6 py-3 rounded-lg font-medium text-base hover:opacity-90 transition-opacity"
          >
            <Zap size={18} strokeWidth={2} />
            Scan a skill now
            <ArrowRight size={16} strokeWidth={2} />
          </Link>
          <a
            href="#how-it-works"
            style={{ color: "var(--text-secondary)", borderColor: "var(--border)" }}
            className="inline-flex items-center gap-2 px-6 py-3 rounded-lg border font-medium text-base hover:text-white transition-colors"
          >
            How it works
          </a>
        </div>
      </section>

      {/* Rating preview */}
      <section className="max-w-6xl mx-auto px-6 pb-20">
        <div
          style={{
            backgroundColor: "var(--bg-card)",
            border: "1px solid var(--border)",
          }}
          className="rounded-2xl p-8 flex flex-col md:flex-row items-center justify-center gap-8"
        >
          <div className="flex flex-col items-center gap-2">
            <div
              style={{
                backgroundColor: "var(--accent-red-bg)",
                border: "2px solid var(--accent-red)",
                color: "var(--accent-red)",
              }}
              className="px-8 py-3 rounded-xl text-2xl font-bold tracking-widest"
            >
              BLOCK
            </div>
            <span style={{ color: "var(--text-muted)" }} className="text-sm">
              Critical threats found
            </span>
          </div>
          <div
            style={{ backgroundColor: "var(--border)" }}
            className="hidden md:block w-px h-16"
          />
          <div className="flex flex-col items-center gap-2">
            <div
              style={{
                backgroundColor: "var(--accent-yellow-bg)",
                border: "2px solid var(--accent-yellow)",
                color: "var(--accent-yellow)",
              }}
              className="px-8 py-3 rounded-xl text-2xl font-bold tracking-widest"
            >
              WARN
            </div>
            <span style={{ color: "var(--text-muted)" }} className="text-sm">
              High-severity issues
            </span>
          </div>
          <div
            style={{ backgroundColor: "var(--border)" }}
            className="hidden md:block w-px h-16"
          />
          <div className="flex flex-col items-center gap-2">
            <div
              style={{
                backgroundColor: "var(--accent-green-bg)",
                border: "2px solid var(--accent-green)",
                color: "var(--accent-green)",
              }}
              className="px-8 py-3 rounded-xl text-2xl font-bold tracking-widest"
            >
              PASS
            </div>
            <span style={{ color: "var(--text-muted)" }} className="text-sm">
              No threats detected
            </span>
          </div>
        </div>
      </section>

      {/* Threat categories */}
      <section id="how-it-works" className="max-w-6xl mx-auto px-6 pb-24">
        <div className="text-center mb-12">
          <h2
            style={{ color: "var(--text-primary)" }}
            className="text-3xl font-bold tracking-tight mb-3"
          >
            16 threat categories checked
          </h2>
          <p style={{ color: "var(--text-secondary)" }} className="text-lg">
            Every scan runs all patterns — no sign-up, no rate limits.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {THREAT_CATEGORIES.map((cat) => {
            const colors = COLOR_MAP[cat.color] || COLOR_MAP.blue;
            const Icon = cat.icon;
            return (
              <div
                key={cat.label}
                style={{
                  backgroundColor: "var(--bg-card)",
                  border: "1px solid var(--border)",
                }}
                className="rounded-xl p-6 hover:border-[var(--border-subtle)] transition-colors"
              >
                <div className="flex items-start gap-4">
                  <div
                    className={`p-2.5 rounded-lg ${colors.badge} flex-shrink-0`}
                  >
                    <Icon size={18} strokeWidth={2} />
                  </div>
                  <div>
                    <h3
                      style={{ color: "var(--text-primary)" }}
                      className="font-semibold mb-1.5"
                    >
                      {cat.label}
                    </h3>
                    <p
                      style={{ color: "var(--text-secondary)" }}
                      className="text-sm leading-relaxed"
                    >
                      {cat.description}
                    </p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Why this exists */}
      <section
        style={{
          backgroundColor: "var(--bg-secondary)",
          borderTop: "1px solid var(--border)",
          borderBottom: "1px solid var(--border)",
        }}
        className="py-20 px-6"
      >
        <div className="max-w-3xl mx-auto">
          <div className="flex items-center gap-3 mb-6">
            <AlertTriangle
              size={22}
              style={{ color: "var(--accent-yellow)" }}
              strokeWidth={2}
            />
            <h2
              style={{ color: "var(--text-primary)" }}
              className="text-2xl font-bold"
            >
              Why ClawGuard exists
            </h2>
          </div>
          <div
            style={{ color: "var(--text-secondary)" }}
            className="space-y-4 text-base leading-relaxed"
          >
            <p>
              ClawHub, the skill marketplace for OpenClaw, has no built-in
              vetting process. A backdoored skill was recently botted to the{" "}
              <strong style={{ color: "var(--text-primary)" }}>
                #1 most downloaded position
              </strong>{" "}
              and was actively stealing cryptocurrency from users before it was
              detected.
            </p>
            <p>
              There is currently{" "}
              <strong style={{ color: "var(--text-primary)" }}>
                no tool to vet skills before installing them
              </strong>
              . ClawGuard fills that gap with static pattern analysis — you
              paste or upload the skill files and get an instant security report.
            </p>
            <p>
              All scanning happens server-side. Pattern definitions are never
              exposed to the client, making them harder to bypass.
            </p>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="max-w-6xl mx-auto px-6 py-24 text-center">
        <h2
          style={{ color: "var(--text-primary)" }}
          className="text-3xl font-bold tracking-tight mb-4"
        >
          Don&apos;t install blind
        </h2>
        <p
          style={{ color: "var(--text-secondary)" }}
          className="text-lg mb-8 max-w-xl mx-auto"
        >
          Paste your skill content or upload the files. Get a full security
          report in under a second.
        </p>
        <Link
          href="/scan"
          style={{ backgroundColor: "var(--accent-blue)", color: "white" }}
          className="inline-flex items-center gap-2 px-8 py-4 rounded-xl font-semibold text-lg hover:opacity-90 transition-opacity"
        >
          <ShieldCheck size={20} strokeWidth={2} />
          Start scanning
        </Link>
      </section>

      {/* Footer */}
      <footer
        style={{
          borderTop: "1px solid var(--border)",
          color: "var(--text-muted)",
        }}
        className="py-8 px-6"
      >
        <div className="max-w-6xl mx-auto flex flex-col items-center gap-4 text-sm">
          <div className="flex items-center gap-2">
            <ShieldCheck size={16} style={{ color: "var(--accent-blue)" }} />
            <span>ClawGuard</span>
            <span style={{ color: "var(--border)" }}>—</span>
            <span>Free, open-source skill security scanner</span>
          </div>
          <span>
            Built by{" "}
            <a
              href="https://x.com/BChopLXXXII"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-white transition-colors"
              style={{ color: "var(--accent-blue)" }}
            >
              @BChopLXXXII
            </a>
          </span>
          <div className="flex items-center gap-6">
            <Link href="/scan" className="hover:text-white transition-colors">
              Scanner
            </Link>
            <Link href="/api/scan" className="hover:text-white transition-colors">
              API
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
