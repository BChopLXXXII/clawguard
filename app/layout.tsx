import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ClawGuard — Skill Security Scanner",
  description:
    "Scan any ClawHub skill for malicious patterns before you install it. Detect exfiltration, crypto theft, obfuscation, and more.",
  keywords: [
    "ClawHub",
    "OpenClaw",
    "skill security",
    "malware scanner",
    "clawguard",
  ],
  applicationName: "ClawGuard",
  authors: [{ name: "BChopLXXXII", url: "https://x.com/BChopLXXXII" }],
  creator: "BChopLXXXII",
  openGraph: {
    title: "ClawGuard — Skill Security Scanner",
    description:
      "Scan any ClawHub skill for malicious patterns before you install it.",
    type: "website",
    url: "https://github.com/BChopLXXXII/clawguard",
    siteName: "ClawGuard",
  },
  twitter: {
    card: "summary_large_image",
    title: "ClawGuard — Skill Security Scanner",
    description:
      "Scan any ClawHub skill for malicious patterns before you install it.",
    creator: "@BChopLXXXII",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body>
        <div className="min-h-screen flex flex-col">{children}</div>
      </body>
    </html>
  );
}
