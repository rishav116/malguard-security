import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import "./globals.css";
import { AuthProvider } from "@/context/AuthContext";
import FloatingMalixOrb from "@/components/FloatingMalixOrb";
import SmoothScroll from "@/components/SmoothScroll";

const geistSans = localFont({
  src: "../../public/fonts/geist-sans.woff2",
  variable: "--font-geist-sans",
  display: "swap",
  fallback: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
});

const geistMono = localFont({
  src: "../../public/fonts/geist-mono.woff2",
  variable: "--font-geist-mono",
  display: "swap",
  fallback: ["JetBrains Mono", "Cascadia Code", "Fira Code", "Consolas", "monospace"],
});

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
  themeColor: "#060D19",
};

export const metadata: Metadata = {
  title: "MALGUARD AI — AI Powered Malware Detection System",
  description:
    "Detect Threats. Understand Risks. Stay Protected. AI-driven malware detection combining Random Forest ML classification, ClamAV scanning, and Malix AI security assistance.",
  keywords: [
    "Malware Detection",
    "Cybersecurity AI",
    "Threat Intelligence",
    "Malix AI Security",
    "Static Binary Analysis",
    "Suspicious Pattern Detection",
    "Random Forest",
    "ClamAV",
  ],
  authors: [{ name: "MALGUARD AI Security Lab" }],
  openGraph: {
    title: "MALGUARD AI — AI Powered Malware Detection System",
    description: "Detect Threats. Understand Risks. Stay Protected.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`dark ${geistSans.variable} ${geistMono.variable}`}>
      <body className="bg-[#060D19] text-slate-100 antialiased selection:bg-cyan-500/30 selection:text-cyan-200 min-h-screen flex flex-col font-sans overflow-x-hidden">
        <AuthProvider>
          <SmoothScroll>
            {children}
            <FloatingMalixOrb />
          </SmoothScroll>
        </AuthProvider>
      </body>
    </html>
  );
}
