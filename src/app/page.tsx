"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/context/AuthContext";
import Navbar from "@/components/Navbar";
import ParticleField from "@/components/ParticleField";
import Hero from "@/components/Hero";
import FeatureCards from "@/components/FeatureCards";
import WorkflowSection from "@/components/WorkflowSection";
import ArchitectureSection from "@/components/ArchitectureSection";
import ScanModal from "@/components/ScanModal";
import Footer from "@/components/Footer";

export default function Home() {
  const router = useRouter();
  const { user } = useAuth();
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);

  const handleOpenScan = () => {
    if (!user) {
      router.push("/login?redirectTo=/scanner");
    } else {
      setIsScanModalOpen(true);
    }
  };

  return (
    <main className="relative min-h-screen bg-[#060D19] text-slate-100 overflow-hidden">
      {/* Background Animated Particle Field */}
      <ParticleField count={26} />

      {/* Cyber Grid Subtle Overlay */}
      <div className="absolute inset-0 cyber-grid opacity-25 pointer-events-none" />

      {/* Ambient Neon Background Light Beacons with GPU Promotion */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-[600px] bg-gradient-to-b from-cyan-500/10 via-purple-600/10 to-transparent blur-[140px] pointer-events-none -z-10 gpu-halo" />

      {/* Sticky Minimal Navbar */}
      <Navbar onOpenScanModal={handleOpenScan} />

      {/* Hero Section with 3D Cyber Shield */}
      <Hero onOpenScanModal={handleOpenScan} />

      {/* Three Animated Feature Cards */}
      <FeatureCards />

      {/* Animated Workflow: Upload → Analyze → Results */}
      <WorkflowSection />

      {/* Architecture & Malix AI Intelligence */}
      <ArchitectureSection onOpenScanModal={handleOpenScan} />

      {/* Minimal Footer */}
      <Footer onOpenScanModal={handleOpenScan} />

      {/* Interactive Scan Modal triggered by CTA buttons */}
      <ScanModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
      />
    </main>
  );
}
