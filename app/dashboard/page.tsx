// src/app/dashboard/page.tsx
"use client";

import ThreatAnalysisDashboard from "@/components/ThreatAnalysisDashboard";

export default function DashboardPage() {
  return (
    <div className="min-h-screen bg-black text-white">
      <ThreatAnalysisDashboard />
    </div>
  );
}