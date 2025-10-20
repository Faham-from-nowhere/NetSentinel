// src/components/ThreatAnalysisDashboard.tsx
"use client";

import React, { useEffect, useId, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { useOutsideClick } from "@/hooks/use-outside-click";
import axios from "axios";
import { Remarkable } from "remarkable";

interface IncidentSequenceItem {
  timestamp: string;
  type: string;
  details: string;
}

interface Alert {
  incident_id: string;
  threat_score: number;
  main_event: string;
  status: string;
  sequence: IncidentSequenceItem[];
  ai_summary: string; // This is Markdown
}

interface FullIncident extends Alert {
  first_seen: number;
  last_seen: number;
  attacker_ip: string;
}

const API_BASE = "http://localhost:8000";
const md = new Remarkable();

// Helper to safely render Markdown
const renderMarkdown = (markdown: string): string => {
  if (!markdown) return "";
  // Optional: sanitize further if needed (not required for hackathon if backend is trusted)
  return md.render(markdown);
};

export default function ThreatAnalysisDashboard() {
  const [mode, setMode] = useState<"live" | "twin">("live");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [active, setActive] = useState<FullIncident | null>(null);
  const [loading, setLoading] = useState(true);
  const ref = useRef<HTMLDivElement>(null);
  const id = useId();

  useEffect(() => {
    document.body.style.overflow = active ? "hidden" : "auto";
    return () => {
      document.body.style.overflow = "auto";
    };
  }, [active]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setActive(null);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useOutsideClick(ref, () => setActive(null));

  const handleCardClick = async (alert: Alert) => {
    try {
      const res = await axios.get<FullIncident>(
        `${API_BASE}/api/incident/${alert.incident_id}`
      );
      setActive(res.data);
    } catch (err) {
      console.error("Failed to load incident", err);
      setActive({
        ...alert,
        first_seen: Date.now(),
        last_seen: Date.now(),
        attacker_ip: "Unknown",
      });
    }
  };

  useEffect(() => {
    if (mode !== "live") return;

    const ws = new WebSocket("ws://localhost:8000/ws/live");
    ws.onopen = () => console.log("✅ Connected to NetSentinel Live Feed");
    ws.onmessage = (event) => {
      const alert = JSON.parse(event.data) as Alert;
      setAlerts((prev) => [alert, ...prev.slice(0, 9)]);
      setLoading(false);
    };
    ws.onerror = () => setLoading(false);
    return () => ws.close();
  }, [mode]);

  const formatTime = (iso: string) => {
    return new Date(iso).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const triggerSimulation = async (type: "portscan" | "udpflood") => {
    try {
      await axios.post(`${API_BASE}/api/simulate/${type === "portscan" ? "portscan" : "udpflood"}`);
      console.log(`✅ ${type} simulation triggered`);
    } catch (err) {
      console.error("Failed to trigger simulation", err);
    }
  };

  // Extract first sentence or line from Markdown for preview
  const getPreviewText = (markdown: string): string => {
    if (!markdown) return "Awaiting AI analysis...";
    // Remove markdown syntax for clean preview
    const plain = markdown
      .replace(/[#*_`[\]()]/g, "")
      .split("\n")[0]
      .trim();
    return plain || "No summary available.";
  };

  return (
    <>
      <AnimatePresence>
        {active && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/40 z-10"
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {active && (
          <div className="fixed inset-0 grid place-items-center z-[100]">
            <motion.button
              layout
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setActive(null)}
              className="absolute top-4 right-4 lg:hidden bg-neutral-800 rounded-full p-2"
            >
              <CloseIcon />
            </motion.button>
            <motion.div
              layoutId={`card-${active.incident_id}-${id}`}
              ref={ref}
              className="w-full max-w-2xl h-[90vh] flex flex-col bg-neutral-900 text-white rounded-xl overflow-hidden border border-neutral-800"
            >
              <div className="p-6 border-b border-neutral-800">
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="text-xl font-bold text-emerald-400">
                      {active.main_event}
                    </h3>
                    <p className="text-sm text-neutral-400 mt-1">
                      ID: {active.incident_id} • Attacker: {active.attacker_ip}
                    </p>
                  </div>
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-bold ${
                      active.threat_score >= 80
                        ? "bg-red-900/50 text-red-300"
                        : active.threat_score >= 50
                        ? "bg-yellow-900/50 text-yellow-300"
                        : "bg-green-900/50 text-green-300"
                    }`}
                  >
                    Threat: {active.threat_score}/100
                  </span>
                </div>
              </div>

              <div className="p-6 border-b border-neutral-800">
                <h4 className="font-semibold text-neutral-200 mb-2">AI Analyst Summary</h4>
                <div
                  className="text-neutral-300 text-sm leading-relaxed prose prose-invert max-w-none"
                  dangerouslySetInnerHTML={{ __html: renderMarkdown(active.ai_summary) }}
                />
              </div>

              <div className="flex-1 overflow-auto p-6">
                <h4 className="font-semibold text-neutral-200 mb-4">Threat Story Timeline</h4>
                <div className="space-y-4">
                  {active.sequence.map((e, i) => (
                    <div key={i} className="flex gap-3">
                      <div className="mt-1 w-2 h-2 rounded-full bg-emerald-500"></div>
                      <div>
                        <p className="text-xs text-neutral-500">{formatTime(e.timestamp)}</p>
                        <p className="font-medium text-neutral-100">{e.type}</p>
                        <p className="text-sm text-neutral-400">{e.details}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      <div className="max-w-4xl mx-auto p-4">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-2xl font-bold text-white">NetSentinel Command Center</h1>
          <div className="flex gap-2">
            <button
              onClick={() => setMode("live")}
              className={`px-4 py-2 text-sm rounded-lg font-medium ${
                mode === "live"
                  ? "bg-emerald-600 text-white"
                  : "bg-neutral-800 text-neutral-400 hover:text-white"
              }`}
            >
              Live
            </button>
            <button
              onClick={() => setMode("twin")}
              className={`px-4 py-2 text-sm rounded-lg font-medium ${
                mode === "twin"
                  ? "bg-purple-600 text-white"
                  : "bg-neutral-800 text-neutral-400 hover:text-white"
              }`}
            >
              Digital Twin
            </button>
          </div>
        </div>

        {mode === "twin" && (
          <div className="mb-6 p-4 bg-neutral-800/50 border border-purple-900/50 rounded-xl">
            <h2 className="text-lg font-semibold text-purple-300 mb-3">Simulate Attacks</h2>
            <div className="flex flex-wrap gap-3">
              <button
                onClick={() => triggerSimulation("portscan")}
                className="px-4 py-2 bg-red-900/60 hover:bg-red-800 text-red-200 rounded-lg text-sm font-medium transition"
              >
                Simulate Port Scan
              </button>
              <button
                onClick={() => triggerSimulation("udpflood")}
                className="px-4 py-2 bg-orange-900/60 hover:bg-orange-800 text-orange-200 rounded-lg text-sm font-medium transition"
              >
                Simulate UDP Flood
              </button>
            </div>
            <p className="text-xs text-neutral-500 mt-2">
              Simulated attacks will appear in the feed below as if they were real.
            </p>
          </div>
        )}

        {mode === "live" && loading && (
          <p className="text-neutral-400 mb-4">Connecting to live network feed...</p>
        )}

        {alerts.length === 0 && !loading && mode === "live" && (
          <p className="text-neutral-500 mb-4">No threats detected yet.</p>
        )}

        <ul className="space-y-4">
          {alerts.map((alert) => (
            <motion.div
              layoutId={`card-${alert.incident_id}-${id}`}
              key={alert.incident_id}
              onClick={() => handleCardClick(alert)}
              className="p-4 flex items-start gap-4 hover:bg-neutral-800/50 rounded-xl cursor-pointer border border-neutral-800 bg-neutral-900"
            >
              <div className="flex-shrink-0 w-12 h-12 rounded-lg bg-gradient-to-br from-red-900/30 to-emerald-900/20 flex items-center justify-center">
                <span className="text-lg font-bold text-white">
                  {Math.round(alert.threat_score / 10)}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="font-bold text-emerald-400 truncate">{alert.main_event}</h3>
                <p className="text-neutral-400 text-sm mt-1 line-clamp-2">
                  {getPreviewText(alert.ai_summary)}
                </p>
                <p className="text-xs text-neutral-500 mt-2">
                  {formatTime(alert.sequence[0]?.timestamp || "")} • {alert.incident_id}
                </p>
              </div>
              <button className="px-3 py-1.5 text-xs rounded-lg font-medium bg-neutral-800 text-emerald-400 whitespace-nowrap">
                View Story
              </button>
            </motion.div>
          ))}
        </ul>
      </div>
    </>
  );
}

const CloseIcon = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width="20"
    height="20"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    className="text-neutral-300"
  >
    <path d="M18 6l-12 12" />
    <path d="M6 6l12 12" />
  </svg>
);