// src/components/ThreatAnalysisDashboard.tsx
"use client";

import React, { useEffect, useState } from "react";
import axios from "axios";
import { Remarkable } from "remarkable";

// Types from NetSentinel Bible (Section 3.1)
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
  ai_summary: string;
}

interface FullIncident extends Alert {
  first_seen: number;
  last_seen: number;
  attacker_ip: string;
}

const API_BASE = "http://localhost:8000";
const md = new Remarkable();

const renderMarkdown = (text: string): string => {
  if (!text) return "";
  return md.render(text);
};

const formatTime = (iso: string) => {
  return new Date(iso).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
};

export default function ThreatAnalysisDashboard() {
  const [mode, setMode] = useState<"live" | "twin">("live");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [activeIncident, setActiveIncident] = useState<FullIncident | null>(null);

  // WebSocket: connect once, stay connected
  useEffect(() => {
    const ws = new WebSocket("ws://localhost:8000/ws/live");

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.incident_id && typeof data.threat_score === "number") {
          setAlerts((prev) => [data, ...prev.slice(0, 9)]);
        }
      } catch (e) {
        console.error("Failed to parse WebSocket message:", e);
      }
    };

    ws.onerror = (err) => console.error("WebSocket error:", err);
    ws.onclose = () => console.log("WebSocket closed");

    return () => ws.close();
  }, []);

  const handleModeChange = (newMode: "live" | "twin") => {
    setMode(newMode);
    // Do NOT clear alerts — per Bible Section 3.3
  };

  const triggerSimulation = async (type: "portscan" | "udpflood") => {
    try {
      await axios.post(`${API_BASE}/api/simulate/${type}`);
      console.log(`✅ ${type} simulation triggered`);
      // Success is silent — no disruptive alert
    } catch (err) {
      console.error(`Simulation failed:`, err);
    }
  };

  const handleAlertClick = async (alert: Alert) => {
    try {
      const res = await axios.get<FullIncident>(
        `${API_BASE}/api/incident/${alert.incident_id}`
      );
      setActiveIncident(res.data);
    } catch (err) {
      console.error("Failed to load incident:", err);
      // Fallback for demo
      setActiveIncident({
        ...alert,
        first_seen: Date.now(),
        last_seen: Date.now(),
        attacker_ip: "192.168.1.100",
      });
    }
  };

  const handleMitigate = async () => {
    if (!activeIncident?.attacker_ip) return;
    try {
      await axios.post(`${API_BASE}/api/mitigate/block_ip/${activeIncident.attacker_ip}`);
      alert(`✅ IP ${activeIncident.attacker_ip} redirected to honeypot!`);
      setActiveIncident(null);
    } catch (err) {
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-4 text-white">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">NetSentinel Command Center</h1>
        <div className="flex gap-2">
          <button
            onClick={() => handleModeChange("live")}
            className={`px-4 py-2 text-sm rounded-lg font-medium ${
              mode === "live"
                ? "bg-emerald-600 text-white"
                : "bg-neutral-800 text-neutral-400 hover:text-white"
            }`}
          >
            Live
          </button>
          <button
            onClick={() => handleModeChange("twin")}
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
        <div className="mb-6 p-4 bg-purple-900/20 border border-purple-700/30 rounded-xl">
          <h2 className="text-lg font-semibold text-purple-300 mb-3">Simulate Attacks</h2>
          <div className="flex gap-3">
            <button
              onClick={() => triggerSimulation("portscan")}
              className="px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg text-sm font-medium"
            >
              Simulate Port Scan
            </button>
            <button
              onClick={() => triggerSimulation("udpflood")}
              className="px-4 py-2 bg-orange-700 hover:bg-orange-600 text-white rounded-lg text-sm font-medium"
            >
              Simulate UDP Flood
            </button>
          </div>
        </div>
      )}

      {/* Alert List */}
      <div className="space-y-4">
        {alerts.length === 0 ? (
          <p className="text-neutral-500">
            {mode === "live"
              ? "No threats detected yet."
              : "Click a simulation button to generate an alert."}
          </p>
        ) : (
          alerts.map((alert) => (
            <div
              key={alert.incident_id}
              onClick={() => handleAlertClick(alert)}
              className="p-4 bg-neutral-900 border border-neutral-800 rounded-lg cursor-pointer hover:bg-neutral-800 transition"
            >
              <div className="flex justify-between">
                <h3 className="font-bold text-emerald-400">{alert.main_event}</h3>
                <span className="text-sm text-neutral-400">ID: {alert.incident_id}</span>
              </div>
              <p className="text-sm text-neutral-400 mt-1 line-clamp-2">
                {alert.ai_summary?.split(".")[0] || "Awaiting AI analysis..."}
              </p>
              <p className="text-xs text-neutral-500 mt-2">
                {formatTime(alert.sequence[0]?.timestamp || "")}
              </p>
            </div>
          ))
        )}
      </div>

      {/* Incident Modal */}
      {activeIncident && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-neutral-900 border border-neutral-700 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-auto">
            <div className="p-6">
              <div className="flex justify-between items-start">
                <div>
                  <h2 className="text-xl font-bold text-emerald-400">
                    {activeIncident.main_event}
                  </h2>
                  <p className="text-sm text-neutral-400">
                    Attacker: {activeIncident.attacker_ip}
                  </p>
                </div>
                <button
                  onClick={() => setActiveIncident(null)}
                  className="text-neutral-400 hover:text-white text-2xl"
                >
                  &times;
                </button>
              </div>

              <div className="mt-4">
                <h3 className="font-semibold text-neutral-200">AI Analyst Summary</h3>
                <div
                  className="text-neutral-300 mt-2 prose prose-invert max-w-none"
                  dangerouslySetInnerHTML={{ __html: renderMarkdown(activeIncident.ai_summary) }}
                />
              </div>

              <div className="mt-6">
                <h3 className="font-semibold text-neutral-200">Threat Story Timeline</h3>
                <div className="mt-4 space-y-3">
                  {activeIncident.sequence.map((e, i) => (
                    <div key={i} className="flex gap-3">
                      <div className="w-2 h-2 rounded-full bg-emerald-500 mt-2"></div>
                      <div>
                        <p className="text-xs text-neutral-500">{formatTime(e.timestamp)}</p>
                        <p className="font-medium text-neutral-100">{e.type}</p>
                        <p className="text-sm text-neutral-400">{e.details}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {activeIncident.attacker_ip && activeIncident.attacker_ip !== "Unknown" && (
                <div className="mt-6">
                  <button
                    onClick={handleMitigate}
                    className="w-full py-2 bg-rose-800 hover:bg-rose-700 text-rose-200 rounded-lg font-medium"
                  >
                    🛡️ Mitigate: Redirect to Honeypot
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}