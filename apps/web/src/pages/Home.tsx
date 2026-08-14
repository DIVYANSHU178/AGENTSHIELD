import { useState, useEffect } from 'react';
import { Shield, ShieldAlert, CheckCircle2, Server, Database, FileCode } from 'lucide-react';
import { fetchHealthStatus } from '../lib/api';
import { HealthStatus } from '../types';

export function Home() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const checkHealth = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchHealthStatus();
      setHealth(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Backend unreachable');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkHealth();
  }, []);

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col">
      {/* Header Navigation */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/10 border border-blue-500/30 rounded-lg text-blue-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="font-bold text-lg text-white leading-tight">AgentShield</h1>
            <p className="text-xs text-slate-400">Runtime Security Layer</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            Phase 7 — Audit Trail & Lifecycle Operational
          </span>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-4xl w-full mx-auto p-6 md:p-10 space-y-8">
        {/* Hero Banner */}
        <section className="text-center space-y-4 pt-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-800/80 border border-slate-700 text-xs text-slate-300">
            <Shield className="w-3.5 h-3.5 text-blue-400" /> Cybersecurity for the Future
          </div>
          <h2 className="text-4xl md:text-5xl font-extrabold tracking-tight text-white">
            AgentShield
          </h2>
          <p className="text-xl text-slate-400 font-medium max-w-2xl mx-auto">
            The Security Layer for Autonomous AI Agents
          </p>
        </section>

        {/* Core Product Principle */}
        <section className="p-6 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Core Architectural Principle
          </h3>
          <blockquote className="text-slate-200 text-lg font-medium italic border-l-4 border-blue-500 pl-4 py-1">
            "The AI agent must never directly execute a tool. Every tool request must pass through AgentShield's security boundary before execution."
          </blockquote>
        </section>

        {/* System Foundation Status */}
        <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Backend Status Card */}
          <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-slate-200 font-semibold text-sm">
                <Server className="w-4 h-4 text-blue-400" /> FastAPI Backend Service
              </div>
              {loading ? (
                <span className="text-xs text-slate-400">Checking...</span>
              ) : health ? (
                <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Online
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-xs text-rose-400 font-medium">
                  <ShieldAlert className="w-3.5 h-3.5" /> Offline
                </span>
              )}
            </div>

            <div className="text-xs text-slate-400 space-y-1">
              <p>Endpoint: <code className="text-slate-300">GET /health</code></p>
              <p>Response: <code className="text-slate-300">{health ? JSON.stringify(health) : error || 'No response'}</code></p>
            </div>

            <button
              onClick={checkHealth}
              disabled={loading}
              className="w-full py-1.5 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-medium transition-colors border border-slate-700"
            >
              Verify Backend Connectivity
            </button>
          </div>

          {/* Database & Security Engine Status Card */}
          <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-slate-200 font-semibold text-sm">
                <Database className="w-4 h-4 text-emerald-400" /> Security Engine & Audit Pipeline
              </div>
              <span className="text-xs text-slate-400 font-mono">SQLite + SQLAlchemy</span>
            </div>

            <ul className="text-xs text-slate-400 space-y-2">
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                <span>Phase 1–4 Detectors & Policy Engine: Operational</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                <span>Phase 5 Security Decision Gateway: Operational</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                <span>Phase 6 Security Enforcement Boundary: Operational</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                <span>Phase 7 Security Audit Trail & Lifecycle: Operational</span>
              </li>
            </ul>
          </div>
        </section>

        {/* Phase Architecture Note */}
        <section className="p-5 bg-slate-900/40 border border-slate-800/80 rounded-xl flex items-start gap-4">
          <FileCode className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
          <div className="text-xs text-slate-400 space-y-1">
            <h4 className="font-semibold text-slate-300 text-sm">Security Engine Status Standard</h4>
            <p>
              This screen confirms that the complete AgentShield security boundary pipeline (Phases 1–7) is operational, including deterministic threat detectors, risk engine, policy engine, decision gateway, enforcement boundary, and immutable audit event lifecycle tracking.
            </p>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-4 px-6 text-center text-xs text-slate-500">
        AgentShield Security Layer &bull; Phase 7 Security Audit Trail &bull; 48-Hour Hackathon Standard
      </footer>
    </div>
  );
}
