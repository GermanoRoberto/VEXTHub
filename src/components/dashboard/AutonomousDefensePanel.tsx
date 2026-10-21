"use client";

import React from "react";
import { ShieldCheck, Zap, Activity, AlertTriangle, CheckCircle2 } from "lucide-react";

export interface AutonomousAction {
  id: string;
  timestamp: string;
  hostname: string;
  unit: string;
  triggerReason: string;
  actionType: "RUN_COMPLIANCE_SCAN" | "REFRESH_INVENTORY" | "UPDATE_AGENT";
  target?: string;
  status: "EXECUTED" | "ENQUEUED" | "VERIFYING";
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
}

export interface EndpointAnomaly {
  hostname: string;
  unit: string;
  maxZScore: number;
  anomalies: Array<{
    metric: string;
    value: number;
    mean: number;
    stdDev: number;
    zScore: number;
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    description: string;
  }>;
}

export interface ThreatCluster {
  unit: string;
  totalMachines: number;
  unauthorizedCount: number;
  activeAlertsCount: number;
  outbreakSeverity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  topThreatSoftware: string[];
  affectedHostnames: string[];
  summary: string;
}

interface AutonomousDefensePanelProps {
  autonomousActions?: AutonomousAction[];
  anomalies?: EndpointAnomaly[];
  threatClusters?: ThreatCluster[];
}

export default function AutonomousDefensePanel({
  autonomousActions = [],
  anomalies = [],
  threatClusters = [],
}: AutonomousDefensePanelProps) {
  const activeAnomaliesCount = anomalies.length;
  const actionsCount = autonomousActions.length;
  const criticalClustersCount = threatClusters.filter((c) => c.outbreakSeverity === "CRITICAL" || c.outbreakSeverity === "HIGH").length;

  return (
    <div className="bg-slate-900/80 backdrop-blur-md border border-cyan-500/20 rounded-2xl p-6 shadow-2xl space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-xl text-cyan-400 animate-pulse">
            <Zap className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="text-lg font-bold text-slate-100 tracking-wide">
                Córtex IA — Motor de Defesa Autônoma
              </h3>
              <span className="px-2.5 py-0.5 text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-full flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                ATIVO
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Análise contínua de anomalias por Z-Score, clusterização de surtos e mitigação sem intervenção humana.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <div className="bg-slate-800/80 px-3 py-2 rounded-lg border border-slate-700 text-slate-300">
            <span className="text-cyan-400 font-bold text-sm">{actionsCount}</span> Ações Autônomas
          </div>
          <div className="bg-slate-800/80 px-3 py-2 rounded-lg border border-slate-700 text-slate-300">
            <span className="text-amber-400 font-bold text-sm">{activeAnomaliesCount}</span> Anomalias Z-Score
          </div>
          <div className="bg-slate-800/80 px-3 py-2 rounded-lg border border-slate-700 text-slate-300">
            <span className="text-rose-400 font-bold text-sm">{criticalClustersCount}</span> Surtos em Frota
          </div>
        </div>
      </div>

      {/* Grid: Autonomous Actions & Z-Score Anomalies */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Feed de Ações Autônomas */}
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-300 uppercase tracking-wider">
            <span className="flex items-center gap-1.5 text-cyan-400">
              <ShieldCheck className="w-4 h-4" /> Ações de Mitigação Automática
            </span>
            <span className="text-slate-500">Últimos disparos</span>
          </div>

          <div className="space-y-2 max-h-72 overflow-y-auto pr-1 custom-scrollbar">
            {autonomousActions.length === 0 ? (
              <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800 text-center text-xs text-slate-500">
                Nenhuma mitigação autônoma necessária nas últimas pulsações.
              </div>
            ) : (
              autonomousActions.slice(0, 5).map((action) => (
                <div
                  key={action.id}
                  className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/80 hover:border-cyan-500/30 transition-all flex items-start justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-semibold text-slate-200">{action.hostname}</span>
                      <span className="text-slate-500">({action.unit})</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-400 border border-cyan-800">
                        {action.actionType}
                      </span>
                    </div>
                    <p className="text-slate-400 text-[11px]">{action.triggerReason}</p>
                  </div>
                  <div className="flex flex-col items-end gap-1">
                    <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" /> {action.status}
                    </span>
                    <span className="text-[10px] text-slate-500">
                      {new Date(action.timestamp).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" })}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right: Anomalias Estatísticas Z-Score */}
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-300 uppercase tracking-wider">
            <span className="flex items-center gap-1.5 text-amber-400">
              <Activity className="w-4 h-4" /> Desvios Estatísticos (Z-Score &gt; 2.2)
            </span>
            <span className="text-slate-500">População Global</span>
          </div>

          <div className="space-y-2 max-h-72 overflow-y-auto pr-1 custom-scrollbar">
            {anomalies.length === 0 ? (
              <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800 text-center text-xs text-slate-500">
                Todos os endpoints operando dentro do desvio padrão esperado (&le; 2.2σ).
              </div>
            ) : (
              anomalies.slice(0, 5).map((item, idx) => (
                <div
                  key={`${item.hostname}-${idx}`}
                  className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/80 hover:border-amber-500/30 transition-all space-y-1 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">{item.hostname} ({item.unit})</span>
                    <span className="px-2 py-0.5 text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30 rounded">
                      Max Z-Score: {item.maxZScore}&sigma;
                    </span>
                  </div>
                  {item.anomalies.map((anom, aIdx) => (
                    <p key={aIdx} className="text-slate-400 text-[11px] flex items-center gap-1.5">
                      <AlertTriangle className="w-3.0 h-3.0 text-amber-400 shrink-0" />
                      <span>{anom.description}</span>
                    </p>
                  ))}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
