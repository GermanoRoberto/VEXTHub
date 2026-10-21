"use client";

import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Boxes,
  CheckCircle2,
  Download,
  ExternalLink,
  Monitor,
  Network,
  RefreshCw,
  Shield,
  TerminalSquare,
} from "lucide-react";

type DevEndpoint = {
  id: string;
  hostname: string;
  unit: string;
  os_name: string;
  agent_version: string;
  last_pulse: string;
  risk_score: number;
  risk_level: string;
  findings_count: number;
  inventory_data: {
    software?: Array<{ name?: string; version?: string; publisher?: string }>;
    network_connections?: {
      listening_tcp_ports?: Array<{ local_address?: string; local_port?: number; exposure?: string }>;
      established_external_tcp?: Array<{
        local_address?: string;
        local_port?: number;
        remote_address?: string;
        remote_port?: number;
        state?: string;
      }>;
    };
  };
};

type DevAlert = {
  id: string;
  hostname: string;
  unit: string;
  software_name: string;
  message: string;
  severity: string;
  detection_category?: string;
};

type DevTelemetryData = {
  generated_at: string;
  telemetry_endpoint: string;
  csharp_agent: {
    version: string;
    source: string;
    binary: string;
    preferred_installer: string;
    bootstrap: string;
  };
  summary: {
    endpoints: number;
    active_alerts: number;
    high_risk_endpoints: number;
    critical_endpoints: number;
    installed_software: number;
    external_sessions: number;
  };
  endpoints: DevEndpoint[];
  alerts: DevAlert[];
  notes: string[];
};

function riskClass(score: number) {
  if (score >= 85) return "text-rose-500 bg-rose-500/10 border-rose-500/20";
  if (score >= 65) return "text-amber-500 bg-amber-500/10 border-amber-500/20";
  if (score >= 35) return "text-sky-500 bg-sky-500/10 border-sky-500/20";
  return "text-emerald-500 bg-emerald-500/10 border-emerald-500/20";
}

function severityClass(severity: string) {
  switch (severity) {
    case "critical":
      return "text-rose-500 border-rose-500/20 bg-rose-500/10";
    case "high":
      return "text-amber-500 border-amber-500/20 bg-amber-500/10";
    case "medium":
      return "text-sky-500 border-sky-500/20 bg-sky-500/10";
    default:
      return "text-emerald-500 border-emerald-500/20 bg-emerald-500/10";
  }
}

function formatRelativeTime(value: string) {
  const diffMs = Date.now() - new Date(value).getTime();
  const minutes = Math.max(0, Math.round(diffMs / 60000));
  if (minutes < 1) return "agora";
  if (minutes < 60) return `${minutes} min`;
  return `${Math.round(minutes / 60)} h`;
}

export function DevTelemetryClient() {
  const [data, setData] = useState<DevTelemetryData | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedEndpoint = useMemo(() => {
    if (!data) return null;
    return data.endpoints.find((endpoint) => endpoint.id === selectedId) || data.endpoints[0] || null;
  }, [data, selectedId]);

  const fetchTelemetry = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("/api/dev/telemetry", { cache: "no-store" });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Falha ao carregar telemetria dev.");
      setData(result);
      setSelectedId((current) => current || result.endpoints?.[0]?.id || null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Falha ao carregar telemetria dev.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
  }, []);

  const stats = [
    { label: "Endpoints", value: data?.summary.endpoints || 0, icon: Monitor },
    { label: "Alertas", value: data?.summary.active_alerts || 0, icon: AlertTriangle },
    { label: "Softwares", value: data?.summary.installed_software || 0, icon: Boxes },
    { label: "Sessoes externas", value: data?.summary.external_sessions || 0, icon: Network },
  ];

  return (
    <main className="min-h-screen bg-background text-foreground">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-6 md:px-8">
        <header className="flex flex-col gap-4 border-b border-border/60 pb-5 md:flex-row md:items-end md:justify-between">
          <div>
            <div className="mb-3 inline-flex items-center gap-2 rounded-md border border-amber-500/20 bg-amber-500/10 px-3 py-1 text-[10px] font-black uppercase tracking-widest text-amber-500">
              <TerminalSquare className="h-3.5 w-3.5" />
              Dev sem Supabase
            </div>
            <h1 className="text-3xl font-black tracking-tight">Telemetria VextHub</h1>
            <p className="mt-2 max-w-2xl text-sm text-foreground/55">
              Area local para testar agente, inventario, risco e portas sensiveis sem login e sem banco.
            </p>
          </div>
          <button
            onClick={fetchTelemetry}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-foreground/10 bg-foreground/5 px-4 py-2 text-xs font-bold hover:bg-foreground/10"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Atualizar
          </button>
        </header>

        {error && (
          <div className="rounded-lg border border-rose-500/20 bg-rose-500/10 p-4 text-sm text-rose-500">
            {error}
          </div>
        )}

        <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {stats.map((stat) => (
            <div key={stat.label} className="rounded-lg border border-border/50 bg-card p-5">
              <div className="flex items-center justify-between text-foreground/45">
                <span className="text-[10px] font-black uppercase tracking-widest">{stat.label}</span>
                <stat.icon className="h-4 w-4" />
              </div>
              <p className="mt-3 text-3xl font-black">{stat.value}</p>
            </div>
          ))}
        </section>

        <section className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
          <div className="rounded-lg border border-border/50 bg-card">
            <div className="flex items-center justify-between border-b border-border/50 p-4">
              <div>
                <h2 className="text-sm font-black uppercase tracking-widest text-foreground/55">Endpoints mockados</h2>
                <p className="mt-1 text-xs text-foreground/45">AnyDesk aparece no inventario, mas nao alerta por padrao.</p>
              </div>
              <Shield className="h-5 w-5 text-emerald-500" />
            </div>
            <div className="divide-y divide-border/40">
              {(data?.endpoints || []).map((endpoint) => (
                <button
                  key={endpoint.id}
                  onClick={() => setSelectedId(endpoint.id)}
                  className={`grid w-full gap-4 p-4 text-left transition hover:bg-foreground/[0.03] md:grid-cols-[1fr_auto] ${
                    selectedEndpoint?.id === endpoint.id ? "bg-foreground/[0.04]" : ""
                  }`}
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-bold">{endpoint.hostname}</p>
                      <span className="rounded border border-border/60 px-2 py-0.5 text-[10px] font-bold uppercase text-foreground/45">
                        {endpoint.unit}
                      </span>
                    </div>
                    <p className="mt-1 truncate text-xs text-foreground/45">
                      {endpoint.os_name} - agente {endpoint.agent_version} - ultimo pulso {formatRelativeTime(endpoint.last_pulse)}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`rounded-md border px-3 py-1 text-xs font-black ${riskClass(endpoint.risk_score)}`}>
                      risco {endpoint.risk_score}
                    </span>
                    <span className="text-xs text-foreground/45">{endpoint.findings_count} achados</span>
                  </div>
                </button>
              ))}
            </div>
          </div>

          <div className="rounded-lg border border-border/50 bg-card">
            <div className="border-b border-border/50 p-4">
              <h2 className="text-sm font-black uppercase tracking-widest text-foreground/55">Detalhe do endpoint</h2>
            </div>
            {selectedEndpoint ? (
              <div className="space-y-5 p-4">
                <div>
                  <p className="text-lg font-black">{selectedEndpoint.hostname}</p>
                  <p className="text-xs text-foreground/45">{selectedEndpoint.unit}</p>
                </div>

                <div>
                  <h3 className="mb-2 text-xs font-black uppercase tracking-widest text-foreground/45">Software instalado</h3>
                  <div className="max-h-44 space-y-2 overflow-auto pr-1">
                    {(selectedEndpoint.inventory_data.software || []).map((item, index) => (
                      <div key={`${item.name}-${index}`} className="rounded-md border border-border/50 bg-foreground/[0.03] p-3">
                        <p className="text-sm font-bold">{item.name}</p>
                        <p className="text-xs text-foreground/45">{item.publisher || "publisher desconhecido"} - {item.version || "sem versao"}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h3 className="mb-2 text-xs font-black uppercase tracking-widest text-foreground/45">Portas e sessoes</h3>
                  <div className="space-y-2">
                    {(selectedEndpoint.inventory_data.network_connections?.listening_tcp_ports || []).slice(0, 6).map((port, index) => (
                      <div key={`listener-${index}`} className="flex items-center justify-between rounded-md border border-border/50 p-3 text-xs">
                        <span>TCP {port.local_address}:{port.local_port}</span>
                        <span className="text-foreground/45">{port.exposure}</span>
                      </div>
                    ))}
                    {(selectedEndpoint.inventory_data.network_connections?.established_external_tcp || []).slice(0, 6).map((connection, index) => (
                      <div key={`session-${index}`} className="rounded-md border border-amber-500/20 bg-amber-500/10 p-3 text-xs text-amber-600">
                        {connection.local_address}:{connection.local_port} {"<-"} {connection.remote_address}:{connection.remote_port}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <p className="p-4 text-sm text-foreground/45">Nenhum endpoint carregado.</p>
            )}
          </div>
        </section>

        <section className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
          <div className="rounded-lg border border-border/50 bg-card p-5">
            <div className="mb-4 flex items-center gap-2">
              <Download className="h-5 w-5 text-emerald-500" />
              <h2 className="text-sm font-black uppercase tracking-widest text-foreground/55">Agente C#</h2>
            </div>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between gap-3">
                <span className="text-foreground/45">Versao</span>
                <span className="font-mono">{data?.csharp_agent.version || "4.1.0"}</span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-foreground/45">Bootstrap</span>
                <span className="font-mono">{data?.csharp_agent.bootstrap || "x-agent-key -> x-agent-token"}</span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-foreground/45">Installer</span>
                <span className="font-mono">{data?.csharp_agent.preferred_installer || "/api/installer/:unitName"}</span>
              </div>
            </div>
            <button
              onClick={() => {
                window.location.assign("/api/installer/Matriz%20TI");
              }}
              className="mt-5 inline-flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-4 py-2 text-xs font-black text-emerald-600 hover:bg-emerald-500/20"
            >
              Baixar ZIP mockado da Matriz TI
              <ExternalLink className="h-3.5 w-3.5" />
            </button>
          </div>

          <div className="rounded-lg border border-border/50 bg-card">
            <div className="border-b border-border/50 p-4">
              <h2 className="text-sm font-black uppercase tracking-widest text-foreground/55">Alertas gerados pelo detector local</h2>
            </div>
            <div className="divide-y divide-border/40">
              {(data?.alerts || []).map((alert) => (
                <div key={alert.id} className="p-4">
                  <div className="mb-2 flex items-center justify-between gap-3">
                    <p className="font-bold">{alert.software_name}</p>
                    <span className={`rounded border px-2 py-1 text-[10px] font-black uppercase ${severityClass(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </div>
                  <p className="line-clamp-2 text-xs text-foreground/55">{alert.message}</p>
                  <p className="mt-2 text-[11px] text-foreground/35">
                    {alert.hostname} - {alert.unit} - {alert.detection_category || "finding"}
                  </p>
                </div>
              ))}
              {!data?.alerts?.length && (
                <div className="flex items-center gap-2 p-4 text-sm text-emerald-500">
                  <CheckCircle2 className="h-4 w-4" />
                  Nenhum alerta ativo nos dados dev.
                </div>
              )}
            </div>
          </div>
        </section>

        <section className="rounded-lg border border-border/50 bg-card p-5">
          <h2 className="mb-3 text-sm font-black uppercase tracking-widest text-foreground/55">Notas de seguranca</h2>
          <div className="grid gap-2 md:grid-cols-3">
            {(data?.notes || []).map((note) => (
              <div key={note} className="rounded-md border border-border/50 bg-foreground/[0.03] p-3 text-xs text-foreground/55">
                {note}
              </div>
            ))}
          </div>
        </section>
      </div>
    </main>
  );
}
