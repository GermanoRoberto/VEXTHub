"use client"

import React, { useEffect, useState, useCallback } from 'react'
import {
  Settings,
  Shield,
  Link2,
  ArrowLeft,
  Building2,
  Save,
  CheckCircle2,
  Activity,
  RefreshCw,
  Database,
  Server,
  Zap,
  BrainCircuit,
  KeyRound,
  AlertTriangle,
  XCircle,
} from 'lucide-react'
import Link from 'next/link'

interface DiagnosticService<TStatus = string> {
  name: string;
  status: TStatus;
  latency_ms: number | null;
  details: string;
  checks?: Record<string, string> | null;
}

interface SystemDiagnostics {
  timestamp: string;
  overall_status: "healthy" | "degraded" | "critical";
  auth: {
    mode: string;
    description: string;
    tenant_id: string;
    user_email: string;
    role: string;
  };
  services: {
    database: DiagnosticService<"connected" | "simulation_mock" | "degraded" | "error">;
    fastapi: DiagnosticService<"online" | "offline" | "degraded">;
    redis: DiagnosticService<"connected" | "fallback_direct">;
    ai_triage: {
      name: string;
      status: "ready" | "partially_configured" | "disabled" | "missing_keys";
      enabled: boolean;
      active_provider: string;
      providers: {
        groq: { configured: boolean; model: string };
        gemini: { configured: boolean; model: string };
      };
    };
  };
}

export default function SettingsPage() {
  const [companyName, setCompanyName] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  const [diagnostics, setDiagnostics] = useState<SystemDiagnostics | null>(null)
  const [testingDiag, setTestingDiag] = useState(false)
  const [diagError, setDiagError] = useState<string | null>(null)

  const fetchDiagnostics = useCallback(async () => {
    setTestingDiag(true)
    setDiagError(null)
    try {
      const res = await fetch('/api/system/status', { cache: 'no-store' })
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`)
      }
      const data = (await res.json()) as SystemDiagnostics
      setDiagnostics(data)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setDiagError(msg)
    } finally {
      setTestingDiag(false)
    }
  }, [])

  useEffect(() => {
    async function fetchConfig() {
      try {
        const res = await fetch('/api/config')
        const data = await res.json()
        setCompanyName(data.company_name || '')
      } catch (err) {
        console.error('Failed to fetch config:', err)
      } finally {
        setLoading(false)
      }
    }
    void fetchConfig()
    void fetchDiagnostics()
  }, [fetchDiagnostics])

  const handleSave = async () => {
    setSaving(true)
    setSaved(false)
    try {
      const res = await fetch('/api/config', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ company_name: companyName })
      })
      if (res.ok) {
        setSaved(true)
        setTimeout(() => setSaved(false), 3000)
      }
    } catch (err) {
      console.error('Failed to save config:', err)
      alert('Erro ao salvar as configurações.')
    } finally {
      setSaving(false)
    }
  }

  const getOverallBadge = (status: SystemDiagnostics["overall_status"]) => {
    switch (status) {
      case "healthy":
        return {
          label: "SISTEMA SAUDÁVEL",
          classes: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
          icon: <CheckCircle2 className="h-4 w-4 text-emerald-400" />
        }
      case "degraded":
        return {
          label: "OPERAÇÃO PARCIAL / FALLBACK",
          classes: "bg-amber-500/15 text-amber-400 border-amber-500/30",
          icon: <AlertTriangle className="h-4 w-4 text-amber-400" />
        }
      case "critical":
        return {
          label: "FALHA CRÍTICA DE CONEXÃO",
          classes: "bg-rose-500/15 text-rose-400 border-rose-500/30",
          icon: <XCircle className="h-4 w-4 text-rose-400" />
        }
    }
  }

  return (
    <div className="space-y-8 max-w-5xl mx-auto pb-20">
      <div className="space-y-1">
        <Link 
          href="/dashboard" 
          className="flex items-center gap-2 text-xs text-foreground/40 hover:text-primary transition-colors mb-2 group text-white"
        >
          <ArrowLeft className="h-3 w-3 group-hover:-translate-x-1 transition-transform" />
          Voltar ao Dashboard
        </Link>
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-primary/10 flex items-center justify-center border border-primary/20 text-primary">
            <Settings className="h-6 w-6" />
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-white">Configurações do Sistema</h2>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Identidade da Empresa */}
        <div className="glass-card p-6 rounded-2xl border border-white/5 space-y-6 md:col-span-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-xl bg-primary/20 flex items-center justify-center border border-primary/20">
                <Building2 className="h-6 w-6 text-primary" />
              </div>
              <div>
                <h3 className="text-lg font-bold">Identidade da Empresa</h3>
                <p className="text-xs text-foreground/40">Personalize o nome exibido em todo o dashboard.</p>
              </div>
            </div>
            
            <button
              onClick={handleSave}
              disabled={saving || loading}
              className={`flex items-center gap-2 px-6 py-2.5 rounded-xl font-bold text-sm transition-all ${
                saved 
                  ? 'bg-emerald-500 text-white' 
                  : 'bg-primary text-white hover:bg-primary/90 shadow-lg shadow-primary/20'
              }`}
            >
              {saving ? (
                <div className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : saved ? (
                <CheckCircle2 className="h-4 w-4" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              {saved ? 'Salvo!' : 'Salvar Alterações'}
            </button>
          </div>

          <div className="space-y-4 pt-2">
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground/60 ml-1">Nome da Empresa</label>
              <input 
                type="text" 
                placeholder="Ex: Minha Empresa" 
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                disabled={loading}
                className="w-full px-5 py-4 bg-foreground/5 border border-white/10 rounded-2xl text-lg outline-none focus:border-primary/50 focus:bg-foreground/[0.08] transition-all"
              />
            </div>
            <p className="text-[10px] text-foreground/30 px-1 italic">
              * Este nome será exibido nos relatórios exportados e na marca do menu lateral.
            </p>
          </div>
        </div>

        {/* Diagnóstico de Infraestrutura & Serviços */}
        <div className="glass-card p-6 rounded-2xl border border-white/5 space-y-6 md:col-span-2">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-xl bg-primary/20 flex items-center justify-center border border-primary/20 text-primary">
                <Activity className="h-6 w-6" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white">Diagnóstico de Infraestrutura &amp; Serviços</h3>
                <p className="text-xs text-foreground/40">
                  Sondagem em tempo real de latência, saúde de banco, motor tático e conectores.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              {diagnostics && (
                <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold ${getOverallBadge(diagnostics.overall_status).classes}`}>
                  {getOverallBadge(diagnostics.overall_status).icon}
                  <span>{getOverallBadge(diagnostics.overall_status).label}</span>
                </div>
              )}

              <button
                onClick={() => void fetchDiagnostics()}
                disabled={testingDiag}
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-white/5 hover:bg-white/10 text-white border border-white/10 transition-all disabled:opacity-50 shadow-sm"
                title="Testar Conectividade"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${testingDiag ? 'animate-spin text-primary' : 'text-foreground/70'}`} />
                {testingDiag ? 'Testando Conexões...' : 'Testar Conectividade'}
              </button>
            </div>
          </div>

          {diagError && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs flex items-center gap-3">
              <XCircle className="h-5 w-5 flex-shrink-0 text-rose-400" />
              <div>
                <span className="font-semibold">Erro ao obter diagnóstico:</span> {diagError}
              </div>
            </div>
          )}

          {diagnostics ? (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
                {/* 1. Camada de Autenticação */}
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 flex flex-col justify-between space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-foreground/70">
                      <KeyRound className="h-4 w-4 text-sky-400" />
                      <span className="text-xs font-semibold text-white">Autenticação</span>
                    </div>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                        diagnostics.auth.mode === 'supabase_auth'
                          ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                          : 'bg-sky-500/15 text-sky-400 border-sky-500/30'
                      }`}
                    >
                      {diagnostics.auth.mode === 'supabase_auth' ? 'SUPABASE' : 'MODO LOCAL'}
                    </span>
                  </div>
                  <div>
                    <div className="text-[11px] text-foreground/50 leading-relaxed truncate" title={diagnostics.auth.description}>
                      {diagnostics.auth.description}
                    </div>
                    <div className="text-[10px] text-foreground/40 font-mono mt-1 truncate" title={diagnostics.auth.user_email}>
                      {diagnostics.auth.user_email}
                    </div>
                  </div>
                  <div className="text-[9px] text-foreground/30 font-mono pt-1 border-t border-white/5">
                    Tenant: {diagnostics.auth.tenant_id.slice(0, 8)}...
                  </div>
                </div>

                {/* 2. Supabase PostgreSQL */}
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 flex flex-col justify-between space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-foreground/70">
                      <Database className="h-4 w-4 text-emerald-400" />
                      <span className="text-xs font-semibold text-white">PostgreSQL</span>
                    </div>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                        diagnostics.services.database.status === 'connected'
                          ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                          : diagnostics.services.database.status === 'simulation_mock'
                          ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                          : 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                      }`}
                    >
                      {diagnostics.services.database.status === 'connected'
                        ? 'CONECTADO'
                        : diagnostics.services.database.status === 'simulation_mock'
                        ? 'SIMULAÇÃO'
                        : 'ERRO'}
                    </span>
                  </div>
                  <div>
                    <div className="flex items-baseline gap-1.5">
                      <span className="text-lg font-bold font-mono text-white">
                        {diagnostics.services.database.latency_ms}
                      </span>
                      <span className="text-[10px] text-foreground/40 font-mono">ms</span>
                    </div>
                    <div className="text-[10px] text-foreground/40 leading-relaxed mt-1 line-clamp-2" title={diagnostics.services.database.details}>
                      {diagnostics.services.database.details}
                    </div>
                  </div>
                  <div className="text-[9px] text-foreground/30 font-mono pt-1 border-t border-white/5">
                    Supabase Admin SDK
                  </div>
                </div>

                {/* 3. Motor Tático FastAPI */}
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 flex flex-col justify-between space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-foreground/70">
                      <Server className="h-4 w-4 text-purple-400" />
                      <span className="text-xs font-semibold text-white">Motor Tático</span>
                    </div>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                        diagnostics.services.fastapi.status === 'online'
                          ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                          : diagnostics.services.fastapi.status === 'degraded'
                          ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                          : 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                      }`}
                    >
                      {diagnostics.services.fastapi.status.toUpperCase()}
                    </span>
                  </div>
                  <div>
                    <div className="flex items-baseline gap-1.5">
                      <span className="text-lg font-bold font-mono text-white">
                        {diagnostics.services.fastapi.latency_ms !== null ? diagnostics.services.fastapi.latency_ms : '—'}
                      </span>
                      {diagnostics.services.fastapi.latency_ms !== null && (
                        <span className="text-[10px] text-foreground/40 font-mono">ms</span>
                      )}
                    </div>
                    <div className="text-[10px] text-foreground/40 leading-relaxed mt-1 line-clamp-2" title={diagnostics.services.fastapi.details}>
                      {diagnostics.services.fastapi.details}
                    </div>
                  </div>
                  <div className="text-[9px] text-foreground/30 font-mono pt-1 border-t border-white/5">
                    FastAPI /health probe
                  </div>
                </div>

                {/* 4. Fila Assíncrona Redis */}
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 flex flex-col justify-between space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-foreground/70">
                      <Zap className="h-4 w-4 text-amber-400" />
                      <span className="text-xs font-semibold text-white">Fila de Jobs</span>
                    </div>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                        diagnostics.services.redis.status === 'connected'
                          ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                          : 'bg-sky-500/15 text-sky-400 border-sky-500/30'
                      }`}
                    >
                      {diagnostics.services.redis.status === 'connected' ? 'REDIS' : 'DIRETO'}
                    </span>
                  </div>
                  <div>
                    <div className="flex items-baseline gap-1.5">
                      <span className="text-lg font-bold font-mono text-white">
                        {diagnostics.services.redis.latency_ms !== null ? diagnostics.services.redis.latency_ms : '0'}
                      </span>
                      {diagnostics.services.redis.latency_ms !== null ? (
                        <span className="text-[10px] text-foreground/40 font-mono">ms</span>
                      ) : (
                        <span className="text-[10px] text-foreground/40 font-mono">síncrono</span>
                      )}
                    </div>
                    <div className="text-[10px] text-foreground/40 leading-relaxed mt-1 line-clamp-2" title={diagnostics.services.redis.details}>
                      {diagnostics.services.redis.details}
                    </div>
                  </div>
                  <div className="text-[9px] text-foreground/30 font-mono pt-1 border-t border-white/5">
                    ioredis client
                  </div>
                </div>

                {/* 5. Motores de IA */}
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/5 flex flex-col justify-between space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-foreground/70">
                      <BrainCircuit className="h-4 w-4 text-teal-400" />
                      <span className="text-xs font-semibold text-white">IA Defensiva</span>
                    </div>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                        diagnostics.services.ai_triage.status === 'ready'
                          ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                          : diagnostics.services.ai_triage.status === 'partially_configured'
                          ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                          : diagnostics.services.ai_triage.status === 'disabled'
                          ? 'bg-white/5 text-foreground/40 border-white/10'
                          : 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                      }`}
                    >
                      {diagnostics.services.ai_triage.status === 'ready'
                        ? 'PRONTO'
                        : diagnostics.services.ai_triage.status === 'partially_configured'
                        ? 'PARCIAL'
                        : diagnostics.services.ai_triage.status === 'disabled'
                        ? 'INATIVO'
                        : 'SEM CHAVES'}
                    </span>
                  </div>
                  <div>
                    <div className="text-[11px] font-medium text-white flex items-center justify-between">
                      <span>Provedor:</span>
                      <span className="uppercase text-primary font-bold">
                        {diagnostics.services.ai_triage.active_provider}
                      </span>
                    </div>
                    <div className="text-[10px] text-foreground/40 leading-relaxed mt-1">
                      Groq: {diagnostics.services.ai_triage.providers.groq.configured ? '✓' : '✗'} | Gemini:{' '}
                      {diagnostics.services.ai_triage.providers.gemini.configured ? '✓' : '✗'}
                    </div>
                  </div>
                  <div className="text-[9px] text-foreground/30 font-mono pt-1 border-t border-white/5 truncate" title={diagnostics.services.ai_triage.providers.groq.model}>
                    {diagnostics.services.ai_triage.providers.groq.model}
                  </div>
                </div>
              </div>

              <div className="text-[10px] text-foreground/30 text-right pr-1">
                Última sondagem realizada em: {new Date(diagnostics.timestamp).toLocaleString('pt-BR')}
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-xl bg-white/[0.02] border border-white/5 flex flex-col items-center justify-center space-y-2 text-foreground/40">
              <RefreshCw className="h-6 w-6 animate-spin text-primary" />
              <p className="text-xs">Sondando subsistemas e infraestrutura...</p>
            </div>
          )}
        </div>

        <div className="glass-card p-6 rounded-2xl border border-white/5 space-y-4">
          <div className="flex items-center gap-3">
            <Shield className="h-5 w-5 text-emerald-500" />
            <h4 className="font-bold text-white">Segurança</h4>
          </div>
          <p className="text-xs text-foreground/40 leading-relaxed">
            As chaves públicas do Supabase são carregadas por ambiente e a `service role`
            permanece no servidor do Next.js para operações administrativas protegidas.
          </p>
        </div>

        <div className="glass-card p-6 rounded-2xl border border-white/5 space-y-4">
          <div className="flex items-center gap-3">
            <Link2 className="h-5 w-5 text-primary" />
            <h4 className="font-bold text-white">Aplicação Ativa</h4>
          </div>
          <p className="text-xs text-foreground/40">
            Status: <span className="text-emerald-500 font-bold uppercase ml-1 text-[10px]">Next.js</span>
          </p>
          <p className="text-xs text-foreground/40 text-white">
            Escopo: <code className="bg-white/5 px-2 py-0.5 rounded text-primary text-white">dashboard</code>
          </p>
        </div>
      </div>
    </div>
  )
}
