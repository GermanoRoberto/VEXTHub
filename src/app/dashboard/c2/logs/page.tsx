"use client"

import React, { useEffect, useState } from 'react'
import {
  History,
  Search,
  CheckCircle2,
  XCircle,
  Clock,
  ArrowLeft,
  Terminal,
  Building2,
  Cpu,
  RefreshCw,
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import Link from 'next/link'

type CommandLog = {
  id: string
  machine_id: string
  command_type: string
  target: string
  status: 'pending' | 'sent' | 'executing' | 'completed' | 'executed' | 'failed'
  result: string | null
  created_at: string
  machines?: {
    hostname: string
    unit: string
  }
}

export default function CommandLogsPage() {
  const [logs, setLogs] = useState<CommandLog[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedLog, setSelectedLog] = useState<CommandLog | null>(null)

  const fetchLogs = async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/agent/commands/logs')
      const data = await response.json()
      if (!response.ok) throw new Error(data.error)
      setLogs(data)
    } catch (error) {
      console.error('Fetch logs error:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchLogs()
    const interval = setInterval(fetchLogs, 15000)
    return () => clearInterval(interval)
  }, [])

  const filtered = logs.filter((log) =>
    log.machines?.hostname?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.machines?.unit?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.target?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.command_type?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.result?.toLowerCase().includes(searchTerm.toLowerCase())
  )

  const succeededCount = logs.filter((log) => ['completed', 'executed'].includes(log.status)).length
  const failedCount = logs.filter((log) => log.status === 'failed').length
  const pendingCount = logs.filter((log) => ['pending', 'sent', 'executing'].includes(log.status)).length

  const getStatusStyle = (status: CommandLog['status']) => {
    switch (status) {
      case 'completed':
      case 'executed':
        return 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20'
      case 'failed':
        return 'bg-rose-500/10 text-rose-500 border-rose-500/20'
      case 'pending':
        return 'bg-amber-500/10 text-amber-500 border-amber-500/20'
      case 'sent':
        return 'bg-blue-500/10 text-blue-500 border-blue-500/20'
      default:
        return 'bg-white/5 text-white/40 border-white/10'
    }
  }

  const getStatusLabel = (status: CommandLog['status']) => {
    return status === 'executed' ? 'completed' : status
  }

  const getResultPreview = (log: CommandLog) => {
    if (!log.result) return 'Aguardando retorno do agente.'
    return log.result.length > 88 ? `${log.result.slice(0, 88)}...` : log.result
  }

  return (
    <div className="space-y-8 pb-20">
      <div className="flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
        <div className="space-y-1">
          <Link
            href="/dashboard/intelligence"
            className="mb-2 flex items-center gap-2 text-xs text-white/40 transition-colors hover:text-primary group"
          >
            <ArrowLeft className="h-3 w-3 transition-transform group-hover:-translate-x-1" />
            Voltar para Inteligencia
          </Link>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-primary/20 bg-primary/10">
              <History className="h-6 w-6 text-primary" />
            </div>
            <h2 className="text-2xl font-bold tracking-tight">Historico de Acoes Seguras</h2>
          </div>
          <p className="text-sm italic text-white/40">
            Auditoria de acoes permitidas, resultados e revalidacoes defensivas.
          </p>
        </div>

        <button
          onClick={fetchLogs}
          className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-xs font-bold text-white transition-all hover:bg-white/10"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          Atualizar Agora
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {[
          { label: 'Total', value: logs.length, color: 'text-white' },
          { label: 'Sucesso', value: succeededCount, color: 'text-emerald-500' },
          { label: 'Falhas', value: failedCount, color: 'text-rose-500' },
          { label: 'Pendentes', value: pendingCount, color: 'text-amber-500' },
        ].map((stat) => (
          <div key={stat.label} className="glass-card rounded-2xl border border-white/5 p-4">
            <p className="text-[10px] font-black uppercase tracking-widest text-white/30">{stat.label}</p>
            <p className={`text-2xl font-black ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      <div className="relative flex-1">
        <Search className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-white/40" />
        <input
          type="text"
          placeholder="Filtrar por host, unidade, comando, alvo ou resultado..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full rounded-2xl border border-white/10 bg-white/5 py-4 pl-12 pr-6 text-lg text-white outline-none transition-all focus:border-primary/50 focus:bg-white/[0.08]"
        />
      </div>

      <div className="glass-card overflow-hidden rounded-3xl border border-white/5">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left">
            <thead>
              <tr className="border-b border-white/10 bg-white/5">
                <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Data/Hora</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Maquina / Unidade</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Operacao</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Alvo</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Status</th>
                <th className="p-4 text-[10px] font-black uppercase tracking-widest text-white/40">Resultado</th>
                <th className="p-4 text-right text-[10px] font-black uppercase tracking-widest text-white/40">Acao</th>
              </tr>
            </thead>
            <tbody>
              {loading && logs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-20 text-center italic text-white/20">Carregando historico...</td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-20 text-center italic text-white/20">Nenhuma operacao encontrada.</td>
                </tr>
              ) : (
                filtered.map((log) => (
                  <tr key={log.id} className="group border-b border-white/5 transition-colors hover:bg-white/[0.02]">
                    <td className="p-4">
                      <p className="text-xs text-white/60">{new Date(log.created_at).toLocaleDateString()}</p>
                      <p className="text-[10px] italic text-white/30">{new Date(log.created_at).toLocaleTimeString()}</p>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                        <Cpu className="h-3 w-3 text-primary/60" />
                        <p className="text-sm font-bold text-white">{log.machines?.hostname || 'N/A'}</p>
                      </div>
                      <div className="flex items-center gap-1">
                        <Building2 className="h-2.5 w-2.5 text-white/20" />
                        <p className="text-[10px] uppercase text-white/40">{log.machines?.unit || 'N/A'}</p>
                      </div>
                    </td>
                    <td className="p-4">
                      <span className="rounded-md border border-primary/20 bg-primary/10 px-2 py-1 text-[10px] font-black uppercase tracking-widest text-primary">
                        {log.command_type}
                      </span>
                    </td>
                    <td className="p-4">
                      <p className="max-w-[180px] truncate text-xs font-bold text-white">{log.target || '-'}</p>
                    </td>
                    <td className="p-4">
                      <span className={`flex w-fit items-center gap-1.5 rounded-full border px-2 py-1 text-[9px] font-black uppercase tracking-tighter ${getStatusStyle(log.status)}`}>
                        {['completed', 'executed'].includes(log.status) && <CheckCircle2 className="h-2.5 w-2.5" />}
                        {log.status === 'failed' && <XCircle className="h-2.5 w-2.5" />}
                        {['pending', 'sent', 'executing'].includes(log.status) && <Clock className="h-2.5 w-2.5 animate-pulse" />}
                        {getStatusLabel(log.status)}
                      </span>
                    </td>
                    <td className="max-w-[340px] p-4">
                      <p className={`truncate text-xs ${log.status === 'failed' ? 'text-rose-400' : 'text-white/55'}`}>
                        {getResultPreview(log)}
                      </p>
                    </td>
                    <td className="p-4 text-right">
                      <button
                        onClick={() => setSelectedLog(log)}
                        className="rounded-lg p-2 text-primary transition-all hover:bg-primary/20 md:opacity-0 md:group-hover:opacity-100"
                      >
                        <Terminal className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <AnimatePresence>
        {selectedLog && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-black/80 backdrop-blur-sm"
              onClick={() => setSelectedLog(null)}
            />
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="glass-card relative w-full max-w-2xl overflow-hidden rounded-3xl border border-white/10 shadow-2xl"
            >
              <div className="flex items-center justify-between border-b border-white/10 bg-white/[0.02] p-6">
                <div className="flex items-center gap-3">
                  <Terminal className="h-5 w-5 text-primary" />
                  <div>
                    <h3 className="text-sm font-bold text-white">Saida Tecnica do Agente</h3>
                    <p className="text-[10px] uppercase tracking-widest text-white/40">
                      {selectedLog.command_type} @ {selectedLog.machines?.hostname || 'N/A'}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedLog(null)}
                  className="rounded-full p-2 text-white/40 hover:bg-white/10"
                >
                  <XCircle className="h-5 w-5" />
                </button>
              </div>

              <div className="p-8">
                <div className="max-h-[400px] overflow-y-auto rounded-2xl border border-white/5 bg-black/40 p-6 font-mono text-xs text-primary/80">
                  {selectedLog.result ? (
                    <pre className="whitespace-pre-wrap">{selectedLog.result}</pre>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-10 opacity-30">
                      <Clock className="mb-4 h-10 w-10" />
                      <p>Aguardando resposta do agente tatico...</p>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex justify-end bg-white/[0.02] p-4">
                <button
                  onClick={() => setSelectedLog(null)}
                  className="rounded-xl bg-primary px-6 py-2 text-xs font-bold uppercase text-white"
                >
                  Fechar Terminal
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  )
}
