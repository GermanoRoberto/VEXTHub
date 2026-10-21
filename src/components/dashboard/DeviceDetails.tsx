"use client"

import React, { useState, useMemo } from 'react'
import { motion } from 'framer-motion'
import { 
  X, 
  Monitor, 
  Cpu, 
  Database, 
  Shield, 
  Box, 
  Calendar, 
  Search,
  CheckCircle2,
  Clock,
  HardDrive,
  Trash2,
  Loader2,
  Zap,
  RefreshCcw,
  UploadCloud,
  AlertCircle,
  ChevronRight,
  AlertTriangle,
  Network,
  Activity,
  ShieldAlert,
  Flame
} from 'lucide-react'
import { analyzeTelemetryInventory, type TelemetryFinding } from '@/utils/security/telemetry-detection'

export interface Machine {
  id: string
  hostname: string
  serial_number: string
  unit: string
  os_name: string
  cpu_info: string
  ram_total: string
  inventory_data: {
    software?: SoftwareItem[]
    system_details?: {
      active_user: string
      local_ip: string
      disk_total_gb: number
      disk_free_gb: number
      domain: string
    }
    processes?: any[]
    services?: any[]
    startup_entries?: any[]
    network_connections?: {
      listening_tcp_ports?: any[]
      established_external_tcp?: any[]
      [key: string]: any
    }
    security_analysis?: {
      score?: number
      risk_level?: string
      findings?: any[]
      [key: string]: any
    }
    [key: string]: any
  }
  last_pulse: string
  agent_version?: string
  last_screenshot?: string
  ocr_text?: string
}

interface SoftwareItem {
  name: string
  version: string
  install_date: string
}

interface DeviceDetailsProps {
  machine: Machine
  onClose: () => void
}

const agentActions = [
  {
    id: 'REFRESH_INVENTORY',
    label: 'Atualizar inventario',
    description: 'Solicita nova coleta de hardware, software e detalhes do sistema no proximo pulso do agente.',
    icon: RefreshCcw,
  },
  {
    id: 'RUN_COMPLIANCE_SCAN',
    label: 'Revalidar compliance',
    description: 'Reprocessa politicas e inconformidades conhecidas para este endpoint.',
    icon: Shield,
  },
  {
    id: 'UPDATE_AGENT',
    label: 'Sincronizar agente',
    description: 'Marca o endpoint para buscar atualizacao assinada do agente quando disponivel.',
    icon: UploadCloud,
  },
]

export function DeviceDetails({ machine, onClose }: DeviceDetailsProps) {
  const [searchTerm, setSearchTerm] = useState('')
  const [activeTab, setActiveTab] = useState<'hardware' | 'software' | 'vrecon' | 'history' | 'commands'>('hardware')
  const [isDeleting, setIsDeleting] = useState(false)
  const [history, setHistory] = useState<any[]>([])
  const [isLoadingHistory, setIsLoadingHistory] = useState(false)
  const [sendingCommand, setSendingCommand] = useState<string | null>(null)
  const [commandStatus, setCommandStatus] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  const fetchHistory = async () => {
    setIsLoadingHistory(true)
    try {
      const response = await fetch(`/api/devices/${machine.id}/history`)
      const data = await response.json()
      if (data.history) setHistory(data.history)
    } catch (err) {
      console.error('Error fetching history:', err)
    } finally {
      setIsLoadingHistory(false)
    }
  }

  const handleDelete = async () => {
    if (!confirm(`Tem certeza que deseja excluir o dispositivo "${machine.hostname}"? Esta ação não pode ser desfeita.`)) {
      return
    }

    setIsDeleting(true)
    try {
      const response = await fetch(`/api/devices/${machine.id}`, {
        method: 'DELETE',
      })
      const data = await response.json()

      if (!response.ok) {
        alert(`Erro ao excluir: ${data.error || 'Erro desconhecido'}`)
      } else {
        alert('Dispositivo removido com sucesso.')
        onClose()
      }
    } catch (err) {
      console.error('Delete error:', err)
      alert('Erro de rede ao tentar excluir o dispositivo.')
    } finally {
      setIsDeleting(false)
    }
  }

  const sendAgentCommand = async (commandType: string, label: string) => {
    setSendingCommand(commandType)
    setCommandStatus(null)

    try {
      const response = await fetch('/api/agent/commands/enqueue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          machine_id: machine.id,
          hostname: machine.hostname,
          command_type: commandType,
          target: machine.unit || null,
        }),
      })
      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Falha ao enfileirar acao.')
      }

      setCommandStatus({
        type: 'success',
        message: data.message || `${label} enfileirado para ${machine.hostname}. O agente recebera no proximo pulso.`,
      })
    } catch (err: any) {
      setCommandStatus({
        type: 'error',
        message: err.message || 'Falha ao acionar o agente.',
      })
    } finally {
      setSendingCommand(null)
    }
  }

  const softwareData = machine.inventory_data?.software
  const software = Array.isArray(softwareData) ? softwareData : []
  const filteredSoftware = software.filter((app: SoftwareItem) => 
    app.name?.toLowerCase().includes(searchTerm.toLowerCase())
  )

  const vreconAnalysis = useMemo(() => {
    if (machine.inventory_data?.security_analysis?.findings?.length) {
      return machine.inventory_data.security_analysis
    }
    return analyzeTelemetryInventory(machine.inventory_data || {})
  }, [machine.inventory_data])

  const vreconScore = vreconAnalysis?.score ?? 0
  const vreconRiskLevel = vreconAnalysis?.risk_level ?? 'low'
  const vreconFindings: TelemetryFinding[] = useMemo(() => {
    return vreconAnalysis?.findings ?? []
  }, [vreconAnalysis])

  const cveFindings = useMemo(() => {
    return vreconFindings.filter((f) => f.category === 'vulnerability')
  }, [vreconFindings])

  const kevFindings = useMemo(() => {
    return vreconFindings.filter((f) => f.cisa_kev)
  }, [vreconFindings])

  const attackPathFindings = useMemo(() => {
    return vreconFindings.filter((f) => f.category === 'toxic_combination')
  }, [vreconFindings])

  const listeningPorts = useMemo(() => {
    return Array.isArray(machine.inventory_data?.network_connections?.listening_tcp_ports)
      ? machine.inventory_data.network_connections.listening_tcp_ports
      : []
  }, [machine.inventory_data])

  const externalConnections = useMemo(() => {
    return Array.isArray(machine.inventory_data?.network_connections?.established_external_tcp)
      ? machine.inventory_data.network_connections.established_external_tcp
      : []
  }, [machine.inventory_data])

  const totalProcesses = useMemo(() => {
    return Array.isArray(machine?.inventory_data?.processes)
      ? machine.inventory_data.processes.length
      : 0
  }, [machine?.inventory_data])

  if (!machine) return null

  return (
    <motion.div
      initial={{ x: '100%' }}
      animate={{ x: 0 }}
      exit={{ x: '100%' }}
      transition={{ type: 'spring', damping: 25, stiffness: 200 }}
      className="fixed inset-y-0 right-0 w-full lg:max-w-xl glass-card m-0 lg:m-4 rounded-none lg:rounded-[2.5rem] border-l lg:border border-foreground/10 z-50 flex flex-col overflow-hidden"
    >
      <div className="absolute inset-0 bg-gradient-to-br from-primary/[0.03] to-transparent pointer-events-none" />
      {/* Header */}
      <div className="p-6 border-b border-foreground/5 bg-foreground/[0.02] flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="h-12 w-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20">
            <Monitor className="h-6 w-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold tracking-tight">{machine.hostname}</h2>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-[10px] text-foreground/40 font-mono uppercase tracking-widest">{machine.id}</span>
              <span className="h-1 w-1 rounded-full bg-foreground/10" />
              <div className="flex items-center gap-1">
                <Shield className="h-2.5 w-2.5 text-primary/40" />
                <span className="text-[10px] font-black text-primary/60 tracking-tight">v{machine.agent_version || '3.3.0'}</span>
              </div>
            </div>
          </div>
        </div>
        <button 
          onClick={onClose}
          className="p-2 hover:bg-foreground/5 rounded-xl transition-colors text-foreground/40 hover:text-foreground"
        >
          <X className="h-5 w-5" />
        </button>
      </div>

      {/* Tabs */}
      <div className="flex px-6 pt-6 gap-4 lg:gap-6 overflow-x-auto no-scrollbar whitespace-nowrap scroll-smooth">
        <button 
          onClick={() => setActiveTab('hardware')}
          className={`pb-3 text-sm font-semibold transition-all relative ${activeTab === 'hardware' ? 'text-primary' : 'text-foreground/40 hover:text-foreground/60'}`}
        >
          Hardware & Sistema
          {activeTab === 'hardware' && <motion.div layoutId="activeTab" className="absolute bottom-0 left-0 right-0 h-0.5 bg-primary" />}
        </button>
        <button 
          onClick={() => setActiveTab('software')}
          className={`pb-3 text-sm font-semibold transition-all relative ${activeTab === 'software' ? 'text-primary' : 'text-foreground/40 hover:text-foreground/60'}`}
        >
          Inventário de Software
          {activeTab === 'software' && <motion.div layoutId="activeTab" className="absolute bottom-0 left-0 right-0 h-0.5 bg-primary" />}
        </button>
        <button 
          onClick={() => setActiveTab('vrecon')}
          className={`pb-3 text-sm font-semibold transition-all relative flex items-center gap-1.5 ${activeTab === 'vrecon' ? 'text-amber-500' : 'text-foreground/40 hover:text-foreground/60'}`}
        >
          <span>Reconhecimento (V-Recon)</span>
          {vreconFindings.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-500 border border-amber-500/30">
              {vreconFindings.length}
            </span>
          )}
          {activeTab === 'vrecon' && <motion.div layoutId="activeTab" className="absolute bottom-0 left-0 right-0 h-0.5 bg-amber-500" />}
        </button>
        <button 
          onClick={() => { setActiveTab('history'); fetchHistory(); }}
          className={`pb-3 text-sm font-semibold transition-all relative ${activeTab === 'history' ? 'text-indigo-400' : 'text-foreground/40 hover:text-foreground/60'}`}
        >
          Histórico
          {activeTab === 'history' && <motion.div layoutId="activeTab" className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-400" />}
        </button>
        <button 
          onClick={() => setActiveTab('commands')}
          className={`pb-3 text-sm font-semibold transition-all relative ${activeTab === 'commands' ? 'text-primary' : 'text-foreground/40 hover:text-foreground/60'}`}
        >
          Arsenal Tático
          {activeTab === 'commands' && <motion.div layoutId="activeTab" className="absolute bottom-0 left-0 right-0 h-0.5 bg-primary" />}
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-8">
        {activeTab === 'hardware' ? (
          <div className="grid grid-cols-1 gap-4">
            <div className="glass-card p-4 rounded-2xl border border-foreground/5 space-y-4">
              <h3 className="text-xs font-bold text-foreground/40 uppercase tracking-widest flex items-center gap-2">
                <Shield className="h-3 w-3" /> Sistema Operacional
              </h3>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">{machine.os_name || 'Windows 10/11'}</span>
                <CheckCircle2 className="h-4 w-4 text-emerald-500" />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="glass-card p-4 rounded-2xl border border-foreground/5 space-y-4">
                <h3 className="text-xs font-bold text-foreground/40 uppercase tracking-widest flex items-center gap-2">
                  <Cpu className="h-3 w-3" /> Processador
                </h3>
                <p className="text-sm font-medium leading-tight">{machine.cpu_info || 'N/A'}</p>
              </div>
              <div className="glass-card p-4 rounded-2xl border border-foreground/5 space-y-4">
                <h3 className="text-xs font-bold text-foreground/40 uppercase tracking-widest flex items-center gap-2">
                  <Database className="h-3 w-3" /> Memória RAM
                </h3>
                <p className="text-sm font-medium">{machine.ram_total || 'N/A'}</p>
              </div>
            </div>

            <div className="glass-card p-4 rounded-2xl border border-foreground/5 space-y-4">
              <h3 className="text-xs font-bold text-foreground/40 uppercase tracking-widest flex items-center gap-2">
                <HardDrive className="h-3 w-3" /> Identificação Tática
              </h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-foreground/40">Unidade Operacional</span>
                  <span className="font-semibold text-indigo-400">{machine.unit || 'Padrão'}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-foreground/40">Usuário Ativo</span>
                  <span className="font-semibold text-foreground/80">{machine.inventory_data?.system_details?.active_user || 'N/A'}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-foreground/40">Serial Number</span>
                  <span className="font-mono">{machine.serial_number || 'UNKNOWN'}</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-foreground/40">Último Reporte</span>
                  <div className="flex items-center gap-1.5 text-foreground/60">
                    <Clock className="h-3 w-3" />
                    {new Date(machine.last_pulse).toLocaleString('pt-BR')}
                  </div>
                </div>
              </div>
            </div>

            {machine.inventory_data?.system_details && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="glass-card p-4 rounded-2xl border border-foreground/5 space-y-4">
                  <h3 className="text-xs font-bold text-foreground/40 uppercase tracking-widest flex items-center gap-2">
                    <CheckCircle2 className="h-3 w-3" /> Rede Local
                  </h3>
                  <div className="space-y-1">
                    <p className="text-sm font-medium">{machine.inventory_data.system_details.local_ip || 'N/A'}</p>
                    <p className="text-[10px] text-foreground/40 uppercase tracking-wider">{machine.inventory_data.system_details.domain || 'Workgroup'}</p>
                  </div>
                </div>
                <div className="glass-card p-4 rounded-2xl border border-foreground/5 space-y-4">
                  <h3 className="text-xs font-bold text-foreground/40 uppercase tracking-widest flex items-center gap-2">
                    <Database className="h-3 w-3" /> Armazenamento (C:)
                  </h3>
                  <div className="space-y-1">
                    <p className="text-sm font-medium">{machine.inventory_data.system_details.disk_free_gb} GB Livres</p>
                    <p className="text-[10px] text-foreground/40 uppercase tracking-wider">de {machine.inventory_data.system_details.disk_total_gb} GB Totais</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        ) : activeTab === 'software' ? (
          <div className="space-y-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-foreground/40" />
              <input 
                type="text" 
                placeholder="Pesquisar softwares..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-foreground/5 border border-foreground/10 rounded-xl text-sm outline-none focus:border-primary/50 focus:bg-foreground/[0.08] transition-all"
              />
            </div>

            <div className="space-y-2">
              {filteredSoftware.length > 0 ? (
                filteredSoftware.map((app: SoftwareItem, idx: number) => (
                  <div key={idx} className="group p-3 rounded-xl border border-foreground/[0.03] bg-foreground/[0.01] hover:bg-foreground/[0.04] hover:border-foreground/10 transition-all flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="h-8 w-8 rounded-lg bg-foreground/5 flex items-center justify-center border border-foreground/10 group-hover:bg-primary/10 group-hover:border-primary/20 transition-colors shrink-0">
                        <Box className="h-4 w-4 text-foreground/30 group-hover:text-primary transition-colors" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm font-semibold truncate group-hover:text-primary transition-colors">{app.name}</p>
                        <p className="text-[10px] text-foreground/40 font-mono">v{app.version || '?.?'}</p>
                      </div>
                    </div>
                    {app.install_date && (
                      <div className="flex items-center gap-1.5 text-[10px] text-foreground/30 font-medium shrink-0 bg-foreground/5 px-2 py-1 rounded-md">
                        <Calendar className="h-3 w-3" />
                        {app.install_date}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="py-20 text-center text-foreground/20 italic text-sm">
                  Nenhum software correspondente encontrado...
                </div>
              )}
            </div>
          </div>
        ) : activeTab === 'vrecon' ? (
          <div className="space-y-6">
            {/* Header / Posture Score Card */}
            <div className="glass-card p-6 rounded-2xl border border-foreground/5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h3 className="text-xs font-bold text-foreground/40 uppercase tracking-widest flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-amber-500" /> Postura de Segurança & Exposição (V-Recon)
                  </h3>
                  <p className="text-xs text-foreground/60 mt-1">
                    Análise heurística de telemetria, superfície de ataque, conexões e conformidade MITRE ATT&CK.
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <div className={`px-3 py-1.5 rounded-xl border text-xs font-bold uppercase tracking-wider flex items-center gap-2 ${
                    vreconRiskLevel === 'critical'
                      ? 'bg-rose-500/10 border-rose-500/20 text-rose-500'
                      : vreconRiskLevel === 'high'
                      ? 'bg-amber-500/10 border-amber-500/20 text-amber-500'
                      : vreconRiskLevel === 'medium'
                      ? 'bg-yellow-500/10 border-yellow-500/20 text-yellow-500'
                      : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500'
                  }`}>
                    <span className={`h-2 w-2 rounded-full ${
                      vreconRiskLevel === 'critical'
                        ? 'bg-rose-500 animate-pulse'
                        : vreconRiskLevel === 'high'
                        ? 'bg-amber-500'
                        : vreconRiskLevel === 'medium'
                        ? 'bg-yellow-500'
                        : 'bg-emerald-500'
                    }`} />
                    Risco: {vreconRiskLevel.toUpperCase()}
                  </div>
                  <div className="text-right">
                    <span className="text-2xl font-black tracking-tight">{vreconScore}</span>
                    <span className="text-xs text-foreground/40 font-mono">/100</span>
                  </div>
                </div>
              </div>

              {/* Progress bar */}
              <div className="w-full bg-foreground/5 h-2 rounded-full overflow-hidden">
                <div 
                  className={`h-full transition-all duration-500 ${
                    vreconRiskLevel === 'critical' ? 'bg-rose-500' :
                    vreconRiskLevel === 'high' ? 'bg-amber-500' :
                    vreconRiskLevel === 'medium' ? 'bg-yellow-500' : 'bg-emerald-500'
                  }`}
                  style={{ width: `${Math.min(100, Math.max(5, vreconScore))}%` }}
                />
              </div>

              {/* Quick stats grid */}
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-2">
                <div className="p-3 rounded-xl bg-foreground/[0.02] border border-foreground/5">
                  <div className="text-[10px] font-bold text-foreground/40 uppercase tracking-wider">Total de Achados</div>
                  <div className="text-lg font-bold mt-1 text-foreground/90">{vreconFindings.length}</div>
                </div>
                <div className="p-3 rounded-xl bg-foreground/[0.02] border border-rose-500/10">
                  <div className="text-[10px] font-bold text-rose-400 uppercase tracking-wider">Cadeias de Ataque</div>
                  <div className="text-lg font-bold mt-1 text-rose-500">{attackPathFindings.length}</div>
                </div>
                <div className="p-3 rounded-xl bg-foreground/[0.02] border border-amber-500/10">
                  <div className="text-[10px] font-bold text-amber-400 uppercase tracking-wider">CVEs & CISA KEV</div>
                  <div className="text-lg font-bold mt-1 text-foreground/90">
                    {cveFindings.length} <span className="text-xs text-rose-400 font-mono">({kevFindings.length} KEV)</span>
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-foreground/[0.02] border border-foreground/5">
                  <div className="text-[10px] font-bold text-foreground/40 uppercase tracking-wider">Portas em Escuta</div>
                  <div className="text-lg font-bold mt-1 text-foreground/90">{listeningPorts.length}</div>
                </div>
                <div className="p-3 rounded-xl bg-foreground/[0.02] border border-foreground/5">
                  <div className="text-[10px] font-bold text-foreground/40 uppercase tracking-wider">Conexões Ativas</div>
                  <div className="text-lg font-bold mt-1 text-foreground/90">{externalConnections.length}</div>
                </div>
                <div className="p-3 rounded-xl bg-foreground/[0.02] border border-foreground/5">
                  <div className="text-[10px] font-bold text-foreground/40 uppercase tracking-wider">Processos Totais</div>
                  <div className="text-lg font-bold mt-1 text-foreground/90">{totalProcesses}</div>
                </div>
              </div>
            </div>

            {/* Findings List */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-foreground/40 uppercase tracking-widest flex items-center gap-2">
                  <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
                  Vulnerabilidades & Heurísticas Detectadas ({vreconFindings.length})
                </h4>
              </div>

              {vreconFindings.length > 0 ? (
                vreconFindings.map((finding: TelemetryFinding, idx: number) => {
                  if (finding.category === 'toxic_combination') {
                    return (
                      <div
                        key={idx}
                        className="glass-card p-5 rounded-2xl border border-rose-500/30 bg-rose-500/[0.03] space-y-4 hover:border-rose-500/50 transition-all shadow-lg shadow-rose-950/20"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="space-y-1.5">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider bg-rose-600 text-white flex items-center gap-1 shadow-sm">
                                <AlertTriangle className="h-3 w-3" /> ATTACK PATH CORRELACIONADO
                              </span>
                              {finding.attack_path?.stage && (
                                <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold bg-rose-500/15 text-rose-300 border border-rose-500/30">
                                  {finding.attack_path.stage}
                                </span>
                              )}
                              {finding.mitre && (
                                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                                  MITRE {finding.mitre}
                                </span>
                              )}
                            </div>
                            <h5 className="text-base font-bold text-rose-100">{finding.title}</h5>
                          </div>
                          <div className="text-right shrink-0">
                            <div className="px-3 py-1 rounded-xl bg-rose-500/20 border border-rose-500/30 text-rose-400 text-xs font-mono font-black">
                              SCORE {finding.score}/100
                            </div>
                          </div>
                        </div>

                        {finding.attack_path?.kill_chain && (
                          <div className="flex items-center gap-2 p-2.5 rounded-xl bg-black/60 border border-rose-500/20 text-xs font-mono">
                            <Zap className="h-3.5 w-3.5 text-rose-400 shrink-0" />
                            <span className="font-bold text-rose-300">Kill-Chain:</span>
                            <span className="text-foreground/90">{finding.attack_path.kill_chain}</span>
                          </div>
                        )}

                        {finding.attack_path?.correlated_signals && finding.attack_path.correlated_signals.length > 0 && (
                          <div className="p-3 rounded-xl bg-black/40 border border-foreground/5 space-y-2">
                            <div className="text-[10px] font-bold text-foreground/40 uppercase tracking-wider">
                              Sinais Multi-Vetoriais Correlacionados ({finding.attack_path.correlated_signals.length})
                            </div>
                            <div className="space-y-1.5">
                              {finding.attack_path.correlated_signals.map((sig, sIdx) => (
                                <div key={sIdx} className="flex items-start gap-2 text-xs font-mono text-foreground/80">
                                  <span className="text-rose-400 select-none font-bold shrink-0">►</span>
                                  <span>{sig}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {finding.evidence && !finding.attack_path?.correlated_signals && (
                          <div className="p-2.5 rounded-lg bg-black/40 border border-foreground/5">
                            <p className="text-[11px] font-mono text-foreground/70 break-all">
                              <span className="text-foreground/30 select-none mr-2">$ evidência:</span>
                              {finding.evidence}
                            </p>
                          </div>
                        )}

                        {finding.recommended_action && (
                          <div className="flex items-start gap-2 text-xs text-rose-200/90 bg-rose-500/10 p-3 rounded-xl border border-rose-500/20">
                            <ShieldAlert className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
                            <span className="leading-relaxed"><strong className="text-rose-100">Mitigação Imediata:</strong> {finding.recommended_action}</span>
                          </div>
                        )}
                      </div>
                    )
                  }

                  return (
                    <div key={idx} className="glass-card p-4 rounded-xl border border-foreground/5 space-y-3 hover:border-foreground/10 transition-all">
                      <div className="flex items-start justify-between gap-3">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                              finding.severity === 'critical'
                                ? 'bg-rose-500/10 text-rose-500 border border-rose-500/20'
                                : finding.severity === 'high'
                                ? 'bg-amber-500/10 text-amber-500 border border-amber-500/20'
                                : finding.severity === 'medium'
                                ? 'bg-yellow-500/10 text-yellow-500 border border-yellow-500/20'
                                : 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20'
                            }`}>
                              {finding.severity}
                            </span>
                            {finding.cisa_kev && (
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-500/20 text-rose-400 border border-rose-500/30 flex items-center gap-1 animate-pulse">
                                <Flame className="h-3 w-3 text-rose-400" />
                                CISA KEV
                              </span>
                            )}
                            {finding.cvss !== undefined && (
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                                CVSS {finding.cvss.toFixed(1)}
                              </span>
                            )}
                            {finding.mitre && (
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                                MITRE {finding.mitre}
                              </span>
                            )}
                            <span className="text-[10px] font-mono text-foreground/40 uppercase">
                              {finding.category}
                            </span>
                          </div>
                          <p className="text-sm font-semibold text-foreground/90">{finding.title}</p>
                        </div>
                        <div className="text-right shrink-0">
                          <span className="text-xs font-mono font-bold text-foreground/60">Score: {finding.score}</span>
                        </div>
                      </div>

                      {finding.evidence && (
                        <div className="p-2.5 rounded-lg bg-black/40 border border-foreground/5">
                          <p className="text-[11px] font-mono text-foreground/70 break-all">
                            <span className="text-foreground/30 select-none mr-2">$ evidência:</span>
                            {finding.evidence}
                          </p>
                        </div>
                      )}

                      {finding.fixed_version && (
                        <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-500/10 p-2.5 rounded-lg border border-emerald-500/20">
                          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                          <span><strong className="text-emerald-300">Patch Recomendado:</strong> Atualizar {finding.software_name || 'aplicação'} para <strong className="underline font-bold text-emerald-200">v{finding.fixed_version}</strong> ou superior</span>
                        </div>
                      )}

                      {finding.recommended_action && (
                        <div className="flex items-start gap-2 text-xs text-foreground/60 bg-foreground/[0.02] p-2.5 rounded-lg border border-foreground/5">
                          <Shield className="h-3.5 w-3.5 text-primary shrink-0 mt-0.5" />
                          <span className="leading-relaxed"><strong className="text-foreground/80">Recomendação:</strong> {finding.recommended_action}</span>
                        </div>
                      )}
                    </div>
                  )
                })
              ) : (
                <div className="glass-card p-8 rounded-xl border border-foreground/5 text-center space-y-2">
                  <CheckCircle2 className="h-8 w-8 text-emerald-500 mx-auto opacity-80" />
                  <p className="text-sm font-semibold text-foreground/80">Nenhuma anomalia crítica detectada</p>
                  <p className="text-xs text-foreground/40 max-w-md mx-auto">
                    A análise de inventário e telemetria deste endpoint não identificou ferramentas de acesso remoto não autorizadas, portas críticas expostas ou indicadores de persistência.
                  </p>
                </div>
              )}
            </div>

            {/* Network Exposure Section */}
            <div className="space-y-4">
              <h4 className="text-xs font-bold text-foreground/40 uppercase tracking-widest flex items-center gap-2">
                <Network className="h-3.5 w-3.5 text-primary" />
                Superfície de Exposição de Rede ({listeningPorts.length} portas monitoradas)
              </h4>

              {listeningPorts.length > 0 ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {listeningPorts.map((port: any, idx: number) => {
                    const isSensitive = [3389, 445, 5900, 22, 23, 21, 139, 8080, 8443].includes(port.local_port)
                    return (
                      <div key={idx} className={`p-3 rounded-xl border transition-all ${
                        isSensitive 
                          ? 'bg-amber-500/5 border-amber-500/20' 
                          : 'bg-foreground/[0.01] border-foreground/5'
                      }`}>
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-mono font-bold text-foreground/90">
                            Porta {port.local_port}
                          </span>
                          <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${
                            isSensitive 
                              ? 'bg-amber-500/20 text-amber-500' 
                              : 'bg-foreground/5 text-foreground/40'
                          }`}>
                            {port.exposure || 'LISTEN'}
                          </span>
                        </div>
                        <p className="text-[10px] font-mono text-foreground/40 mt-1 truncate">
                          {port.protocol || 'TCP'} • {port.local_address || '0.0.0.0'}
                        </p>
                      </div>
                    )
                  })}
                </div>
              ) : (
                <div className="p-4 rounded-xl bg-foreground/[0.01] border border-foreground/5 text-xs text-foreground/40 text-center italic">
                  Nenhuma porta TCP em escuta reportada no inventário recente.
                </div>
              )}
            </div>

            {/* Active External Connections */}
            {externalConnections.length > 0 && (
              <div className="space-y-4">
                <h4 className="text-xs font-bold text-foreground/40 uppercase tracking-widest flex items-center gap-2">
                  <Activity className="h-3.5 w-3.5 text-indigo-400" />
                  Conexões Externas Estabelecidas ({externalConnections.length})
                </h4>
                <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                  {externalConnections.map((conn: any, idx: number) => (
                    <div key={idx} className="p-2.5 rounded-lg bg-foreground/[0.01] border border-foreground/5 flex items-center justify-between text-xs font-mono">
                      <span className="text-foreground/70 truncate">
                        {conn.local_address || 'local'}:{conn.local_port} &rarr; {conn.remote_address || 'remoto'}:{conn.remote_port}
                      </span>
                      <span className="text-[10px] text-foreground/40 font-bold uppercase shrink-0 ml-2">
                        {conn.state || 'ESTABLISHED'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : activeTab === 'history' ? (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-foreground/40 uppercase tracking-widest flex items-center gap-2">
                <Clock className="h-3 w-3" /> Histórico de Telemetria (Pulsos)
              </h3>
              <button 
                onClick={fetchHistory}
                className="text-[10px] text-primary hover:underline font-bold"
              >
                Atualizar
              </button>
            </div>

            <div className="space-y-3">
              {isLoadingHistory ? (
                <div className="py-12 flex justify-center">
                  <Loader2 className="h-6 w-6 animate-spin text-primary/40" />
                </div>
              ) : history.length > 0 ? (
                history.map((pulse: any, idx: number) => (
                  <div key={idx} className="glass-card p-4 rounded-xl border border-foreground/5 bg-foreground/[0.01] flex items-center justify-between">
                    <div className="space-y-1">
                      <p className="text-xs font-medium text-foreground/80">
                        {new Date(pulse.timestamp).toLocaleString('pt-BR')}
                      </p>
                      <p className="text-[10px] text-foreground/40 font-mono">
                        ID: {pulse.id}
                      </p>
                    </div>
                    <div className="text-right">
                      <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded-md ${
                        pulse.unit === 'Sem Unidade' || !pulse.unit 
                          ? 'bg-foreground/5 text-foreground/40' 
                          : 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20'
                      }`}>
                        {pulse.unit || '---'}
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="py-20 text-center text-foreground/20 italic text-sm">
                  Nenhum histórico de pulso encontrado para este dispositivo.
                </div>
              )}
            </div>
          </div>
        ) : activeTab === 'commands' ? (
          <div className="space-y-6">
            <h3 className="text-xs font-bold text-foreground/40 uppercase tracking-widest flex items-center gap-2">
              <Zap className="h-3 w-3" /> Acoes Seguras do Agente
            </h3>
            
            <div className="grid grid-cols-1 gap-3">
              {agentActions.map((cmd) => (
                <button
                  key={cmd.id}
                  onClick={() => sendAgentCommand(cmd.id, cmd.label)}
                  disabled={sendingCommand !== null}
                  className="w-full p-4 rounded-xl border border-foreground/10 bg-foreground/5 hover:bg-primary hover:text-white transition-all flex items-center justify-between group disabled:opacity-60"
                >
                  <div className="flex items-start gap-3 text-left">
                    <div className="p-2 rounded-lg bg-foreground/10 group-hover:bg-white/20">
                      <cmd.icon className="h-4 w-4" />
                    </div>
                    <span>
                      <span className="block text-sm font-bold">{cmd.label}</span>
                      <span className="block text-[10px] text-foreground/45 group-hover:text-white/70 mt-1 leading-relaxed">{cmd.description}</span>
                    </span>
                  </div>
                  {sendingCommand === cmd.id ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <ChevronRight className="h-4 w-4 opacity-0 group-hover:opacity-100 transition-all" />
                  )}
                </button>
              ))}
            </div>

            {commandStatus && (
              <div className={`p-4 rounded-xl border flex items-start gap-3 ${
                commandStatus.type === 'success'
                  ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500'
                  : 'bg-rose-500/10 border-rose-500/20 text-rose-500'
              }`}>
                {commandStatus.type === 'success' ? (
                  <CheckCircle2 className="h-4 w-4 mt-0.5" />
                ) : (
                  <AlertCircle className="h-4 w-4 mt-0.5" />
                )}
                <p className="text-xs font-semibold leading-relaxed">{commandStatus.message}</p>
              </div>
            )}

            <div className="p-4 rounded-xl bg-primary/10 border border-primary/20">
              <p className="text-[10px] text-primary font-bold uppercase tracking-widest leading-relaxed">
                A fila aceita apenas acoes defensivas permitidas: inventario, compliance e atualizacao do agente. O agente recebe a instrucao quando enviar o proximo pulso de telemetria.
              </p>
            </div>
          </div>
        ) : (
          <div className="py-20 text-center text-foreground/20 italic text-sm">
            Selecione uma aba para visualizar os detalhes...
          </div>
        )}
      </div>

      {/* Footer / Meta */}
      <div className="p-6 bg-foreground/[0.01] border-t border-foreground/5 flex items-center justify-between">
        <div className="flex items-center gap-4 text-[10px] text-foreground/20 font-bold uppercase tracking-[0.2em]">
          <span>VextHub Agent v{machine.agent_version || '4.0.0'}</span>
          <span className="h-1 w-1 rounded-full bg-foreground/10" />
          <span>Defensive Inventory Engine</span>
        </div>
        <button
          onClick={handleDelete}
          disabled={isDeleting}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-rose-500/10 text-rose-500 text-[10px] font-bold uppercase tracking-wider hover:bg-rose-500/20 transition-all border border-rose-500/10 disabled:opacity-50"
        >
          {isDeleting ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <Trash2 className="h-3 w-3" />
          )}
          {isDeleting ? 'Excluindo...' : 'Deletar Dispositivo'}
        </button>
      </div>
    </motion.div>
  )
}
