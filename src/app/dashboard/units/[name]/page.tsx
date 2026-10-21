"use client"

import React, { useCallback, useEffect, useState } from 'react'
import { 
  ArrowLeft, 
  ShieldAlert, 
  Zap,
  Monitor,
  Signal,
  RefreshCcw,
  Activity,
  Building2,
  Search
} from 'lucide-react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { CommandCenter } from '@/components/dashboard/CommandCenter'
import { MachineTable } from '@/components/dashboard/MachineTable'


type UnitData = {
  unitStats: any[]
  topSoftware: any[]
  fleetSummary: {
    totalMachines: number
    totalAlerts: number
    averageRisk: number
  }
}

export default function UnitDetailPage() {
  const params = useParams()
  const unitName = decodeURIComponent(params.name as string)
  
  const [data, setData] = useState<UnitData | null>(null)
  const [loading, setLoading] = useState(true)
  const [isCommandCenterOpen, setIsCommandCenterOpen] = useState(false)
  const [machineSearch, setMachineSearch] = useState("")

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const response = await fetch(`/api/intelligence/stats?unit=${encodeURIComponent(unitName)}`)
      const result = await response.json()
      if (response.ok) setData(result)
    } catch (error) {
      console.error('Unit detail fetch error:', error)
    } finally {
      setLoading(false)
    }
  }, [unitName])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  if (loading || !data) {
    return (
      <div className="py-20 flex flex-col items-center justify-center gap-4">
        <div className="animate-spin h-10 w-10 border-t-2 border-primary rounded-full" />
        <p className="text-foreground/40 text-sm font-medium">Sincronizando Centro de Comando: {unitName}...</p>
      </div>
    )
  }

  const unit = data.unitStats[0] || { name: unitName, devices: [], riskScore: 0 }

  return (
    <div className="space-y-8 pb-32">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 px-4">
        <div className="space-y-1">
          <Link 
            href="/dashboard/intelligence" 
            className="flex items-center gap-2 text-xs text-foreground/40 hover:text-primary transition-colors mb-2 group"
          >
            <ArrowLeft className="h-3 w-3 group-hover:-translate-x-1 transition-transform" />
            Voltar para Inteligência Geral
          </Link>
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-primary/10 flex items-center justify-center border border-primary/20">
              <Building2 className="h-6 w-6 text-primary" />
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-foreground uppercase tracking-widest">
              Unidade: <span className="text-primary">{unitName}</span>
            </h2>

            {/* BADGE DE UNIDADE CONFIÁVEL (Padrão sugerido na imagem) */}
            {unit.auto_allow_compliance && (
              <div className="flex items-center gap-2 px-6 py-2 rounded-full bg-emerald-500/10 border border-emerald-500/30 shadow-[0_0_15px_rgba(16,185,129,0.1)] ml-4">
                <div className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.5)]" />
                <span className="text-[10px] font-black text-emerald-500 uppercase tracking-[0.2em] whitespace-nowrap">
                  Unidade Confiável
                </span>
                <Signal className="h-3 w-3 text-emerald-500/50" />
              </div>
            )}
          </div>
          <p className="text-sm text-foreground/40 italic">Monitoramento tático de ativos e performance de rede local.</p>
        </div>

        <div className="flex items-center gap-3">
            <button 
              onClick={() => setIsCommandCenterOpen(true)} 
              className="flex items-center gap-2 px-6 py-2 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 text-xs font-bold hover:bg-emerald-500 hover:text-white transition-all shadow-lg"
            >
              <ShieldAlert className="h-4 w-4" />
              <span>Acoes da Unidade</span>
            </button>

           <div className={`px-4 py-2 rounded-xl border flex items-center gap-2 text-xs font-bold ${
             unit.riskScore > 50 ? 'bg-rose-500/10 border-rose-500/20 text-rose-500' : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500'
           }`}>
             <ShieldAlert className="h-4 w-4" />
             Risco Unitário: {unit.riskScore}%
           </div>
           <button onClick={fetchData} className="p-2.5 rounded-xl bg-foreground/[0.05] border border-border/50 hover:bg-foreground/[0.1] transition-all">
             <RefreshCcw className="h-4 w-4" />
           </button>
        </div>

        <CommandCenter 
          isOpen={isCommandCenterOpen} 
          onClose={() => setIsCommandCenterOpen(false)} 
          currentUnit={unitName}
        />
      </div>

      {/* 1. Managed Devices List (Migrated SOC Agents functionality) */}
      <div className="glass-card p-8 rounded-[3rem] border border-border/50 mb-8 overflow-hidden">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-8">
           <h3 className="text-xl font-bold flex items-center gap-3 text-foreground">
             <Monitor className="h-6 w-6 text-foreground/40" /> Agentes Gerenciados
           </h3>
           <div className="relative group w-full sm:w-72">
             <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-foreground/40 group-focus-within:text-primary transition-colors" />
             <input 
               type="text" 
               placeholder="Pesquisar agentes..." 
               value={machineSearch}
               onChange={(e) => setMachineSearch(e.target.value)}
               className="w-full pl-10 pr-4 py-2.5 bg-foreground/[0.03] border border-foreground/10 rounded-2xl text-sm outline-none focus:border-primary/50 focus:bg-foreground/[0.05] transition-all"
             />
           </div>
        </div>
        <div className="p-1 -mx-8 -mb-8 bg-foreground/[0.01] border-t border-border/30">
          <MachineTable unitFilter={unitName} search={machineSearch} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Unit Stats & Distribution */}
        {unit && (
          <div className="glass-card p-8 rounded-[3rem] border border-border/50 space-y-8">
            <h3 className="text-xl font-bold mb-8 flex items-center gap-3 text-foreground">
              <Building2 className="h-6 w-6 text-foreground/40" /> Distribuição da Unidade
            </h3>
            
            <div className="space-y-6">
              {unit.unitStats?.map((item: any, i: number) => (
                <div key={i} className="space-y-2">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-foreground/40 font-bold uppercase tracking-wider">{item.name}</span>
                    <span className="font-black text-foreground">{item.value}%</span>
                  </div>
                  <div className="h-1.5 bg-foreground/5 rounded-full overflow-hidden border border-foreground/5">
                    <div 
                      className="h-full bg-primary" 
                      style={{ width: `${item.value}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Top Software Distribution */}
        {unit && (
          <div className="glass-card p-8 rounded-[3rem] border border-border/50">
            <h3 className="text-xl font-bold mb-8 flex items-center gap-3 text-foreground">
              <ShieldAlert className="h-6 w-6 text-foreground/40" /> Alertas de Software
            </h3>
            <div className="space-y-4">
              {unit.topSoftware?.map((item: any, i: number) => (
                <div key={i} className="flex items-center justify-between p-4 rounded-2xl bg-foreground/[0.02] border border-border/50">
                  <span className="text-sm font-medium text-foreground/80">{item.name}</span>
                  <span className="px-3 py-1 rounded-full bg-rose-500/10 text-rose-500 text-[10px] font-bold">
                    {item.count} máquinas
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Network Health Analysis */}
      <div className="mt-8">
        <h3 className="text-xl font-bold mb-8 px-4 flex items-center gap-3 text-foreground">
          <Zap className="h-6 w-6 text-foreground/40" /> Performance da Rede por Agente
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 px-2">
          {unit?.devices.map((device: any, i: number) => {
            const perf = device.inventory_data?.network_performance || { status: 'Unknown', gateway_ms: 0, server_ms: 0 }
            return (
              <div key={i} className="glass-card p-5 rounded-3xl border border-border/50 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className={`h-2 w-2 rounded-full animate-pulse ${
                      perf.status === 'Excellent' ? 'bg-emerald-500' :
                      perf.status === 'Good' ? 'bg-primary' :
                      perf.status === 'Unstable' ? 'bg-amber-500' : 'bg-rose-500'
                    }`} />
                    <span className="text-[10px] font-black uppercase text-foreground/40">{device.hostname}</span>
                  </div>
                  <Activity className="h-3 w-3 text-foreground/20" />
                </div>
                
                <div className="space-y-2">
                   <div className="flex items-center justify-between">
                     <p className="text-[9px] text-foreground/20 uppercase font-black">Gateway Local</p>
                     <p className="font-mono text-xs font-bold">{perf.gateway_ms}ms</p>
                   </div>
                   <div className="flex items-center justify-between">
                     <p className="text-[9px] text-foreground/20 uppercase font-black">Link VEXT</p>
                     <p className="font-mono text-xs font-bold">{perf.server_ms}ms</p>
                   </div>
                </div>

                <div className={`px-3 py-1.5 rounded-lg text-[9px] font-black uppercase text-center border ${
                  perf.status === 'Excellent' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500' :
                  perf.status === 'Good' ? 'bg-primary/10 border-primary/20 text-primary' :
                  perf.status === 'Unstable' ? 'bg-amber-500/10 border-amber-500/20 text-amber-500' : 'bg-rose-500/10 border-rose-500/20 text-rose-500'
                }`}>
                  Conexão: {perf.status}
                </div>
              </div>
            )
          })}
          {(!unit?.devices || unit.devices.length === 0) && (
            <div className="lg:col-span-4 py-10 text-center glass-card border-dashed border-border/50 text-foreground/20 italic">
              Aguardando sinal dos agentes desta unidade...
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
