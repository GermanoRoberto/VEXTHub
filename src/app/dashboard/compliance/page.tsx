"use client"

import React, { useEffect, useState } from 'react'
import { 
  ShieldCheck, 
  Search, 
  CheckCircle2, 
  Clock, 
  ArrowLeft,
  AlertTriangle,
  Building2,
  Layers,
  ChevronDown,
  RefreshCw,
  LayoutGrid,
  FileSpreadsheet,
  FileText,
  Loader2
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import Link from 'next/link'
import {
  exportComplianceCsv,
  exportCompliancePdf,
  SoftwarePolicyExportItem,
  ComplianceAlertExportItem,
} from '@/utils/export/reports'

type UnitOverride = {
  unit_name: string
  status: 'allowed' | 'forbidden'
}

type SoftwarePolicy = {
  name: string
  status: 'allowed' | 'forbidden' | 'pending'
  overrides?: UnitOverride[]
  units?: string[]
}

interface RawComplianceAlert {
  id?: string | number
  hostname?: string
  unit?: string
  software_name?: string
  message?: string
  created_at?: string
  is_resolved?: boolean
}

export default function CompliancePage() {
  const [policies, setPolicies] = useState<SoftwarePolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [activeTab, setActiveTab] = useState<'all' | 'allowed' | 'forbidden' | 'pending'>('all')
  const [updating, setUpdating] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [availableUnits, setAvailableUnits] = useState<string[]>([])
  const [searchFocused, setSearchFocused] = useState(false)
  const [exportingCsv, setExportingCsv] = useState(false)
  const [exportingPdf, setExportingPdf] = useState(false)

  const fetchActiveAlerts = async (): Promise<ComplianceAlertExportItem[]> => {
    try {
      const res = await fetch('/api/compliance/alerts')
      if (!res.ok) return []
      const data: RawComplianceAlert[] = await res.json()
      if (!Array.isArray(data)) return []
      return data.map((a) => ({
        id: String(a.id || ''),
        hostname: a.hostname || 'Desconhecido',
        unit: a.unit || 'Geral',
        software_name: a.software_name || 'N/A',
        message: a.message || 'Violação de política de compliance',
        created_at: a.created_at
          ? new Date(a.created_at).toLocaleString('pt-BR')
          : new Date().toLocaleString('pt-BR'),
        is_resolved: Boolean(a.is_resolved),
      }))
    } catch (err) {
      console.error('Falha ao obter alertas de compliance:', err)
      return []
    }
  }

  const handleExportCsv = async () => {
    try {
      setExportingCsv(true)
      const alerts = await fetchActiveAlerts()
      const policyItems: SoftwarePolicyExportItem[] = policies.map((p) => ({
        name: p.name,
        status: p.status,
        units: p.units || [],
        overrides: p.overrides,
      }))
      exportComplianceCsv(policyItems, alerts)
    } catch (err) {
      console.error('Erro ao exportar CSV de compliance:', err)
    } finally {
      setExportingCsv(false)
    }
  }

  const handleExportPdf = async () => {
    try {
      setExportingPdf(true)
      const alerts = await fetchActiveAlerts()
      const policyItems: SoftwarePolicyExportItem[] = policies.map((p) => ({
        name: p.name,
        status: p.status,
        units: p.units || [],
        overrides: p.overrides,
      }))
      await exportCompliancePdf(policyItems, alerts)
    } catch (err) {
      console.error('Erro ao gerar laudo PDF de compliance:', err)
    } finally {
      setExportingPdf(false)
    }
  }

  const fetchPolicies = async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const response = await fetch('/api/compliance/policies')
      const data = await response.json()
      
      // A API pode retornar um objeto com erro ou o array direto
      const rawList = Array.isArray(data) ? data : (data.programs || [])
      
      const adapted = rawList.map((p: any) => ({
        ...p,
        status: p.status || p.globalStatus || 'pending'
      }))
      
      setPolicies(adapted)

      const allUnits = new Set<string>()
      adapted.forEach((p: any) => p.units?.forEach((u: string) => allUnits.add(u)))
      setAvailableUnits(Array.from(allUnits))
    } catch (error) {
      console.error('Fetch policies error:', error)
    } finally {
      if (!silent) setLoading(false)
    }
  }

  useEffect(() => {
    fetchPolicies()
  }, [])

  const updatePolicy = async (name: string, newStatus: string, unitName?: string) => {
    setUpdating(unitName ? `${name}-${unitName}` : name)
    try {
      const response = await fetch('/api/compliance/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, status: newStatus, unit_name: unitName })
      })
      if (!response.ok) throw new Error('Falha ao atualizar')
      await fetchPolicies(true)
    } catch (error) {
      console.error(error)
    } finally {
      setUpdating(null)
    }
  }

  const filtered = policies.filter(p => {
    const matchesSearch = p.name.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesTab = activeTab === 'all' || p.status === activeTab
    return matchesSearch && matchesTab
  })

  const stats = {
    total: policies.length,
    allowed: policies.filter(p => p.status === 'allowed').length,
    forbidden: policies.filter(p => p.status === 'forbidden').length,
    pending: policies.filter(p => p.status === 'pending').length,
  }

  return (
    <div className="space-y-8 pb-32">
      {/* HEADER TÁTICO */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-8">
        <div className="space-y-4">
          <Link 
            href="/dashboard" 
            className="inline-flex items-center gap-2 text-[10px] font-black uppercase tracking-widest text-foreground/40 hover:text-primary transition-all group"
          >
            <ArrowLeft className="h-3 w-3 group-hover:-translate-x-1 transition-transform" />
            Dashboard
          </Link>
          <div className="flex items-center gap-4">
            <div className="h-14 w-14 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shadow-lg shadow-primary/5">
              <ShieldCheck className="h-8 w-8 text-primary" />
            </div>
            <div>
              <h2 className="text-2xl font-black tracking-tighter uppercase italic">Políticas de Compliance</h2>
              <div className="flex items-center gap-2">
                <p className="text-xs text-foreground/40 font-medium">Gestão de inventário e regras táticas.</p>
                <button onClick={() => fetchPolicies()} className="p-1 hover:text-primary transition-colors">
                   <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* STATS HEADER & EXPORTS */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex bg-foreground/5 rounded-2xl p-1 border border-foreground/10 h-fit">
            <div className="px-6 py-2 text-center">
              <p className="text-xs uppercase font-bold text-foreground/20 leading-tight tracking-widest">Registros</p>
              <p className="text-lg font-black">{stats.total}</p>
            </div>
            <div className="w-px h-8 bg-foreground/10 my-auto" />
            <div className="px-6 py-2 text-center">
              <p className="text-xs uppercase font-bold text-emerald-500/40 leading-tight tracking-widest">OK</p>
              <p className="text-lg font-black text-emerald-500">{stats.allowed}</p>
            </div>
            <div className="w-px h-8 bg-foreground/10 my-auto" />
            <div className="px-6 py-2 text-center">
              <p className="text-xs uppercase font-bold text-rose-500/40 leading-tight tracking-widest">Proibidos</p>
              <p className="text-lg font-black text-rose-500">{stats.forbidden}</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleExportCsv}
              disabled={exportingCsv || exportingPdf}
              className="flex items-center gap-2 px-3.5 py-3 rounded-2xl bg-foreground/[0.04] hover:bg-foreground/[0.08] border border-foreground/10 text-xs font-bold text-foreground transition-all hover:border-emerald-500/40 disabled:opacity-50"
              title="Exportar conformidade e alertas em formato CSV (RFC-4180)"
            >
              {exportingCsv ? (
                <Loader2 className="h-4 w-4 animate-spin text-emerald-400" />
              ) : (
                <FileSpreadsheet className="h-4 w-4 text-emerald-400" />
              )}
              <span>Exportar CSV</span>
            </button>

            <button
              type="button"
              onClick={handleExportPdf}
              disabled={exportingCsv || exportingPdf}
              className="flex items-center gap-2 px-3.5 py-3 rounded-2xl bg-primary/10 hover:bg-primary/20 border border-primary/20 text-xs font-bold text-primary transition-all shadow-sm hover:border-primary/40 disabled:opacity-50"
              title="Gerar laudo executivo de conformidade em PDF A4"
            >
              {exportingPdf ? (
                <Loader2 className="h-4 w-4 animate-spin text-primary" />
              ) : (
                <FileText className="h-4 w-4 text-primary" />
              )}
              <span>Laudo PDF</span>
            </button>
          </div>
        </div>
      </div>

      {/* FILTROS E BUSCA */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        <div className="md:col-span-7 relative group">
          <Search className={`absolute left-5 top-1/2 -translate-y-1/2 h-5 w-5 transition-colors ${searchFocused ? 'text-primary' : 'text-foreground/20'}`} />
          <input 
            type="text" 
            placeholder="Pesquisar softwares..." 
            value={searchTerm}
            onFocus={() => setSearchFocused(true)}
            onBlur={() => setSearchFocused(false)}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-14 pr-6 py-4 bg-foreground/5 border border-foreground/10 rounded-[1.5rem] text-base outline-none focus:border-primary/50 focus:bg-foreground/[0.08] transition-all placeholder:text-foreground/20"
          />
        </div>

        <div className="md:col-span-5 flex bg-foreground/5 rounded-2xl p-1 border border-foreground/10 w-full">
          {[
            { id: 'all', label: 'Todos' },
            { id: 'pending', label: 'Novos' },
            { id: 'allowed', label: 'OK' },
            { id: 'forbidden', label: 'Proibidos' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex-1 relative py-2.5 rounded-xl text-xs font-bold uppercase tracking-wider transition-all ${
                activeTab === tab.id ? 'text-white' : 'text-foreground/30 hover:text-foreground/60'
              }`}
            >
              {activeTab === tab.id && (
                <motion.div
                  layoutId="activeTabComp"
                  className="absolute inset-0 bg-primary rounded-xl -z-10 shadow-lg shadow-primary/30"
                />
              )}
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* LISTAGEM DE PROGRAMAS */}
      <div className="grid grid-cols-1 gap-4">
        {loading && policies.length === 0 ? (
          <div className="space-y-4">
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="h-24 bg-foreground/5 rounded-3xl animate-pulse border border-foreground/5" />
            ))}
          </div>
        ) : (
          <AnimatePresence mode="popLayout">
            {filtered.map((policy) => (
              <motion.div
                key={policy.name}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="glass-card flex flex-col rounded-[1.5rem] border border-foreground/5 hover:border-primary/20 transition-all group overflow-hidden"
              >
                <div className="flex flex-col md:flex-row items-center justify-between p-5 gap-6">
                   <div className="flex items-center gap-5 w-full md:w-auto">
                    <div className={`h-12 w-12 rounded-xl flex items-center justify-center border-2 transition-all shadow-xl ${
                      policy.status === 'allowed' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500 shadow-emerald-500/5' :
                      policy.status === 'forbidden' ? 'bg-rose-500/10 border-rose-500/20 text-rose-500 shadow-rose-500/5' :
                      'bg-white/5 border-white/10 text-foreground/10'
                    }`}>
                      {policy.status === 'allowed' ? <CheckCircle2 className="h-6 w-6" /> : 
                       policy.status === 'forbidden' ? <AlertTriangle className="h-6 w-6" /> : 
                       <Clock className="h-6 w-6" />}
                    </div>
                    <div className="min-w-0">
                      <h3 className="font-bold text-base tracking-tight text-foreground/80 group-hover:text-foreground transition-colors truncate max-w-md">{policy.name}</h3>
                      <div className="flex items-center gap-3 mt-0.5">
                        <span className={`text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded-md border ${
                           policy.status === 'allowed' ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' :
                           policy.status === 'forbidden' ? 'bg-rose-500/10 text-rose-500 border-rose-500/20' :
                           'bg-foreground/10 text-foreground/40 border-transparent'
                        }`}>
                          {policy.status === 'allowed' ? 'Autorizado' : policy.status === 'forbidden' ? 'Bloqueado' : 'Indefinido'}
                        </span>
                        {policy.units && policy.units.length > 0 && (
                          <span className="text-[9px] font-black uppercase tracking-widest text-foreground/30 flex items-center gap-1">
                            <Building2 className="h-3 w-3" /> {policy.units.length} Unidades
                          </span>
                        )}
                      </div>
                    </div>
                   </div>

                   <div className="flex items-center gap-3 w-full md:w-auto justify-end">
                      <button
                        onClick={() => updatePolicy(policy.name, 'allowed')}
                        disabled={!!updating}
                        className={`px-6 py-3 rounded-2xl text-[11px] font-bold uppercase tracking-widest border transition-all ${
                          policy.status === 'allowed' 
                          ? 'bg-emerald-500 text-white border-emerald-500 shadow-lg shadow-emerald-500/20' 
                          : 'bg-foreground/5 text-foreground/40 border-transparent hover:border-emerald-500/30 hover:text-emerald-500'
                        }`}
                      >
                        Autorizar
                      </button>
                      <button
                        onClick={() => updatePolicy(policy.name, 'forbidden')}
                        disabled={!!updating}
                        className={`px-6 py-3 rounded-2xl text-[11px] font-bold uppercase tracking-widest border transition-all ${
                          policy.status === 'forbidden' 
                          ? 'bg-rose-500 text-white border-rose-500 shadow-lg shadow-rose-500/20' 
                          : 'bg-foreground/5 text-foreground/40 border-transparent hover:border-rose-500/30 hover:text-rose-500'
                        }`}
                      >
                        Bloquear
                      </button>
                      <button 
                        onClick={() => setExpanded(expanded === policy.name ? null : policy.name)}
                        className={`p-3 rounded-2xl border transition-all ${expanded === policy.name ? 'bg-primary text-black border-primary' : 'bg-foreground/5 text-foreground/40 border-transparent'}`}
                      >
                         <ChevronDown className={`h-5 w-5 transition-transform duration-500 ${expanded === policy.name ? 'rotate-180' : ''}`} />
                      </button>
                   </div>
                </div>

                <AnimatePresence>
                  {expanded === policy.name && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      className="bg-foreground/[0.03] border-t border-foreground/5 p-8"
                    >
                       <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                          <div className="space-y-4">
                             <h4 className="text-[10px] font-black uppercase tracking-widest text-primary flex items-center gap-2">
                               <Layers className="h-4 w-4" /> Unidades Detectadas
                             </h4>
                             <div className="flex flex-wrap gap-2">
                                {policy.units?.map(u => (
                                  <span key={u} className="px-3 py-1 bg-foreground/5 rounded-lg text-xs font-bold border border-foreground/5">{u}</span>
                                ))}
                             </div>
                          </div>
                          
                          <div className="space-y-4">
                             <h4 className="text-[10px] font-black uppercase tracking-widest text-primary">Configurar Exceção</h4>
                             <div className="flex gap-2">
                                <select 
                                  className="flex-1 bg-foreground/10 border border-foreground/10 rounded-xl p-2 text-xs outline-none focus:border-primary/50 text-white"
                                  onChange={(e) => updatePolicy(policy.name, 'allowed', e.target.value)}
                                  value=""
                                >
                                  <option value="">Autorizar para Unidade...</option>
                                  {availableUnits.map(u => <option key={u} value={u}>{u}</option>)}
                                </select>
                                <select 
                                  className="flex-1 bg-foreground/10 border border-foreground/10 rounded-xl p-2 text-xs outline-none focus:border-rose-500/50 text-white"
                                  onChange={(e) => updatePolicy(policy.name, 'forbidden', e.target.value)}
                                  value=""
                                >
                                  <option value="">Bloquear para Unidade...</option>
                                  {availableUnits.map(u => <option key={u} value={u}>{u}</option>)}
                                </select>
                             </div>
                          </div>
                       </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            ))}
          </AnimatePresence>
        )}

        {!loading && filtered.length === 0 && (
          <div className="py-32 flex flex-col items-center justify-center text-center space-y-4">
            <div className="h-20 w-20 rounded-full bg-foreground/5 flex items-center justify-center border border-foreground/10 border-dashed">
               <LayoutGrid className="h-8 w-8 text-foreground/10" />
            </div>
            <p className="text-xl font-black text-foreground/20 italic tracking-tighter">Nenhum rastro detectado</p>
          </div>
        )}
      </div>
    </div>
  )
}
