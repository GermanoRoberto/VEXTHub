"use client"

import React, { useEffect, useState } from 'react'
import { 
  Layers, 
  Plus, 
  Trash2, 
  ArrowLeft,
  Building2,
  Download,
  X,
  ShieldCheck,
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import Link from 'next/link'

type Unit = {
  id: string | number
  name: string
  city?: string
  state?: string
  latitude?: number
  longitude?: number
  agent_key?: string
  created_at?: string
  auto_allow_compliance?: boolean
}

export default function UnitsPage() {
  const [units, setUnits] = useState<Unit[]>([])
  const [loading, setLoading] = useState(true)
  const [isCreating, setIsCreating] = useState(false)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [newUnitName, setNewUnitName] = useState('')
  const [newUnitCity, setNewUnitCity] = useState('')
  const [newUnitState, setNewUnitState] = useState('')
  const [newUnitAutoAllow, setNewUnitAutoAllow] = useState(false)
  const [updatingId, setUpdatingId] = useState<string | number | null>(null)

  const fetchUnits = async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const response = await fetch('/api/units', { cache: 'no-store' })
      const data = await response.json()

      if (!response.ok) {
        throw new Error(data?.error || 'Falha ao buscar unidades.')
      }

      setUnits(data)
    } catch (error) {
      console.error('Fetch units error:', error)
      if (!silent) alert(error instanceof Error ? error.message : 'Falha ao buscar unidades.')
    } finally {
      if (!silent) setLoading(false)
    }
  }

  useEffect(() => {
    fetchUnits()
  }, [])

  const handleCreateUnit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newUnitName || isCreating) {
      console.log('handleCreateUnit - Aborted:', { name: newUnitName, isCreating })
      if (!newUnitName) alert('Por favor, digite o nome da unidade.')
      return
    }

    console.log(`handleCreateUnit - Attempting to create: "${newUnitName}"`)
    setIsCreating(true)
    try {
      const response = await fetch('/api/units', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          name: newUnitName, 
          city: newUnitCity,
          state: newUnitState,
          auto_allow_compliance: newUnitAutoAllow 
        }),
      })
      
      console.log(`handleCreateUnit - Response status: ${response.status} ${response.statusText}`)
      
      let data;
      try {
        data = await response.json()
      } catch {
        const text = await response.text()
        console.error('handleCreateUnit - Could not parse JSON response:', text)
        throw new Error(`Servidor retornou erro nao-JSON (${response.status}): ${text.substring(0, 100)}`)
      }

      if (!response.ok) {
        const errorMsg = data?.error || JSON.stringify(data) || 'Falha desconhecida no servidor.'
        console.error('handleCreateUnit - Server Error:', errorMsg)
        alert(`Erro ao criar unidade: ${errorMsg}\n\n(Status: ${response.status})`)
      } else {
        console.log('handleCreateUnit - Success:', data)
        setNewUnitName('')
        setNewUnitCity('')
        setNewUnitState('')
        setIsModalOpen(false) // Fecha o modal após sucesso
        await fetchUnits(true)
        alert('Unidade criada com sucesso!')
      }
    } catch (err) {
      console.error('handleCreateUnit - Unexpected Error:', err)
      alert(`Erro inesperado: ${err instanceof Error ? err.message : String(err)}`)
    } finally {
      setIsCreating(false)
    }
  }

  const handleDeleteUnit = async (id: string | number) => {
    if (!confirm('Deseja realmente excluir esta unidade?')) return

    const response = await fetch(`/api/units/${id}`, {
      method: 'DELETE',
    })
    const data = await response.json()

    if (!response.ok) {
      alert(`Erro ao excluir unidade: ${data?.error || 'Falha desconhecida.'}`)
      return
    }

    fetchUnits(true)
  }

  const handleToggleAutoAllow = async (unit: Unit) => {
    setUpdatingId(unit.id)
    try {
      const response = await fetch(`/api/units/${unit.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ auto_allow_compliance: !unit.auto_allow_compliance }),
      })
      if (response.ok) {
        await fetchUnits(true)
      }
    } catch (err) {
      console.error('Update unit error:', err)
    } finally {
      setUpdatingId(null)
    }
  }

  return (
    <div className="space-y-8 pb-20">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <Link 
            href="/dashboard" 
            className="flex items-center gap-2 text-xs text-foreground/40 hover:text-primary transition-colors mb-2 group text-white"
          >
            <ArrowLeft className="h-3 w-3 group-hover:-translate-x-1 transition-transform" />
            Voltar ao Dashboard
          </Link>
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-primary/10 flex items-center justify-center border border-primary/20">
              <Layers className="h-6 w-6 text-primary" />
            </div>
            <h2 className="text-2xl font-bold tracking-tight">Gestão de Unidades</h2>
          </div>
        </div>

        <button 
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-2 px-6 py-3 rounded-xl bg-primary text-white text-sm font-bold shadow-lg shadow-primary/20 hover:scale-[1.02] active:scale-[0.98] transition-all"
        >
          <Plus className="h-5 w-5" /> Adicionar Unidade
        </button>
      </div>

      {/* Grid de Unidades */}
      {loading ? (
        <div className="h-64 flex items-center justify-center">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-primary" />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <AnimatePresence>
            {units.map((unit, index) => (
              <motion.div
                key={unit.id}
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.9 }}
                transition={{ delay: index * 0.05 }}
                className="glass-card p-6 rounded-2xl border border-white/5 hover:border-white/10 transition-all group relative overflow-hidden"
              >
                <div className="absolute top-0 right-0 p-4 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button 
                    onClick={() => handleDeleteUnit(unit.id)}
                    className="p-2 hover:bg-rose-500/10 text-foreground/20 hover:text-rose-500 rounded-lg transition-all"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>

                <div className="flex items-center gap-4 mb-4">
                  <Link 
                    href={`/dashboard/units/${encodeURIComponent(unit.name)}`}
                    className="flex items-center gap-4 hover:opacity-80 transition-opacity group/link"
                  >
                    <div className="h-12 w-12 rounded-xl bg-white/5 flex items-center justify-center border border-white/10 group-hover/link:border-primary/50 transition-colors">
                      <Building2 className="h-6 w-6 text-foreground/40 group-hover/link:text-primary transition-colors" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <h3 className="font-bold text-lg group-hover/link:text-primary transition-colors line-clamp-1" title={unit.name}>
                        {unit.name}
                      </h3>
                      <p className="text-[10px] text-foreground/40 font-mono tracking-tighter uppercase truncate">
                        {unit.city ? `${unit.city}, ${unit.state}` : 'Sem Localização'}
                      </p>
                    </div>
                  </Link>
                  <div className="flex flex-col items-end gap-1">
                    <button 
                      onClick={() => handleToggleAutoAllow(unit)}
                      disabled={updatingId === unit.id}
                      className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-[9px] font-bold uppercase tracking-wider transition-all border ${
                        unit.auto_allow_compliance 
                          ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' 
                          : 'bg-foreground/5 text-foreground/40 border-foreground/10 hover:border-foreground/20'
                      }`}
                    >
                      <ShieldCheck className="h-3 w-3" />
                      {unit.auto_allow_compliance ? 'Confiável' : 'Manual'}
                    </button>
                    {unit.agent_key && (
                      <span className="text-[8px] font-mono text-primary/40 select-all cursor-pointer hover:text-primary transition-colors">
                        {unit.agent_key}
                      </span>
                    )}
                  </div>
                </div>

                <div className="pt-4 border-t border-white/5 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <a 
                      href={`/api/installer/${encodeURIComponent(unit.name)}`}
                      className="flex items-center gap-2 p-2 px-3 rounded-lg bg-emerald-500/10 text-emerald-500 text-[10px] font-bold hover:bg-emerald-500/20 transition-all border border-emerald-500/10"
                      download={`Agent_${unit.name.replace(/\s+/g, "_")}.zip`}
                    >
                      <Download className="h-3 w-3" /> Agente C# ZIP
                    </a>
                  </div>
                  <div className="text-right">
                    <p className="text-[10px] text-foreground/40 leading-none">Criado em</p>
                    <span className="text-xs font-medium text-foreground/60">
                      {new Date(unit.created_at || Date.now()).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
          
          {units.length === 0 && (
            <div className="col-span-full py-20 text-center text-foreground/20 italic text-sm">
              Nenhuma unidade cadastrada. Crie a primeira acima!
            </div>
          )}
        </div>
      )}

      {/* Modal de Criação */}
      <AnimatePresence>
        {isModalOpen && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => !isCreating && setIsModalOpen(false)}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[100] flex items-center justify-center p-4"
            >
              {/* Modal Card */}
              <motion.div
                initial={{ opacity: 0, scale: 0.95, y: 20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95, y: 20 }}
                onClick={(e) => e.stopPropagation()}
                className="w-full max-w-md bg-[#0a0a0b] border border-white/10 rounded-3xl shadow-2xl overflow-hidden relative"
              >
                <div className="p-8 space-y-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="h-10 w-10 rounded-xl bg-primary/10 flex items-center justify-center border border-primary/20 text-primary">
                        <Plus className="h-6 w-6" />
                      </div>
                      <h3 className="text-xl font-bold">Nova Unidade</h3>
                    </div>
                    <button 
                      onClick={() => setIsModalOpen(false)}
                      className="p-2 hover:bg-white/5 rounded-full transition-colors"
                    >
                      <X className="h-5 w-5 text-white/40" />
                    </button>
                  </div>

                  <form onSubmit={handleCreateUnit} className="space-y-6">
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-white/60 ml-1">Nome da Unidade</label>
                      <input 
                        autoFocus
                        type="text" 
                        placeholder="Ex: Operacional Sul" 
                        value={newUnitName}
                        onChange={(e) => setNewUnitName(e.target.value)}
                        className="w-full px-5 py-4 bg-white/5 border border-white/10 rounded-2xl text-lg outline-none focus:border-primary/50 focus:bg-white/[0.08] transition-all text-white"
                      />
                    </div>

                    <div className="grid grid-cols-3 gap-4">
                      <div className="col-span-2 space-y-2">
                        <label className="text-[10px] font-bold uppercase tracking-widest text-white/40 ml-1">Cidade</label>
                        <input 
                          type="text" 
                          placeholder="Ex: São Paulo" 
                          value={newUnitCity}
                          onChange={(e) => setNewUnitCity(e.target.value)}
                          className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-sm outline-none focus:border-primary/50 transition-all text-white"
                        />
                      </div>
                      <div className="space-y-2">
                        <label className="text-[10px] font-bold uppercase tracking-widest text-white/40 ml-1">Estado (UF)</label>
                        <input 
                          type="text" 
                          placeholder="SP" 
                          maxLength={2}
                          value={newUnitState}
                          onChange={(e) => setNewUnitState(e.target.value.toUpperCase())}
                          className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-sm outline-none focus:border-primary/50 text-center transition-all text-white"
                        />
                      </div>
                    </div>

                    <div className="flex items-center gap-3 px-1 py-1">
                      <input 
                        type="checkbox" 
                        id="autoAllow"
                        checked={newUnitAutoAllow}
                        onChange={(e) => setNewUnitAutoAllow(e.target.checked)}
                        className="h-5 w-5 rounded border-white/10 bg-white/5 text-primary focus:ring-primary/40 transition-all cursor-pointer"
                      />
                      <label htmlFor="autoAllow" className="text-sm font-medium text-white/60 cursor-pointer select-none">
                        Unidade de Confiança (Auto-Permitir Softwares)
                      </label>
                    </div>

                    <div className="flex gap-3">
                      <button 
                        type="button"
                        onClick={() => setIsModalOpen(false)}
                        className="flex-1 px-6 py-4 rounded-2xl bg-white/5 text-white font-semibold hover:bg-white/10 transition-all border border-white/5"
                      >
                        Cancelar
                      </button>
                      <button 
                        type="submit"
                        disabled={isCreating || !newUnitName}
                        className="flex-[2] flex items-center justify-center gap-2 px-6 py-4 rounded-2xl bg-primary text-white font-bold shadow-lg shadow-primary/20 hover:scale-[1.02] active:scale-[0.98] transition-all disabled:opacity-50"
                      >
                        {isCreating ? (
                          <div className="animate-spin h-5 w-5 border-2 border-white/20 border-t-white rounded-full" />
                        ) : (
                          'Criar Unidade'
                        )}
                      </button>
                    </div>
                  </form>
                </div>
              </motion.div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  )
}
