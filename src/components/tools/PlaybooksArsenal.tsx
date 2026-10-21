"use client"

import React, { useState, useEffect } from 'react'
import { 
  Zap, 
  Search, 
  Terminal, 
  Activity,
  Info
} from 'lucide-react'
import { motion } from 'framer-motion'
import { useToast } from '@/components/ui/Toast'

type Playbook = {
  id: string
  label: string
  category: string
  description: string
  threats: string[]
  severity: 'low' | 'medium' | 'high' | 'critical'
}

export function PlaybooksArsenal() {
  const [search, setSearch] = useState("")
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [loading, setLoading] = useState(true)
  const toast = useToast()

    const fetchCatalog = async () => {
      setLoading(true)
      try {
        // Add timestamp to prevent browser caching
        const response = await fetch('/api/playbooks/catalog?t=' + Date.now())
        if (!response.ok) throw new Error('Falha no catálogo')
        const data = await response.json()
        
        // Map backend items to frontend Playbook type
        const mapped: Playbook[] = data.map((item: any) => ({
          id: item.id,
          label: item.label,
          category: item.category,
          description: item.description,
          threats: [item.category, ...item.scope],
          severity: item.category === 'Forense' ? 'critical' : 'low'
        }))
        
        setPlaybooks(mapped)
      } catch (error) {
        console.error('Erro ao buscar catálogo:', error)
      } finally {
        setLoading(false)
      }
    }

  useEffect(() => {
    fetchCatalog()
  }, [])


  const filtered = playbooks.filter(p => 
    p.label.toLowerCase().includes(search.toLowerCase()) || 
    p.description.toLowerCase().includes(search.toLowerCase())
  )

  const executePlaybook = async (id: string) => {
    try {
      const response = await fetch('/api/playbooks/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ playbook_id: id, scope: 'all' })
      })
      if (response.ok) {
        toast.tactical(`Playbook [${id}] registrado com sucesso. Verifique o Lab Forense.`)
      } else {
        toast.error('Falha ao disparar playbook.')
      }
    } catch {
      toast.error('Erro de conexão com o Arsenal.')
    }
  }

  return (
    <div className="h-full flex flex-col space-y-8 animate-in slide-in-from-bottom-2 duration-500">
      <header className="flex flex-col lg:flex-row lg:items-end justify-between gap-6">
        <div>
          <div className="flex items-center gap-3 mb-3">
            <Zap className="h-4 w-4 text-primary" />
            <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Biblioteca de Resposta a Incidentes</p>
          </div>
          <h2 className="text-4xl font-extrabold tracking-tight uppercase text-white">Arsenal <span className="text-primary">Tático</span></h2>
        </div>
        
        <div className="flex flex-col sm:flex-row items-center gap-4">
          <div className="relative group w-full lg:w-96">
            <div className="absolute left-6 top-1/2 -translate-y-1/2 text-muted-foreground/50">
              <Search className="h-4 w-4" />
            </div>
            <input 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              type="text" 
              placeholder="Buscar playbook por função ou ameaça..." 
              className="apex-input w-full pl-14 pr-6 font-mono text-xs"
            />
          </div>
        </div>
      </header>

      {loading ? (
        <div className="flex-1 flex items-center justify-center">
          <Activity className="h-12 w-12 text-primary animate-spin" />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {filtered.map((pb) => (
          <motion.div 
            key={pb.id}
            whileHover={{ y: -4 }}
            className="apex-card p-0 flex flex-col overflow-hidden border-white/5 bg-white/[0.02] hover:border-primary/30 transition-all group"
          >
            <div className="p-8 space-y-6">
              <div className="flex items-start justify-between">
                <div className={`w-12 h-12 rounded-[--radius-tactical] border border-white/10 flex items-center justify-center shadow-lg ${
                  pb.severity === 'critical' ? 'bg-rose-500/10 text-rose-500' : 'bg-primary/10 text-primary'
                }`}>
                  <Terminal className="h-6 w-6" />
                </div>
                <div className={`px-3 py-1 rounded-full text-[8px] font-black uppercase tracking-widest border ${
                  pb.severity === 'critical' ? 'bg-rose-500/10 text-rose-500 border-rose-500/20' : 'bg-white/5 text-muted-foreground border-white/10'
                }`}>
                  {pb.category}
                </div>
              </div>

              <div>
                <h3 className="text-xl font-black uppercase text-white mb-2 group-hover:text-primary transition-colors">{pb.label}</h3>
                <p className="text-xs text-muted-foreground leading-relaxed h-12 overflow-hidden">{pb.description}</p>
              </div>

              <div className="flex flex-wrap gap-2">
                {pb.threats.map((threat, i) => (
                  <span key={i} className="px-2 py-1 bg-black/40 rounded-[--radius-tactical] text-[9px] font-bold text-muted-foreground/60 border border-white/5 italic">
                    #{threat}
                  </span>
                ))}
              </div>
            </div>

            <button 
              onClick={() => executePlaybook(pb.id)}
              className="mt-auto p-6 bg-white/5 border-t border-white/10 flex items-center justify-center gap-3 text-[10px] font-black uppercase tracking-[0.2em] hover:bg-primary hover:text-white transition-all text-primary"
            >
              <Zap className="h-4 w-4" />
              Executar Playbook
            </button>
          </motion.div>
        ))}
      </div>
      )}

      <div className="apex-card p-8 border-primary/20 bg-primary/5 flex items-center justify-between">
        <div className="flex items-center gap-6">
          <div className="w-16 h-16 rounded-[--radius-tactical] bg-primary/20 flex items-center justify-center text-primary border border-primary/30">
            <Info className="h-8 w-8" />
          </div>
          <div>
            <h4 className="text-lg font-black uppercase text-white tracking-tight">Manual de Engajamento</h4>
            <p className="text-xs text-muted-foreground max-w-2xl mt-1">
               Playbooks registram ações defensivas no simulador e não executam shell arbitrário. Para comandos no agente, use a aba Arsenal Tático dentro do dispositivo.
            </p>
          </div>
        </div>
        <button 
          onClick={() => fetchCatalog()}
          className="px-8 py-4 bg-white/5 border border-white/10 rounded-[--radius-tactical] text-[10px] font-black uppercase tracking-widest hover:bg-white/10 transition-all text-muted-foreground hover:text-white"
        >
          Sincronizar Catálogo
        </button>
      </div>
    </div>
  )
}
