"use client"

import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  AlertTriangle, 
  X, 
  Monitor, 
  Layers, 
  ArrowRight,
  ShieldAlert
} from 'lucide-react'

type Alert = {
  id: string
  hostname: string
  unit: string
  software_name: string
  message: string
  created_at: string
}

export function ComplianceAlerts() {
  const queryClient = useQueryClient()
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)

  const { data: alerts = [], isLoading: loading } = useQuery<Alert[]>({
    queryKey: ['compliance-alerts'],
    queryFn: async () => {
      const response = await fetch('/api/compliance/alerts')
      if (!response.ok) throw new Error('Failed to fetch alerts')
      return response.json()
    },
    refetchInterval: 30000
  })

  const resolveMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await fetch('/api/compliance/alerts', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id })
      })
      if (!res.ok) throw new Error('Failed to resolve alert')
      return id
    },
    onSuccess: (id) => {
      queryClient.setQueryData<Alert[]>(['compliance-alerts'], (old = []) => 
        old.filter(a => a.id !== id)
      )
    }
  })

  const resolveAlert = (id: string) => {
    resolveMutation.mutate(id)
  }

  if (loading || alerts.length === 0) return null;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between px-2">
        <div className="flex items-center gap-2 text-rose-500">
          <ShieldAlert className="h-4 w-4" />
          <h3 className="text-xs font-bold uppercase tracking-widest">Alertas de Compliance</h3>
        </div>
        <span className="px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-500 text-[10px] font-bold">
          {alerts.length} VIOLAÇÕES
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <AnimatePresence>
          {alerts.map((alert) => (
            <motion.div
              key={alert.id}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              onClick={() => setSelectedAlert(alert)}
              className="glass-card p-6 rounded-[2rem] border border-rose-500/20 bg-rose-500/[0.02] hover:bg-rose-500/[0.05] transition-all relative group overflow-hidden cursor-pointer"
            >
              <div className="absolute top-0 right-0 p-3">
                <button 
                  onClick={(e) => {
                    e.stopPropagation();
                    resolveAlert(alert.id);
                  }}
                  className="p-1.5 hover:bg-rose-500/20 text-rose-500/40 hover:text-rose-500 rounded-lg transition-all"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="flex items-start gap-4">
                <div className="h-10 w-10 rounded-xl bg-rose-500/10 flex items-center justify-center border border-rose-500/20 text-rose-500 shrink-0 mt-1">
                  <AlertTriangle className="h-5 w-5" />
                </div>
                <div className="space-y-3 min-w-0">
                  <div>
                    <h4 className="text-sm font-bold text-rose-500 truncate pr-6">{alert.software_name}</h4>
                    <p className="text-[10px] text-foreground/40 font-medium">Detector de software não permitido</p>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-white/5 border border-white/5 text-[10px] font-medium text-foreground/60">
                      <Monitor className="h-3 w-3" /> {alert.hostname}
                    </div>
                    <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-white/5 border border-white/5 text-[10px] font-medium text-foreground/60">
                      <Layers className="h-3 w-3" /> {alert.unit}
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-2 border-t border-rose-500/10">
                    <span className="text-[9px] text-foreground/30 font-mono">
                      {new Date(alert.created_at).toLocaleString()}
                    </span>
                    <button 
                      onClick={(e) => {
                        e.stopPropagation();
                        resolveAlert(alert.id);
                      }}
                      className="flex items-center gap-1 text-primary text-[10px] font-bold hover:gap-2 transition-all"
                    >
                      Resolver <ArrowRight className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {/* DETAILED REMEDIATION CARD MODAL */}
      <AnimatePresence>
        {selectedAlert && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, y: 20, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 20, scale: 0.95 }}
              transition={{ duration: 0.3, ease: "easeOut" }}
              className="w-full max-w-lg bg-[#0C0C0D] border border-rose-500/20 rounded-[2rem] overflow-hidden shadow-2xl p-6 relative"
            >
              <button
                onClick={() => setSelectedAlert(null)}
                className="absolute top-5 right-5 p-2 bg-white/5 hover:bg-white/10 rounded-full text-foreground/60 hover:text-foreground transition-all"
              >
                <X className="h-4 w-4" />
              </button>

              <div className="space-y-6">
                <div className="flex items-center gap-3 border-b border-white/5 pb-4">
                  <div className="h-10 w-10 rounded-xl bg-rose-500/10 flex items-center justify-center border border-rose-500/20 text-rose-500">
                    <ShieldAlert className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-black text-white uppercase tracking-tight">Detalhes da Violação</h3>
                    <p className="text-[10px] text-foreground/45 font-medium uppercase tracking-widest">Procedimento Operacional Padrão</p>
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="p-4 bg-white/5 rounded-2xl border border-white/5 space-y-2">
                    <h4 className="text-xs font-bold text-rose-500 uppercase tracking-wider">{selectedAlert.software_name}</h4>
                    <p className="text-xs text-foreground/80 leading-relaxed">{selectedAlert.message}</p>
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div className="p-3 bg-white/[0.02] border border-white/5 rounded-xl space-y-1">
                      <span className="text-[9px] uppercase font-bold text-foreground/30">Equipamento</span>
                      <p className="font-semibold text-white truncate">{selectedAlert.hostname}</p>
                    </div>
                    <div className="p-3 bg-white/[0.02] border border-white/5 rounded-xl space-y-1">
                      <span className="text-[9px] uppercase font-bold text-foreground/30">Unidade</span>
                      <p className="font-semibold text-white truncate">{selectedAlert.unit}</p>
                    </div>
                  </div>

                  <div className="space-y-3">
                    <h5 className="text-[10px] font-black uppercase tracking-widest text-primary">Plano de Mitigação / Solução</h5>
                    <ul className="space-y-2.5 text-xs text-foreground/70 pl-1">
                      <li className="flex gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 shrink-0"></span>
                        <span><strong>Isolamento Lógico:</strong> Recomenda-se contatar o administrador local do endpoint <strong>{selectedAlert.hostname}</strong> para verificar a justificativa comercial do software.</span>
                      </li>
                      <li className="flex gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 shrink-0"></span>
                        <span><strong>Remoção do Rastro:</strong> Caso não seja autorizado, inicie a desinstalação manual do <strong>{selectedAlert.software_name}</strong> no equipamento.</span>
                      </li>
                      <li className="flex gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-primary mt-1.5 shrink-0"></span>
                        <span><strong>Homologação de Regra:</strong> Caso este software seja corporativo legítimo, você pode adicionar uma regra de exceção em <a href="/dashboard/compliance" className="text-primary hover:underline font-bold">Políticas</a> para autorizar o programa.</span>
                      </li>
                    </ul>
                  </div>
                </div>

                <div className="flex gap-3 pt-4 border-t border-white/5">
                  <button
                    onClick={() => {
                      resolveAlert(selectedAlert.id);
                      setSelectedAlert(null);
                    }}
                    className="flex-1 py-3 bg-rose-500 hover:bg-rose-600 text-white rounded-2xl text-xs font-black uppercase tracking-widest transition-all shadow-lg shadow-rose-500/20"
                  >
                    Marcar como Resolvido
                  </button>
                  <button
                    onClick={() => setSelectedAlert(null)}
                    className="px-6 py-3 bg-white/5 hover:bg-white/10 text-white rounded-2xl text-xs font-black uppercase tracking-widest transition-all"
                  >
                    Fechar
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  )
}
