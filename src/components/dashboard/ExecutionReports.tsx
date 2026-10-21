"use client"

import React, { useEffect, useState } from 'react'
import { createClient } from '@/utils/supabase/client'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckCircle2, AlertCircle, X, Terminal } from 'lucide-react'

interface CommandLog {
  id: string
  machine_id: string
  command_type: string
  target: string
  status: string
  result: string | null
  updated_at: string
  machines: { hostname: string } | null
}

export function ExecutionReports() {
  const [logs, setLogs] = useState<CommandLog[]>([])
  const supabase = createClient()

  useEffect(() => {
    const fetchRecentLogs = async () => {
      if (process.env.NEXT_PUBLIC_SIMULATION_MODE === 'true') {
        // In simulation mode, we might want to fetch from a local API or just skip
        // For now, let's just avoid the Supabase call if it's causing errors
        return
      }
      const { data, error } = await supabase
        .from('agent_commands')
        .select('*, machines(hostname)')
        .order('updated_at', { ascending: false })
        .limit(3)
        .in('status', ['completed', 'failed'])
      
      if (!error && data) {
        setLogs(data as any)
      }
    }

    fetchRecentLogs()

    if (process.env.NEXT_PUBLIC_SIMULATION_MODE === 'true') return

    const channel = supabase
      .channel('command-updates')
      .on('postgres_changes', { 
        event: 'UPDATE', 
        table: 'agent_commands', 
        schema: 'public' 
      }, (payload: any) => {
        if (payload.new.status === 'completed' || payload.new.status === 'failed') {
          fetchRecentLogs()
        }
      })
      .subscribe()

    return () => {
      supabase.removeChannel(channel)
    }
  }, [supabase])

  if (logs.length === 0) return null

  return (
    <div className="fixed bottom-24 right-8 z-50 flex flex-col gap-3 max-w-sm w-full">
      <AnimatePresence>
        {logs.map((log) => (
          <motion.div
            key={log.id}
            initial={{ opacity: 0, x: 20, scale: 0.95 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 20, scale: 0.95 }}
            className={`p-5 rounded-[1.5rem] glass-card shadow-[0_20px_50px_rgba(0,0,0,0.4)] flex flex-col gap-3 ${
              log.status === 'completed' 
                ? 'bg-emerald-500/[0.03] border-emerald-500/20 shadow-emerald-500/[0.02]' 
                : 'bg-rose-500/[0.03] border-rose-500/20 shadow-rose-500/[0.02]'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className={`h-8 w-8 rounded-xl flex items-center justify-center ${
                  log.status === 'completed' ? 'bg-emerald-500/20' : 'bg-rose-500/20'
                }`}>
                  {log.status === 'completed' ? (
                    <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                  ) : (
                    <AlertCircle className="h-4 w-4 text-rose-500" />
                  )}
                </div>
                <div>
                  <h5 className="text-[10px] font-black uppercase tracking-widest text-foreground/40">
                    Ordem Executada
                  </h5>
                  <p className="text-xs font-bold text-foreground">
                    {log.machines?.hostname || 'Máquina Remota'}
                  </p>
                </div>
              </div>
              <button 
                onClick={() => setLogs(logs.filter(l => l.id !== log.id))}
                className="p-1 hover:bg-foreground/5 rounded-lg"
              >
                <X className="h-3 w-3 text-foreground/20" />
              </button>
            </div>

            <div className="bg-black/20 rounded-xl p-3 space-y-2 border border-foreground/5">
              <div className="flex items-center gap-2">
                <Terminal className="h-3 w-3 text-primary/60" />
                <span className="text-[10px] font-mono text-foreground/60 truncate">
                  {log.command_type}: {log.target}
                </span>
              </div>
              {log.result && (
                <div className="text-[9px] font-mono text-foreground/40 leading-tight max-h-20 overflow-y-auto custom-scrollbar italic">
                  {log.result.startsWith('SCREENSHOT_DATA:') ? '[IMAGEM CAPTURADA]' : log.result}
                </div>
              )}
            </div>

            <div className="flex items-center justify-between mt-1">
              <span className="text-[9px] text-foreground/30 font-medium">
                Finalizado às {new Date(log.updated_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
              <div className={`text-[9px] font-black px-2 py-0.5 rounded-full uppercase tracking-tighter ${
                log.status === 'completed' ? 'text-emerald-500 bg-emerald-500/10' : 'text-rose-500 bg-rose-500/10'
              }`}>
                {log.status === 'completed' ? 'Sucesso' : 'Falha'}
              </div>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  )
}
