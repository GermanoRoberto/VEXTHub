"use client"

import React, { useEffect, useState } from 'react'
import { Info, RefreshCw, CheckCircle2 } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

interface UpdateStats {
  latest_version: string;
  stats: {
    total: number;
    updated: number;
    outdated: number;
    percentage: number;
  }
}

export function UpdateBanner() {
  const [data, setData] = useState<UpdateStats | null>(null)
  const [isVisible, setIsVisible] = useState(false)

  useEffect(() => {
    async function fetchUpdates() {
      try {
        const res = await fetch('/api/agent/updates')
        const json = await res.json()
        if (json.stats) {
          setData(json)
          // Só mostra se houver desatualizados ou se foi atualizado recentemente
          if (json.stats.outdated > 0) {
            setIsVisible(true)
          }
        }
      } catch (err) {
        console.error('Failed to fetch agent updates:', err)
      }
    }

    fetchUpdates()
    // Poll every 30 seconds while updating
    const interval = setInterval(fetchUpdates, 30000)
    return () => clearInterval(interval)
  }, [])

  if (!isVisible || !data) return null

  const isFullyUpdated = data.stats.outdated === 0

  return (
    <AnimatePresence>
      <motion.div 
        initial={{ height: 0, opacity: 0 }}
        animate={{ height: 'auto', opacity: 1 }}
        exit={{ height: 0, opacity: 0 }}
        className="mb-6 overflow-hidden"
      >
        <div className={`p-4 rounded-2xl glass-card flex flex-col md:flex-row items-center justify-between gap-4 transition-all duration-500 ${
          isFullyUpdated 
            ? 'bg-emerald-500/5 border-emerald-500/20 shadow-[0_0_20px_rgba(16,185,129,0.05)]' 
            : 'bg-primary/5 border-primary/20 shadow-[0_0_20px_rgba(124,58,237,0.05)]'
        }`}>
          <div className="flex items-center gap-4">
            <div className={`h-10 w-10 rounded-xl flex items-center justify-center shrink-0 ${
              isFullyUpdated ? 'bg-emerald-500/20' : 'bg-primary/20'
            }`}>
              {isFullyUpdated ? (
                <CheckCircle2 className="h-5 w-5 text-emerald-500" />
              ) : (
                <RefreshCw className="h-5 w-5 text-primary animate-spin-slow" />
              )}
            </div>
            
            <div>
              <h4 className="text-sm font-bold text-foreground">
                {isFullyUpdated 
                  ? 'Frota 100% Atualizada' 
                  : `Atualização em Andamento: v${data.latest_version}`
                }
              </h4>
              <p className="text-xs text-foreground/50">
                {isFullyUpdated 
                  ? 'Todas as máquinas do Parque Total já estão operando na versão mais recente.' 
                  : `${data.stats.updated} de ${data.stats.total} máquinas do Parque Total já migraram para esta versão.`
                }
              </p>
            </div>
          </div>

          <div className="flex items-center gap-6 w-full md:w-auto">
            <div className="flex-1 md:w-48 h-2 bg-foreground/5 rounded-full overflow-hidden border border-foreground/5">
              <motion.div 
                initial={{ width: 0 }}
                animate={{ width: `${data.stats.percentage}%` }}
                className={`h-full rounded-full ${
                  isFullyUpdated ? 'bg-emerald-500' : 'bg-primary shadow-[0_0_10px_#6366f1]'
                }`}
              />
            </div>
            
            <div className="flex items-center gap-2">
              <span className={`text-lg font-black tracking-tighter ${
                isFullyUpdated ? 'text-emerald-500' : 'text-primary'
              }`}>
                {data.stats.percentage}%
              </span>
              <button 
                onClick={() => setIsVisible(false)}
                className="p-2 hover:bg-foreground/5 rounded-lg transition-colors"
              >
                <Info className="h-4 w-4 text-foreground/20" />
              </button>
            </div>
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  )
}
