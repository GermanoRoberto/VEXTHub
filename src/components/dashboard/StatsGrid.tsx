"use client"

import React, { useEffect, useState } from 'react'
import { 
  Monitor, 
  Layers, 
  AlertCircle 
} from 'lucide-react'
import { motion } from 'framer-motion'

interface StatItem {
  label: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  subtext?: string;
}

export function StatsGrid({ data }: { data?: any }) {
  const [fetchedStats, setFetchedStats] = useState<StatItem[] | null>(null)

  useEffect(() => {
    if (data?.fleetSummary) return

    let isMounted = true
    const fetchRealStats = async () => {
      try {
        const response = await fetch('/api/intelligence/stats')
        const result = await response.json()
        
        if (isMounted && result?.fleetSummary) {
          setFetchedStats([
            { label: 'Máquinas Totais', value: result.fleetSummary.totalMachines.toString(), icon: Monitor, color: 'text-emerald-500' },
            { label: 'Unidades Operacionais', value: (result.unitStats?.length ?? 0).toString(), icon: Layers, color: 'text-indigo-400' },
            { label: 'Alertas Ativos', value: result.fleetSummary.totalAlerts.toString(), icon: AlertCircle, color: 'text-rose-500' },
          ])
        }
      } catch (e) {
        console.error('Stats fetch error:', e)
      }
    }

    void fetchRealStats()
    const interval = setInterval(fetchRealStats, 10000)
    return () => {
      isMounted = false
      clearInterval(interval)
    }
  }, [data])

  const stats: StatItem[] = data?.fleetSummary
    ? [
        { label: 'Máquinas Totais', value: data.fleetSummary.totalMachines.toString(), icon: Monitor, color: 'text-emerald-500' },
        { label: 'Unidades Operacionais', value: (data.unitStats?.length ?? 0).toString(), icon: Layers, color: 'text-indigo-400' },
        { label: 'Alertas Ativos', value: data.fleetSummary.totalAlerts.toString(), icon: AlertCircle, color: 'text-rose-500' },
      ]
    : (fetchedStats || [
        { label: 'Máquinas Totais', value: '--', icon: Monitor, color: 'text-emerald-500' },
        { label: 'Unidades Operacionais', value: '--', icon: Layers, color: 'text-indigo-400' },
        { label: 'Alertas Ativos', value: '--', icon: AlertCircle, color: 'text-rose-500' },
      ])

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      {stats.map((stat, index) => (
        <motion.div
          key={stat.label}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: index * 0.1 }}
          className="glass-card p-6 rounded-2xl hover:border-primary/30 transition-all group min-h-[140px] flex flex-col justify-between relative overflow-hidden"
        >
          <div className="absolute inset-0 bg-gradient-to-br from-primary/[0.02] to-transparent pointer-events-none" />
          <div className="relative z-10">
            <div className="flex items-center justify-between mb-4">
              <div className={`p-3 rounded-xl bg-foreground/[0.03] border border-foreground/10 ${stat.color} group-hover:scale-110 group-hover:bg-foreground/[0.05] transition-all duration-500`}>
                <stat.icon className="h-6 w-6" />
              </div>
            </div>
            <p className="text-3xl font-bold tracking-tight text-foreground">{stat.value}</p>
            <p className="text-sm text-foreground/40 font-medium mt-1">{stat.label}</p>
          </div>
          
          {stat.subtext && (
            <div className="mt-3 pt-3 border-t border-foreground/5">
              <p className="text-[10px] font-bold text-foreground/30 uppercase tracking-widest truncate">
                {stat.subtext}
              </p>
            </div>
          )}
        </motion.div>
      ))}
    </div>
  )
}
