"use client"

import React, { useEffect, useState } from 'react'
import { createClient } from '@/utils/supabase/client'
import { 
  Monitor, 
  Cpu, 
  Database, 
  Clock, 
  ChevronRight,
  Shield
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { DeviceDetails, Machine } from './DeviceDetails'

export function MachineTable({ 
  search = "", 
  unitFilter = "",
  onDataLoaded 
}: { 
  search?: string; 
  unitFilter?: string;
  onDataLoaded?: (machines: Machine[]) => void;
}) {
  const getStatus = (lastPulse: string) => {
    const diff = new Date().getTime() - new Date(lastPulse).getTime()
    const minutes = diff / 1000 / 60
    if (minutes < 15) return 'online'
    if (minutes < 60) return 'away'
    return 'offline'
  }

  const formatRelativeTime = (date: string) => {
    const diff = new Date().getTime() - new Date(date).getTime()
    const minutes = Math.floor(diff / 1000 / 60)
    if (minutes < 1) return 'agora'
    if (minutes < 60) return `${minutes}m atrás`
    const hours = Math.floor(minutes / 60)
    if (hours < 24) return `${hours}h atrás`
    return new Date(date).toLocaleDateString()
  }
  const [machines, setMachines] = useState<Machine[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedMachine, setSelectedMachine] = useState<Machine | null>(null)
  const [currentPage, setCurrentPage] = useState(1)
  const machinesPerPage = 50
  const supabase = createClient()
  const onDataLoadedRef = React.useRef(onDataLoaded)

  useEffect(() => {
    onDataLoadedRef.current = onDataLoaded
  }, [onDataLoaded])

  // Reset page when search changes
  useEffect(() => {
    setCurrentPage(1)
  }, [search])

  useEffect(() => {
    const fetchMachines = async () => {
      try {
        const url = unitFilter 
          ? `/api/inventory/machines?unit=${encodeURIComponent(unitFilter)}` 
          : '/api/inventory/machines'
        const response = await fetch(url)
        if (response.ok) {
          const data = await response.json()
          // Map simulation fields to component expectations
          const mapped = data.map((m: any) => ({
            ...m,
            cpu_info: m.telemetry ? `${m.telemetry.cpu}% CPU` : 'N/A',
            ram_total: m.telemetry ? `${m.telemetry.ram}% RAM` : 'N/A',
            agent_version: m.agent_version || 'v4.0.0-sim'
          }))
          setMachines(mapped)
          onDataLoadedRef.current?.(mapped)
        } else {
           // Only attempt supabase if simulation API fails AND we're not in a strict local-sim mode
           // This prevents ERR_CONNECTION_REFUSED noise when running purely from local files
           if (process.env.NEXT_PUBLIC_SIMULATION_MODE === 'true') {
             console.log('Skipping Supabase fallback in simulation mode');
             return;
           }

           const { data, error } = await supabase
            .from('machines')
            .select('*')
            .order('last_pulse', { ascending: false })
          if (!error && data) {
            setMachines(data)
            onDataLoadedRef.current?.(data)
          }
        }
      } catch (e) {
        console.error('Error fetching machines:', e)
      } finally {
        setLoading(false)
      }
    }

    fetchMachines()
    const interval = setInterval(fetchMachines, 15000)
    return () => clearInterval(interval)
  }, [supabase, unitFilter])

  if (loading) return (
    <div className="h-64 flex items-center justify-center text-foreground/20">
      <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-primary" />
    </div>
  )

  return (
    <div className="relative">
      <div className="mt-10 overflow-hidden glass-card rounded-[2rem]">
      <div className="px-8 py-5 border-b border-foreground/5 flex items-center justify-between bg-foreground/[0.01]">
        <div className="flex flex-col">
          <h3 className="font-black text-[10px] uppercase tracking-[0.2em] text-foreground/40">Inventário do Parque</h3>
          <p className="text-sm font-bold text-foreground/80">Dispositivos Ativos</p>
        </div>
        <span className="text-[9px] bg-primary/10 text-primary px-3 py-1 rounded-full font-black border border-primary/20 uppercase tracking-widest">
          {machines.length} Unidades
        </span>
      </div>
      
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead className="text-[9px] uppercase tracking-[0.2em] text-foreground/30 font-black bg-foreground/[0.005]">
            <tr>
              <th className="px-8 py-5">Status</th>
              <th className="px-8 py-5">Máquina / Identidade</th>
              <th className="px-8 py-5">Setor / Unidade</th>
              <th className="px-8 py-5">Telemetria Hardware</th>
              <th className="px-8 py-5">Protocolo VEXT</th>
              <th className="px-8 py-5">Último Heartbeat</th>
              <th className="px-8 py-5"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-foreground/5">
            {machines
              .filter(m => {
                const term = search.toLowerCase();
                const matchesSearch = m.hostname?.toLowerCase().includes(term) || m.unit?.toLowerCase().includes(term);
                const matchesUnit = !unitFilter || m.unit === unitFilter;
                return matchesSearch && matchesUnit;
              })
              .slice((currentPage - 1) * machinesPerPage, currentPage * machinesPerPage)
              .map((machine) => (
              <tr
                key={machine.id}
                onClick={() => setSelectedMachine(machine)}
                className="hover:bg-primary/[0.02] transition-all group cursor-pointer border-b border-foreground/[0.02] last:border-0"
              >
                  <td className="px-6 py-4">
                    <div className="relative">
                      <div className={`h-2.5 w-2.5 rounded-full shadow-[0_0_10px_rgba(0,0,0,0.2)] ${ 
                        getStatus(machine.last_pulse) === 'online' ? 'bg-emerald-500 animate-pulse shadow-emerald-500/50' : 
                        getStatus(machine.last_pulse) === 'away' ? 'bg-amber-500' : 'bg-rose-500' 
                      }`} />
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="h-9 w-9 rounded-lg bg-foreground/5 flex items-center justify-center border border-foreground/10 group-hover:border-primary/30 transition-colors">
                        <Monitor className="h-4 w-4 text-primary" />
                      </div>
                      <div>
                        <p className="text-sm font-semibold">{machine.hostname || 'Desconhecido'}</p>
                        <p className="text-[10px] text-foreground/40 font-mono tracking-tighter uppercase">{machine.id.slice(0, 13)}...</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-[10px] px-2 py-1 bg-indigo-500/10 text-indigo-400 rounded-md font-bold border border-indigo-500/10 uppercase tracking-wider">
                      {machine.unit || 'Sem Unidade'}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 text-[10px] text-foreground/60">
                        <Cpu className="h-3 w-3" /> {machine.cpu_info?.split(' ')[0]}...
                      </div>
                      <div className="flex items-center gap-2 text-[10px] text-foreground/60">
                        <Database className="h-3 w-3" /> {machine.ram_total}
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2">
                      <Shield className="h-3 w-3 text-primary/40" />
                      <span className="text-[10px] font-black text-foreground/70 tracking-tight">
                        v{machine.agent_version || '3.3.0'}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-2 text-[10px] font-bold text-foreground/50">
                      <Clock className="h-3 w-3 opacity-50" />
                      {formatRelativeTime(machine.last_pulse)}
                    </div>
                  </td>
                  <td className="px-8 py-6 text-right">
                    <button className="p-2 hover:bg-foreground/5 rounded-lg opacity-0 group-hover:opacity-100 transition-all">
                      <ChevronRight className="h-4 w-4 text-foreground/40" />
                    </button>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
        {machines.length === 0 && (
          <div className="py-20 text-center text-foreground/20 italic text-sm">
            Nenhuma máquina enviando telemetria...
          </div>
        )}
      </div>

      {/* Pagination Controls */}
      {machines.length > machinesPerPage && (
        <div className="px-8 py-4 border-t border-foreground/5 flex items-center justify-between bg-foreground/[0.005]">
          <p className="text-[10px] font-bold text-foreground/30 uppercase tracking-widest">
            Mostrando {Math.min(machines.length, (currentPage - 1) * machinesPerPage + 1)}-{Math.min(machines.length, currentPage * machinesPerPage)} de {machines.length}
          </p>
          <div className="flex items-center gap-2">
            <button 
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="px-3 py-1 rounded-lg bg-white/5 border border-white/10 text-[10px] font-bold uppercase tracking-widest hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
            >
              Anterior
            </button>
            <div className="px-4 py-1 rounded-lg bg-primary/10 border border-primary/20 text-[10px] font-bold text-primary">
              {currentPage}
            </div>
            <button 
              onClick={() => setCurrentPage(p => Math.min(Math.ceil(machines.length / machinesPerPage), p + 1))}
              disabled={currentPage >= Math.ceil(machines.length / machinesPerPage)}
              className="px-3 py-1 rounded-lg bg-white/5 border border-white/10 text-[10px] font-bold uppercase tracking-widest hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
            >
              Próximo
            </button>
          </div>
        </div>
      )}
      </div>

      <AnimatePresence>
        {selectedMachine && (
          <>
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setSelectedMachine(null)}
              className="fixed inset-0 bg-black/40 backdrop-blur-sm z-40"
            />
            <DeviceDetails 
              machine={selectedMachine} 
              onClose={() => setSelectedMachine(null)} 
            />
          </>
        )}
      </AnimatePresence>
    </div>
  )
}
