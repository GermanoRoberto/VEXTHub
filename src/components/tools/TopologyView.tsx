"use client"

import React, { useState, useEffect, useRef } from 'react'
import dynamic from 'next/dynamic'
import { 
  Globe, 
  Share2, 
  Building2, 
  Monitor, 
  Activity, 
  ShieldCheck 
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

// Dynamically import Leaflet components to avoid SSR issues
const MapContainer = dynamic(() => import('react-leaflet').then(mod => mod.MapContainer), { ssr: false })
const TileLayer = dynamic(() => import('react-leaflet').then(mod => mod.TileLayer), { ssr: false })
const Marker = dynamic(() => import('react-leaflet').then(mod => mod.Marker), { ssr: false })
const Popup = dynamic(() => import('react-leaflet').then(mod => mod.Popup), { ssr: false })

type Node = {
  id: string
  hostname: string
  ip: string
  unit: string
  status: 'online' | 'offline'
  x: number
  y: number
  vx: number
  vy: number
}

type Unit = {
  id: string
  name: string
  location: string
  latitude: number
  longitude: number
  x: number
  y: number
}

type ActivityLog = {
  id: number
  type: 'connect' | 'disconnect' | 'alert'
  text: string
  timestamp: string
}

export function TopologyView() {
  const [viewMode, setViewMode] = useState<'logical' | 'geo'>('logical')
  const [units, setUnits] = useState<Unit[]>([])
  const [nodes, setNodes] = useState<Node[]>([])

  const [logs, setLogs] = useState<ActivityLog[]>([])

  useEffect(() => {
    const loadData = async () => {
      try {
        const response = await fetch('/api/topology')
        if (response.ok) {
          const data = await response.json()
          const mappedUnits = (data.units || []).map((u: any) => ({
            ...u,
            latitude: typeof u.latitude === 'number' ? u.latitude : u.lat,
            longitude: typeof u.longitude === 'number' ? u.longitude : u.lon
          }))
          setUnits(mappedUnits)
          
          // Sample nodes if too many for logical view
          const allMachines = data.machines || []
          const sampledMachines = allMachines.length > 300 
            ? allMachines.sort(() => 0.5 - Math.random()).slice(0, 300)
            : allMachines
            
          setNodes(sampledMachines.map((m: any) => ({ 
            ...m, 
            vx: 0, 
            vy: 0,
            x: m.x || Math.random() * 100,
            y: m.y || Math.random() * 100
          })))

          if (data.events) {
             const initialLogs: ActivityLog[] = data.events.map((ev: any) => ({
                id: ev.id,
                type: ev.severity === 'HIGH' || ev.severity === 'CRITICAL' ? 'alert' : 'connect',
                text: `[${ev.agent_hostname}] ${ev.type}`,
                timestamp: new Date(ev.timestamp).toLocaleTimeString('pt-BR')
              }))
              setLogs(initialLogs.slice(0, 20))
          }
        }
      } catch (e) { console.error(e) }
    }

    const pollEvents = async () => {
      try {
        const response = await fetch('/api/topology')
        if (response.ok) {
          const data = await response.json()
          if (data.events) {
            const newLogs: ActivityLog[] = data.events.map((ev: any) => ({
              id: ev.id,
              type: ev.severity === 'HIGH' || ev.severity === 'CRITICAL' ? 'alert' : 'connect',
              text: `[${ev.agent_hostname}] ${ev.type}`,
              timestamp: new Date(ev.timestamp).toLocaleTimeString('pt-BR')
            }))
            setLogs(prev => {
              const ids = new Set(prev.map(l => l.id))
              const unique = newLogs.filter(l => !ids.has(l.id))
              return [...unique, ...prev].slice(0, 20)
            })
          }
        }
      } catch (e) { console.error(e) }
    }
    
    loadData()
    const interval = setInterval(pollEvents, 15000)
    return () => clearInterval(interval)
  }, [])


  const simulationRef = useRef<number>(null)

  useEffect(() => {
    if (viewMode === 'logical') {
      const runSimulation = () => {
        setNodes(prevNodes => {
          const k_attr = 0.05
          const k_rep = 15.0
          const damping = 0.85

          const updated = [...prevNodes]

          // Repulsion
          for (let i = 0; i < updated.length; i++) {
            for (let j = i + 1; j < updated.length; j++) {
              const dx = updated[i].x - updated[j].x
              const dy = updated[i].y - updated[j].y
              const distSq = dx * dx + dy * dy + 0.1
              const force = k_rep / distSq
              const fx = (dx / Math.sqrt(distSq)) * force
              const fy = (dy / Math.sqrt(distSq)) * force
              updated[i].vx += fx; updated[i].vy += fy
              updated[j].vx -= fx; updated[j].vy -= fy
            }
          }

          // Attraction to Unit Hubs
          updated.forEach(node => {
            const hub = units.find(u => u.id === node.unit) || { x: 50, y: 50 }
            node.vx += (hub.x - node.x) * k_attr
            node.vy += (hub.y - node.y) * k_attr
          })

          // Update positions
          return updated.map(n => {
            n.vx *= damping; n.vy *= damping
            n.x += n.vx; n.y += n.vy
            n.x = Math.max(5, Math.min(95, n.x))
            n.y = Math.max(5, Math.min(95, n.y))
            return n
          })
        })
        simulationRef.current = requestAnimationFrame(runSimulation)
      }
      simulationRef.current = requestAnimationFrame(runSimulation)
    } else {
      if (simulationRef.current) cancelAnimationFrame(simulationRef.current)
    }

    return () => {
      if (simulationRef.current) cancelAnimationFrame(simulationRef.current)
    }
  }, [viewMode, units])

  // Mock Leaflet CSS if not loaded
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const link = document.createElement('link')
      link.rel = 'stylesheet'
      link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css'
      document.head.appendChild(link)
    }
  }, [])

  return (
    <div className="h-[calc(100vh-140px)] flex flex-col space-y-8 animate-fade-in">
      {/* Header Area */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 px-4">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="w-2 h-2 rounded-full bg-primary shadow-lg shadow-primary/30 animate-pulse"></div>
            <p className="text-[11px] font-black text-primary/60 uppercase tracking-[0.3em]">MAPA DE INFRAESTRUTURA</p>
          </div>
          <h1 className="text-3xl sm:text-5xl font-black text-foreground tracking-tighter uppercase">
            Topologia de <span className="text-primary italic">Rede</span>
          </h1>
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="flex items-center justify-between gap-4 px-6 py-4 bg-white/5 rounded-[--radius-tactical] border border-white/10 shadow-xl">
            <div className="flex -space-x-2">
              {nodes.slice(0, 3).map((n, i) => (
                <div key={i} className="w-7 h-7 rounded-full border-2 border-[#0A0A0B] bg-primary flex items-center justify-center text-white shadow-lg">
                  <Monitor className="h-3.5 w-3.5" />
                </div>
              ))}
              {nodes.length > 3 && (
                <div className="w-7 h-7 rounded-full border-2 border-[#0A0A0B] bg-white/10 flex items-center justify-center text-[10px] font-bold text-muted-foreground">
                  +{nodes.length - 3}
                </div>
              )}
            </div>
            <div className="h-4 w-[1px] bg-white/10 mx-1"></div>
            <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">{nodes.length} Nodos Conectados</span>
          </div>

          <button 
            onClick={() => setViewMode(v => v === 'geo' ? 'logical' : 'geo')}
            className="h-12 px-8 rounded-2xl glass-card text-[10px] font-black uppercase text-foreground/80 flex items-center justify-center gap-3 hover:text-primary transition-all border border-foreground/10 group shadow-xl"
          >
            {viewMode === 'geo' ? <Share2 className="h-5 w-5" /> : <Globe className="h-5 w-5" />}
            {viewMode === 'geo' ? "Mapa Lógico" : "Geo Mapa"}
          </button>
        </div>
      </div>

      <div className="flex-1 flex gap-8 min-h-0">
        {/* Map Canvas Container */}
        <div className="flex-1 apex-card relative overflow-hidden group/canvas p-0 transition-all duration-500 hover:shadow-primary/5 border-white/5 bg-white/[0.02]">
          {/* Grid Overlay */}
          <div className="absolute inset-0 opacity-10 pointer-events-none transition-opacity group-hover/canvas:opacity-20 z-0" 
               style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, var(--color-primary) 1px, transparent 0)', backgroundSize: '30px 30px' }}></div>

          {viewMode === 'logical' ? (
            <div className="w-full h-full relative z-10 animate-fade-in overflow-hidden">
              <svg className="absolute inset-0 w-full h-full pointer-events-none opacity-40">
                {nodes.map(node => {
                  const hub = units.find(u => u.id === node.unit) || { x: 50, y: 50 }
                  return (
                    <line
                      key={node.id}
                      x1={`${hub.x}%`}
                      y1={`${hub.y}%`}
                      x2={`${node.x}%`}
                      y2={`${node.y}%`}
                      stroke="rgba(124, 58, 237, 0.3)"
                      strokeWidth="1.2"
                      strokeDasharray="2 4"
                    />
                  )
                })}
              </svg>

              {/* Unit Hubs */}
              {units.map(hub => (
                <div key={hub.id} className="absolute z-20 -translate-x-1/2 -translate-y-1/2 transition-all duration-300" style={{ left: `${hub.x}%`, top: `${hub.y}%` }}>
                  <div className="flex flex-col items-center gap-2">
                    <div className="w-12 h-12 rounded-[--radius-tactical] bg-primary/10 border border-primary/40 flex items-center justify-center shadow-[0_0_20px_rgba(124,58,237,0.2)] backdrop-blur-sm">
                      <Building2 className="h-6 w-6 text-primary" />
                    </div>
                    <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest bg-black/80 px-3 py-1 rounded-full border border-white/10">{hub.name}</span>
                  </div>
                </div>
              ))}

              {/* Agent Nodes */}
              {nodes.map(node => (
                <div key={node.id} className="absolute z-10" style={{ left: `${node.x}%`, top: `${node.y}%` }}>
                  <div className="relative group/node -translate-x-1/2 -translate-y-1/2">
                    <div className="w-16 h-16 rounded-[--radius-tactical] bg-[#0A0A0B]/60 backdrop-blur-md border border-white/10 flex items-center justify-center hover:bg-white/5 group-hover/node:scale-110 group-hover/node:border-primary/50 transition-all cursor-pointer shadow-xl">
                      <Monitor className="h-8 w-8 text-primary/60 group-hover/node:text-primary transition-colors" />
                      <div className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-primary border-2 border-[#0A0A0B] shadow-lg"></div>
                    </div>
                    <div className="absolute -bottom-14 left-1/2 -translate-x-1/2 opacity-0 group-hover/node:opacity-100 group-hover/node:-bottom-12 transition-all duration-300 pointer-events-none whitespace-nowrap z-30">
                      <div className="px-4 py-3 bg-[#0A0A0B] border border-white/20 rounded-[--radius-tactical] shadow-2xl">
                        <p className="text-[11px] font-bold text-white uppercase tracking-widest">{node.hostname}</p>
                        <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-widest mt-1">{node.ip}</p>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="absolute inset-0 z-10 animate-fade-in">
              <MapContainer 
                center={[-15.78, -47.93]} 
                zoom={4} 
                style={{ height: '100%', width: '100%', background: '#0A0A0B' }}
                zoomControl={false}
              >
                <TileLayer url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png" />
                {viewMode === 'geo' && units
                  .filter(u => typeof u.latitude === 'number' && typeof u.longitude === 'number' && !isNaN(u.latitude) && !isNaN(u.longitude))
                  .map(u => (
                  <Marker key={u.id} position={[u.latitude!, u.longitude!]}>
                    <Popup>
                      <div className="p-2 font-bold uppercase text-[10px]">{u.name}</div>
                    </Popup>
                  </Marker>
                ))}
              </MapContainer>
              <div className="absolute bottom-10 right-10 z-[400] px-5 py-3 bg-[#0A0A0B]/80 backdrop-blur-md rounded-[--radius-tactical] flex items-center gap-4 shadow-2xl border border-white/10">
                <span className="w-2 h-2 rounded-full bg-primary shadow-lg shadow-primary/50 animate-pulse"></span>
                <span className="text-[10px] font-bold text-white uppercase tracking-widest">Geolocalizador Global</span>
              </div>
            </div>
          )}
        </div>

        {/* Real-time Monitor Sidebar */}
        <div className="w-80 flex flex-col gap-6">
          <div className="glass-card flex-1 flex flex-col p-0 overflow-hidden border-foreground/10">
            <div className="p-6 bg-foreground/[0.03] border-b border-foreground/5 flex items-center gap-3">
              <Activity className="h-5 w-5 text-primary" />
              <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-foreground/80">Monitor de Atividade</h3>
            </div>
            
            <div className="flex-1 overflow-y-auto p-6 space-y-4 hide-scrollbar">
              <AnimatePresence initial={false}>
                {logs.map((log) => (
                  <motion.div 
                    key={log.id}
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="p-4 rounded-[--radius-tactical] bg-white/[0.02] border border-white/5 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className={`text-[8px] font-black uppercase tracking-widest px-2 py-0.5 rounded ${
                        log.type === 'alert' ? 'bg-rose-500/20 text-rose-500' : 'bg-primary/20 text-primary'
                      }`}>
                        {log.type}
                      </span>
                      <span className="text-[8px] font-mono text-muted-foreground/40">{log.timestamp}</span>
                    </div>
                    <p className="text-[10px] text-white/70 font-medium leading-relaxed">{log.text}</p>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
            
            <div className="p-6 bg-white/5 border-t border-white/10">
              <div className="flex items-center justify-between gap-4">
                <div className="flex flex-col">
                  <span className="text-[9px] font-bold text-muted-foreground uppercase tracking-widest">Saúde do Uplink</span>
                  <span className="text-xs font-black text-primary">ESTÁVEL</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse"></div>
                  <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse delay-75"></div>
                  <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse delay-150"></div>
                </div>
              </div>
            </div>
          </div>

          <div className="apex-card p-6 border-white/5 bg-gradient-to-br from-primary/5 to-transparent">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-[--radius-tactical] bg-primary/10 flex items-center justify-center text-primary border border-primary/20">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <div>
                <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">Estado de Integridade</p>
                <p className="text-sm font-black text-white uppercase">NOMINAL</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
