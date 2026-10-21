"use client"

export const dynamic = 'force-dynamic';

import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { 
  Search, 
  Bell, 
  User, 
  Shield
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { StatsGrid } from '@/components/dashboard/StatsGrid'
import { ComplianceAlerts } from '@/components/dashboard/ComplianceAlerts'
import { 
  Chart as ChartJS, 
  RadialLinearScale, 
  PointElement, 
  LineElement, 
  Filler, 
  Tooltip, 
  Legend,
  CategoryScale,
  LinearScale,
  BarElement
} from 'chart.js'
import { Radar } from 'react-chartjs-2'
import { ExecutionReports } from '@/components/dashboard/ExecutionReports'
import AutonomousDefensePanel from '@/components/dashboard/AutonomousDefensePanel'

ChartJS.register(
  RadialLinearScale, 
  PointElement, 
  LineElement, 
  Filler, 
  Tooltip, 
  Legend,
  CategoryScale,
  LinearScale,
  BarElement
)

export default function DashboardPage() {
  const [searchFocused, setSearchFocused] = useState(false);

  const { data: configData } = useQuery({
    queryKey: ['config'],
    queryFn: async () => {
      const res = await fetch('/api/config')
      if (!res.ok) return { company_name: 'VEXT' }
      return res.json()
    },
    staleTime: 5 * 60 * 1000,
  })

  const { data: intelData } = useQuery({
    queryKey: ['intelligence-stats'],
    queryFn: async () => {
      const res = await fetch('/api/intelligence/stats')
      if (!res.ok) throw new Error('Failed to fetch stats')
      return res.json()
    },
    refetchInterval: 10000
  })

  const companyName = configData?.company_name || 'VEXT'

  useEffect(() => {
    if (configData?.company_name) {
      document.title = `${configData.company_name} | VextHub`
    }
  }, [configData])

  const hasMachines = intelData?.fleetSummary?.totalMachines > 0

  // Real Metrics Calculation
  const totalMachines = intelData?.fleetSummary?.totalMachines || 0;
  const totalAlerts = intelData?.fleetSummary?.totalAlerts || 0;
  const avgRisk = intelData?.fleetSummary?.averageRisk ? parseFloat(intelData.fleetSummary.averageRisk) : 0;
  
  const securityScore = hasMachines ? Math.max(0, 10 - (avgRisk / 10)).toFixed(1) : '0.0';
  const percentageProtected = hasMachines ? Math.max(0, 100 - avgRisk).toFixed(1) : '0';
  const stability = hasMachines ? Math.max(0, Math.min(100, 100 - (totalAlerts / totalMachines * 100))).toFixed(1) : '0';

  let complianceScore = 100;
  let atualizacaoScore = 100;
  let atividadeScore = 100;
  let reconScore = 100;
  let resilienciaScore = 100;
  let estabilidadeScore = 100;

  if (hasMachines && intelData.unitStats) {
    let totalUnauthorized = 0;
    let totalActiveAlerts = 0;
    intelData.unitStats.forEach((u: any) => {
      totalUnauthorized += u.unauthorizedApps || 0;
      totalActiveAlerts += u.activeAlerts || 0;
    });
    
    // Proportional Scoring Logic (Weighting based on fleet size)
    complianceScore = hasMachines ? Math.max(10, 100 - (totalUnauthorized / totalMachines * 400)) : 0;
    estabilidadeScore = hasMachines ? Math.max(15, 100 - (totalActiveAlerts / totalMachines * 800)) : 0;
    atividadeScore = hasMachines ? Math.max(5, 100 - avgRisk) : 0;
    resilienciaScore = hasMachines ? Math.max(12, 100 - (totalActiveAlerts / totalMachines * 1500)) : 0;
    
    // Relative secondary scores
    atualizacaoScore = Math.max(10, complianceScore * 0.95);
    reconScore = Math.max(10, atividadeScore * 0.9);
  }

  const radarData = React.useMemo(() => ({
    labels: ['Compliance', 'Atualização', 'Atividade', 'Recon OCR', 'Resiliência', 'Estabilidade'],
    datasets: [
      {
        label: 'Security Score',
        data: hasMachines ? [complianceScore, atualizacaoScore, atividadeScore, reconScore, resilienciaScore, estabilidadeScore] : [0, 0, 0, 0, 0, 0],
        backgroundColor: 'rgba(0, 245, 212, 0.2)',
        borderColor: '#00f5d4',
        borderWidth: 2,
        pointBackgroundColor: '#00f5d4',
        pointBorderColor: '#fff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: '#00f5d4'
      }
    ]
  }), [hasMachines, complianceScore, atualizacaoScore, atividadeScore, reconScore, resilienciaScore, estabilidadeScore])

  const radarOptions = React.useMemo(() => ({
    scales: {
      r: {
        angleLines: { color: 'rgba(255,255,255,0.05)' },
        grid: { color: 'rgba(255,255,255,0.05)' },
        pointLabels: { color: 'rgba(255,255,255,0.4)', font: { size: 10, weight: 'bold' as const } },
        ticks: { display: false },
        suggestedMin: 0,
        suggestedMax: 100
      }
    },
    plugins: {
      legend: { display: false }
    }
  }), [])

  return (
    <div className="space-y-6 pb-20">
      {/* 1. Header & Global Search */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="relative w-full md:w-96 group">
          <Search className={`absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 transition-colors duration-500 ${searchFocused ? 'text-primary' : 'text-foreground/20'}`} />
          <input 
            type="text" 
            placeholder="Comando Central: pesquisar no parque..." 
            onFocus={() => setSearchFocused(true)}
            onBlur={() => setSearchFocused(false)}
            className="w-full glass-card bg-foreground/[0.02] rounded-2xl pl-12 pr-4 py-3 text-sm outline-none focus:border-primary/50 focus:bg-foreground/[0.04] transition-all duration-500 shadow-sm"
          />
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 glass-card bg-foreground/[0.02] p-1.5 rounded-2xl border border-foreground/5">
             <button className="p-2 hover:bg-foreground/5 rounded-xl text-foreground/40 hover:text-foreground transition-all"><Bell className="h-4 w-4" /></button>
             <div className="w-px h-4 bg-foreground/10 mx-1" />
             <button className="p-2 hover:bg-foreground/5 rounded-xl text-foreground/40 hover:text-foreground transition-all flex items-center gap-2 px-3">
                <span className="text-[10px] font-black uppercase tracking-widest">Admin</span>
                <div className="h-6 w-6 rounded-full bg-primary/10 flex items-center justify-center border border-primary/20">
                  <User className="h-3 w-3 text-primary" />
                </div>
             </button>
          </div>
        </div>
      </div>

      {/* 2. Global Stats Highlight (Cards do topo) */}
      <StatsGrid data={intelData} />

      {/* 3. Main Tactical Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Col: Park Status & Coverage */}
        <div className="lg:col-span-3 flex flex-col gap-6">
          <div className="glass-card p-8 rounded-3xl relative overflow-hidden group flex-1 flex flex-col">
            <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/[0.03] to-transparent pointer-events-none" />
            <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-foreground/40 mb-8 flex items-center gap-2 relative z-10">
              <Shield className="h-4 w-4 text-emerald-500" /> Cobertura do Parque
            </h3>
            <div className="space-y-6 flex-1 flex flex-col justify-center">
              {[
                { label: 'Compliance Software', value: complianceScore, color: 'bg-emerald-500' },
                { label: 'Atualização Agentes', value: atualizacaoScore, color: 'bg-rose-500' },
                { label: 'Telemetria Contínua', value: atividadeScore, color: 'bg-indigo-500' },
                { label: 'Estabilidade', value: estabilidadeScore, color: 'bg-amber-500' },
              ].map((item) => (
                <div key={item.label} className="space-y-2.5">
                  <div className="flex justify-between text-[10px] font-bold uppercase tracking-wider">
                    <span className="text-foreground/60">{item.label}</span>
                    <span className="text-foreground">{hasMachines ? item.value.toFixed(1) : 0}%</span>
                  </div>
                  <div className="h-1.5 bg-foreground/5 rounded-full overflow-hidden">
                    <motion.div 
                      initial={{ width: 0 }}
                      animate={{ width: `${hasMachines ? item.value : 0}%` }}
                      className={`h-full ${item.color}`}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="glass-card p-6 rounded-3xl relative overflow-hidden group border-rose-500/10 shrink-0">
            <div className="absolute inset-0 bg-gradient-to-br from-rose-500/[0.03] to-transparent pointer-events-none" />
            <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-rose-500 mb-5 relative z-10">Softwares Irregulares</h3>
            <div className="space-y-2">
               {hasMachines && intelData?.topSoftware && intelData.topSoftware.length > 0 ? (
                 intelData.topSoftware.slice(0, 4).map((s: any) => (
                   <div key={s.name} className="bg-foreground/5 p-2.5 rounded-2xl border border-rose-500/10 text-[10px] font-bold text-foreground/60 flex justify-between">
                     <span className="truncate pr-2">{s.name}</span>
                     <span className="text-rose-500">{s.count}</span>
                   </div>
                 ))
               ) : (
                 <div className="col-span-2 text-center text-xs text-foreground/30 py-4">Nenhum software irregular</div>
               )}
            </div>
          </div>
        </div>

        {/* Center Col: Security Score Radar */}
        <div className="lg:col-span-6 flex flex-col">
          <div className="glass-card p-8 rounded-[2.5rem] bg-gradient-to-b from-primary/[0.05] via-transparent to-transparent flex flex-col items-center relative overflow-hidden group hover:border-primary/20 transition-all duration-700 h-full justify-between">
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(124,58,237,0.08),transparent)] pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity duration-1000" />
            <div className="text-center w-full">
              <h3 className="text-sm font-black uppercase tracking-[0.4em] text-primary mb-2 drop-shadow-sm">{companyName} Security Score</h3>
              <p className="text-[10px] text-foreground/30 font-bold uppercase tracking-widest mb-4">Inteligência Tática Consolidada</p>
            </div>
            
            <div className="relative w-full max-w-[380px] aspect-square flex items-center justify-center py-4">
              <Radar data={radarData} options={radarOptions} />
              <div className="absolute flex flex-col items-center justify-center">
                <span className="text-6xl font-black tracking-tighter text-foreground">
                  {securityScore}
                </span>
                <span className="text-[10px] font-bold uppercase tracking-widest text-primary/60">Nível Tático</span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-8 w-full mt-6 pt-6 border-t border-foreground/5">
               <div className="text-center">
                  <p className={`text-xl font-black ${hasMachines && percentageProtected !== '0' ? 'text-emerald-500' : 'text-foreground/20'}`}>
                    {percentageProtected}%+
                  </p>
                  <p className="text-[9px] uppercase font-bold text-foreground/30 tracking-tight">protegido que a média</p>
               </div>
               <div className="text-center">
                  <p className={`text-xl font-black ${hasMachines && stability !== '0' ? 'text-indigo-400' : 'text-foreground/20'}`}>
                    {stability}%
                  </p>
                  <p className="text-[9px] uppercase font-bold text-foreground/30 tracking-tight">estabilidade operacional</p>
               </div>
            </div>
          </div>
        </div>

        {/* Right Col: Dedicated Cortex Neural Briefing */}
        <div className="lg:col-span-3 flex flex-col gap-6">
           <div className="glass-card p-8 rounded-3xl relative overflow-hidden group flex-1 flex flex-col bg-gradient-to-br from-primary/[0.03] to-transparent border-primary/10">
             <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(124,58,237,0.06),transparent)] pointer-events-none" />
             <h3 className="text-[10px] font-black uppercase tracking-[0.2em] text-primary mb-6 flex items-center gap-2.5 relative z-10">
               <span className="w-2 h-2 rounded-full bg-primary animate-pulse" /> Córtex Neural
             </h3>
             
             <div className="space-y-5 flex-1 flex flex-col justify-center relative z-10">
               {/* Prioritized consolidated briefing summary */}
               <div className="space-y-2">
                 <span className="font-bold text-[8px] uppercase tracking-widest text-foreground/30">PARECER OPERACIONAL</span>
                 <p className="text-xs md:text-sm text-foreground/90 leading-relaxed font-semibold bg-primary/5 p-4.5 rounded-2xl border border-primary/10 shadow-sm shadow-primary/2 whitespace-pre-line">
                   {intelData?.cortexBriefing?.summary || "Carregando telemetria consolidada..."}
                 </p>
               </div>

               {/* Threat vector indicator */}
               {intelData?.cortexBriefing?.threats && (
                 <div className="p-3.5 bg-white/[0.01] border border-white/5 rounded-xl space-y-1">
                   <span className="font-bold text-foreground/45 uppercase tracking-widest text-[8px]">Vetor de Ameaça</span>
                   <p className="text-[11px] text-foreground/70 leading-relaxed">{intelData.cortexBriefing.threats}</p>
                 </div>
               )}

               {/* Strategic suggestions */}
               {intelData?.cortexBriefing?.recommendations && intelData.cortexBriefing.recommendations.length > 0 && (
                 <div className="space-y-2.5 pt-1">
                   <span className="font-bold text-primary/70 uppercase tracking-widest text-[8px]">Diretrizes Estratégicas</span>
                   <ul className="space-y-2 pl-1.5 text-[11px] text-foreground/50">
                     {intelData.cortexBriefing.recommendations.slice(0, 3).map((rec: string, idx: number) => (
                       <li key={idx} className="flex gap-2 items-start">
                         <span className="w-1 h-1 rounded-full bg-primary mt-1.5 shrink-0" />
                         <span className="leading-tight">{rec}</span>
                       </li>
                     ))}
                   </ul>
                 </div>
               )}
             </div>
           </div>
        </div>
      </div>

      {/* 4. Bottom Sections: Autonomous AI Defense, Alerts, Execution Reports */}
      <AutonomousDefensePanel 
        autonomousActions={intelData?.autonomousActions}
        anomalies={intelData?.anomalies}
        threatClusters={intelData?.threatClusters}
      />
      <ComplianceAlerts />
      <ExecutionReports />
    </div>
  )
}
