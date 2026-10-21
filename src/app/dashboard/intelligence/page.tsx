"use client"

import React, { useEffect, useState, useRef } from 'react'
import { 
  FileBarChart2, 
  ArrowLeft, 
  TrendingUp, 
  Target,
  Building2,
  Zap,
  Printer,
  ShieldAlert,
  RefreshCcw,
  Circle,
  Layers,
  Monitor
} from 'lucide-react'
import Link from 'next/link'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler,
  ArcElement
} from 'chart.js'
import { Bar, Doughnut } from 'react-chartjs-2'
import jsPDF from 'jspdf'
import { toJpeg } from 'html-to-image'
import { CommandCenter } from '@/components/dashboard/CommandCenter'


// Register ChartJS
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
)

type IntelData = {
  unitStats: {
    name: string
    machineCount: number
    unauthorizedApps: number
    activeAlerts: number
    riskScore: number
    devices: any[]
    networkSummary: any
    violatingDevices?: { hostname: string, badApps: string[] }[]
  }[]
  topSoftware: { 
    name: string, 
    count: number, 
    affectedMachines: { hostname: string, unit: string }[] 
  }[]
  companyName: string
  fleetSummary: {
    totalMachines: number
    totalAlerts: number
    averageRisk: number
  }
  cortex_analysis?: {
    enabled: boolean
    executive_summary?: string
    threat_landscape?: string
    strategic_recommendations?: string[]
    compliance_posture?: string
    provider?: string
  }
}

export default function ReportsPage() {
  const [data, setData] = useState<IntelData | null>(null)
  const [loading, setLoading] = useState(true)
  const [isExporting, setIsExporting] = useState(false)
  const [exportProgress, setExportProgress] = useState(0)
  const [isCommandCenterOpen, setIsCommandCenterOpen] = useState(false)
  const [actioning, setActioning] = useState<string | null>(null)
  const auditRef = useRef<HTMLDivElement>(null)

  const fetchData = async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const response = await fetch('/api/intelligence/stats')
      const result = await response.json()
      if (response.ok) setData(result)
    } catch (error) {
      console.error('Reports fetch error:', error)
    } finally {
      if (!silent) setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    // Auto-refresh every 30 seconds to reflect real-time connections
    const interval = setInterval(() => fetchData(true), 30000)
    return () => clearInterval(interval)
  }, [])

  const exportPDF = async () => {
    setIsExporting(true)
    setExportProgress(0)
    
    try {
      // Wait a bit for the DOM to render the hidden document and the loading overlay
      await new Promise(resolve => setTimeout(resolve, 500))

      if (!auditRef.current) throw new Error('Ref não inicializado');

      const pdf = new jsPDF('p', 'mm', 'a4')
      const pages = auditRef.current.querySelectorAll('.audit-page')
      
      for (let i = 0; i < pages.length; i++) {
        // Update progress and yield to render cycle
        setExportProgress(Math.round(((i) / pages.length) * 100));
        await new Promise(resolve => setTimeout(resolve, 10));

        const page = pages[i] as HTMLElement
        // Render each page with optimized scale for performance
        const dataUrl = await toJpeg(page, {
          quality: 0.90, // JPEG quality
          pixelRatio: 2, // Reduced from 3x to 2x scale to prevent Out of Memory on huge documents
          backgroundColor: '#ffffff',
          cacheBust: true,
        })
        
        if (i > 0) pdf.addPage()
        pdf.addImage(dataUrl, 'JPEG', 0, 0, 210, 297, undefined, 'FAST') // Added FAST compression
        
        // Update progress after adding page
        setExportProgress(Math.round(((i + 1) / pages.length) * 100));
      }
      
      pdf.save(`VEXTHUB_RELATORIO_${new Date().toISOString().split('T')[0]}.pdf`)
    } catch (error: any) {
      console.error('PDF Export error:', error)
      alert('Erro ao gerar relatório. Tente novamente.')
    } finally {
      setIsExporting(false)
      setExportProgress(0)
    }
  }

  const sendCommand = async (machineHostname: string, type: string, target: string) => {
    setActioning(`${machineHostname}-${type}`);
    try {
      const response = await fetch('/api/agent/commands/enqueue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname: machineHostname, command_type: type, target })
      })
      if (!response.ok) throw new Error('Falha ao enviar')
      alert(`Ação ${type} enfileirada para ${machineHostname}. O agente processará no próximo pulso.`);
    } catch {
      alert('Erro ao processar acao segura.');
    } finally {
      setActioning(null);
    }
  }

  const sendCommandMass = async (softwareName: string) => {
    setActioning(`MASS-${softwareName}`);
    try {
      const response = await fetch('/api/agent/commands/enqueue/mass', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ software_name: softwareName })
      })
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Falha na acao em massa')
      alert(`Revalidação enfileirada para ${result.count} endpoints. Os agentes atualizarão a telemetria no próximo pulso.`);
      fetchData(true);
    } catch (error: any) {
      alert(`Erro: ${error.message}`);
    } finally {
      setActioning(null);
    }
  }

  if (loading && !data) {
    return (
      <div className="py-20 flex flex-col items-center justify-center gap-4">
        <div className="animate-spin h-10 w-10 border-t-2 border-primary rounded-full" />
        <p className="text-foreground/40 text-sm font-medium animate-pulse">Sincronizando inteligência...</p>
      </div>
    )
  }

  // If no data yet and not loading, show something or keep spinner
  if (!data) return null;

  // Neon Palettes for Dashboard
  const riskChartData = {
    labels: data.unitStats.map(u => u.name),
    datasets: [
      {
        label: 'Índice de Risco (%)',
        data: data.unitStats.map(u => u.riskScore),
        backgroundColor: data.unitStats.map(u => 
          u.riskScore > 70 ? 'rgba(244, 63, 94, 0.4)' : 
          u.riskScore > 40 ? 'rgba(245, 158, 11, 0.4)' : 
          'rgba(99, 102, 241, 0.4)'
        ),
        borderColor: data.unitStats.map(u => 
          u.riskScore > 70 ? '#f43f5e' : 
          u.riskScore > 40 ? '#f59e0b' : 
          '#6366f1'
        ),
        borderWidth: 2,
        borderRadius: 12,
      }
    ]
  }

  const chartOptions: any = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: { enabled: true }
    },
    scales: {
      y: { 
        beginAtZero: true,
        max: 100,
        grid: { color: 'rgba(51, 65, 85, 0.1)' },
        ticks: { color: '#64748b', font: { size: 10 } }
      },
      x: { 
        grid: { display: false },
        ticks: { color: '#64748b', font: { size: 9 } }
      }
    }
  }

  // Helper for dynamic A4 pagination
  const chunkArray = <T,>(arr: T[], size: number): T[][] => {
    if (!arr) return [];
    return Array.from({ length: Math.ceil(arr.length / size) }, (_, i) =>
      arr.slice(i * size, i * size + size)
    );
  };

  return (
    <div className="space-y-8 pb-32">
      {/* 1. VISIBLE DASHBOARD UI */}
      <div className="space-y-8">
        {/* Header and Actions */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 px-4">
          <div className="space-y-1">
            <Link href="/dashboard" className="flex items-center gap-2 text-xs text-foreground/40 hover:text-primary transition-colors mb-2 group">
              <ArrowLeft className="h-3 w-3 group-hover:-translate-x-1 transition-transform" />
              Voltar ao Dashboard
            </Link>
              <div className="flex items-center gap-4">
                <div className="h-10 w-10 rounded-xl bg-primary/10 flex items-center justify-center border border-primary/20">
                  <FileBarChart2 className="h-6 w-6 text-primary" />
                </div>
                <div className="space-y-0.5">
                  <h2 className="text-2xl font-bold tracking-tight text-foreground">Relatórios Operacionais</h2>
                  <div className="flex items-center gap-2">
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                    </span>
                    <span className="text-[10px] font-black text-emerald-500 uppercase tracking-tighter">Live Intelligence Sync Active</span>
                  </div>
                </div>
              </div>
            <p className="text-sm text-foreground/40 italic">Mapeamento geral de dispositivos, unidades e inconformidades.</p>
          </div>

          <div className="flex items-center gap-3">
            <button 
              onClick={() => setIsCommandCenterOpen(true)} 
              className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 text-xs font-bold hover:bg-emerald-500 hover:text-white transition-all shadow-lg"
            >
              <ShieldAlert className="h-4 w-4" />
              <span>Ações Seguras</span>
            </button>

            <button onClick={exportPDF} disabled={isExporting} className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-primary text-white text-xs font-bold hover:bg-primary/80 transition-all shadow-lg disabled:opacity-50">
              {isExporting ? <RefreshCcw className="h-4 w-4 animate-spin" /> : <Printer className="h-4 w-4" />}
              <span>Gerar Relatório Executivo A4</span>
            </button>
          </div>
        </div>

        <CommandCenter 
          isOpen={isCommandCenterOpen} 
          onClose={() => setIsCommandCenterOpen(false)} 
        />

        {/* Top Metric Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 px-1">
          {[
            { label: 'Risco Médio Fleet', value: `${data.fleetSummary.averageRisk}%`, icon: Zap, color: 'text-primary' },
            { label: 'Violações Ativas', value: data.fleetSummary.totalAlerts, icon: ShieldAlert, color: 'text-rose-500' },
            { label: 'Ponto Focal de Risco', value: data.unitStats[0]?.name || 'N/A', icon: Building2, color: 'text-amber-500' },
            { label: 'Dispositivos Totais', value: data.fleetSummary.totalMachines, icon: TrendingUp, color: 'text-emerald-500' },
          ].map((stat, i) => (
            <div key={i} className="glass-card p-6 rounded-3xl border border-border/50 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase tracking-widest text-foreground/40">{stat.label}</span>
                <stat.icon className={`h-4 w-4 ${stat.color}`} />
              </div>
              <p className="text-3xl font-black text-foreground">{stat.value}</p>
            </div>
          ))}
        </div>

        {/* Risk Chart (Full Width) */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-3 glass-card p-8 rounded-[2.5rem] border border-border/50 h-[400px]">
             <h3 className="text-lg font-bold mb-8 flex items-center gap-2 text-foreground">
               <TrendingUp className="h-5 w-5 text-primary" /> Mapeamento de Risco por Unidade
            </h3>
            <div className="h-full pb-12">
              <Bar data={riskChartData} options={chartOptions} />
            </div>
          </div>
        </div>


        {/* Detailed Non-Conformity Section */}
        <div className="grid grid-cols-1 gap-6">
          <div className="glass-card p-8 rounded-[3rem] border border-rose-500/10 bg-rose-500/[0.01]">
            <h3 className="text-xl font-bold flex items-center gap-3 text-rose-500 mb-8">
              <ShieldAlert className="h-6 w-6" /> Inconformidades Críticas
            </h3>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
              {data.topSoftware.map((s, i) => (
                <div key={i} className="p-5 rounded-2xl bg-foreground/[0.01] border border-border/50 space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4 text-white">
                      <div className="h-8 w-8 rounded-lg bg-rose-500/10 flex items-center justify-center border border-rose-500/20 text-rose-500 font-bold">{i+1}</div>
                      <div>
                        <p className="text-sm font-bold">{s.name}</p>
                        <p className="text-[10px] text-rose-500/70 uppercase font-black tracking-tighter">Bloqueio Ativo pela Política</p>
                      </div>
                    </div>
                    
                    {/* Acoes em massa: revalidacao defensiva */}
                    <div className="flex items-center gap-2">
                       <button 
                        onClick={() => {
                          if(confirm(`Enfileirar revalidacao de compliance para "${s.name}" em ${s.count} endpoints?`)) {
                            sendCommandMass(s.name)
                          }
                        }}
                        disabled={actioning === `MASS-${s.name}`}
                        className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-600 text-white text-[9px] font-black uppercase hover:bg-emerald-700 transition-all shadow-lg shadow-emerald-500/20 disabled:opacity-50"
                       >
                         <Zap className="h-3 w-3" /> {actioning === `MASS-${s.name}` ? 'Enfileirando...' : 'Revalidar Todos'}
                       </button>
                       <p className="text-lg font-black text-rose-500">{s.count}</p>
                    </div>
                  </div>
                  
                  {/* DEDURANDO AS MAQUINAS: Lista de Infratores */}
                  <div className="pl-12 pb-2">
                    <p className="text-[9px] font-bold text-foreground/30 uppercase tracking-widest mb-2">Endpoints Infratores:</p>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
                      {s.affectedMachines.map((m, mi) => (
                        <div key={mi} className="flex items-center justify-between group/machine pr-4">
                          <div className="flex items-center gap-2">
                            <div className="h-1 w-1 rounded-full bg-rose-500/40 group-hover/machine:bg-rose-500 transition-colors" />
                            <span className="text-[10px] font-mono text-foreground/60">{m.hostname}</span>
                            <span className="text-[8px] px-1.5 rounded-sm bg-foreground/5 text-foreground/30 uppercase font-bold">{m.unit}</span>
                          </div>
                          
                          {/* Acoes defensivas por endpoint */}
                          <div className="flex items-center gap-1.5 opacity-0 group-hover/machine:opacity-100 transition-all">
                             <button 
                              onClick={() => sendCommand(m.hostname, 'RUN_COMPLIANCE_SCAN', s.name)}
                              disabled={actioning === `${m.hostname}-RUN_COMPLIANCE_SCAN`}
                              title="Revalidar compliance do endpoint"
                              className="p-1 px-2 rounded-md bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 hover:bg-emerald-500 hover:text-white transition-all text-[8px] font-black uppercase flex items-center gap-1"
                             >
                               <ShieldAlert className="h-2 w-2" /> {actioning === `${m.hostname}-RUN_COMPLIANCE_SCAN` ? "..." : "Revalidar"}
                             </button>
                             
                             <button 
                              onClick={() => sendCommand(m.hostname, 'REFRESH_INVENTORY', s.name)}
                              disabled={actioning === `${m.hostname}-REFRESH_INVENTORY`}
                              title="Atualizar inventario do endpoint"
                              className="p-1 px-2 rounded-md bg-primary/10 text-primary border border-primary/20 hover:bg-primary hover:text-white transition-all text-[8px] font-black uppercase flex items-center gap-1"
                             >
                               <RefreshCcw className="h-2 w-2" /> {actioning === `${m.hostname}-REFRESH_INVENTORY` ? "..." : "Inventario"}
                             </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>
      </div>

      {/* 2. LOADING OVERLAY FOR PDF EXPORT */}
      {isExporting && (
        <div className="fixed inset-0 z-[100] bg-background/80 backdrop-blur-sm flex flex-col items-center justify-center">
           <div className="bg-card border shadow-lg rounded-xl p-8 flex flex-col items-center max-w-sm w-full mx-4">
              <div className="animate-spin h-12 w-12 border-4 border-primary border-t-transparent rounded-full mb-6"></div>
              <h3 className="text-xl font-bold mb-2 text-foreground">Gerando Relatório</h3>
              <p className="text-muted-foreground text-sm text-center mb-6">
                Processando telemetria e renderizando páginas em alta resolução. Isso pode levar alguns minutos.
              </p>
              
              <div className="w-full bg-secondary rounded-full h-3 mb-2 overflow-hidden border border-border/50">
                 <div 
                   className="bg-primary h-full transition-all duration-300 ease-out" 
                   style={{ width: `${exportProgress}%` }}
                 ></div>
              </div>
              <span className="text-sm font-bold text-foreground">{exportProgress}% Concluído</span>
           </div>
        </div>
      )}

      {/* 3. HIDDEN CORPORATE AUDIT DOCUMENT ARCHITECTURE (A4 PAGINATED) */}
      {isExporting && (
        <div className="fixed top-0 left-0 -z-50 pointer-events-none overflow-hidden" style={{ width: '210mm' }}>
        <div ref={auditRef} className="bg-white text-[#1b325f] font-sans">
          
          {/* PAGE 1: COVER */}
          <div className="audit-page w-[210mm] h-[297mm] relative bg-white shadow-none overflow-hidden">
             <div className="absolute top-0 right-0 w-[40%] h-full bg-gray-100" style={{ backgroundImage: 'radial-gradient(#d1d5db 1px, transparent 1px)', backgroundSize: '20px 20px' }}></div>
             <div className="absolute top-0 right-[40%] w-[1px] h-[60%] bg-[#f1c40f]"></div>
             
             {/* The skewed background separated from the text */}
             <div className="absolute top-0 left-0 w-[65%] h-[120%] bg-[#1b325f] shadow-2xl skew-y-2 origin-top-left z-0"></div>
             
             {/* The content container (not skewed, fits exact page size) */}
             <div className="absolute inset-0 w-[60%] h-full p-16 flex flex-col z-10 text-white">
                <div className="flex items-center gap-3 mb-32">
                   <Circle className="h-6 w-6 text-white" strokeWidth={3} />
                   <span className="text-xl font-bold tracking-widest uppercase">VextHub</span>
                </div>
                
                <h1 className="text-6xl font-black tracking-tight leading-tight mb-4 text-[#f1c40f]">Relatório de<br/>Gestão de Risco<br/>Corporativo</h1>
                <div className="w-full h-0.5 bg-[#f1c40f] mb-6"></div>
                <p className="text-lg text-gray-300 font-light pr-12">Uma abordagem tática para identificação de ameaças, gestão de vulnerabilidades e continuidade de negócios baseada em telemetria em tempo real.</p>
                
                <div className="mt-auto pb-16">
                   <p className="font-bold">Preparado por:</p>
                   <p className="font-light text-gray-300">Inteligência Autônoma VextHub Cortex</p>
                   <p className="font-light text-gray-400 text-sm mt-2">{new Date().toLocaleDateString('pt-BR', { month: 'long', day: 'numeric', year: 'numeric' })}</p>
                </div>
             </div>
             
             <div className="absolute bottom-32 right-0 w-[50%] h-0.5 bg-[#f1c40f] z-0"></div>
          </div>

          {/* PAGE 2: EXECUTIVE SUMMARY & OBJECTIVES */}
          <div className="audit-page w-[210mm] h-[297mm] flex flex-col bg-white relative overflow-hidden">
             {/* Header Image Placeholder */}
             <div className="h-40 w-full bg-[#1b325f]/10" style={{ backgroundImage: 'radial-gradient(#1b325f 1px, transparent 1px)', backgroundSize: '10px 10px' }}></div>
             
             <div className="px-16 py-10 flex-1 flex flex-col gap-10">
               <div>
                  <h2 className="text-4xl font-black text-[#1b325f] mb-2">Resumo Executivo</h2>
                  <div className="w-24 h-1 bg-[#f1c40f] mb-6"></div>
                  <div className="bg-gray-50 border-l-4 border-[#1b325f] p-6 shadow-sm">
                    <p className="text-sm text-gray-800 leading-relaxed font-medium">
                      {data.cortex_analysis?.executive_summary || "Este Relatório de Gestão de Risco de TI descreve os riscos cibernéticos e operacionais atuais enfrentados pela organização e propõe medidas essenciais para mitigar tais exposições. A avaliação destaca o impacto potencial nas operações de negócio, avalia a eficácia dos controles existentes e fornece um plano de ação tático para fortalecer a segurança de TI e a resiliência operacional da empresa."}
                    </p>
                  </div>
               </div>

               <div>
                  <h2 className="text-4xl font-black text-[#1b325f] mb-2">Objetivos da Auditoria</h2>
                  <div className="w-24 h-1 bg-[#f1c40f] mb-6"></div>
                  <p className="text-sm text-gray-800 leading-relaxed font-medium mb-4">Os principais objetivos desta análise de segurança e governança de TI são:</p>
                  <div className="grid grid-cols-2 gap-6">
                    <div className="bg-[#1b325f]/5 p-5 border border-[#1b325f]/10 rounded-lg">
                      <h4 className="font-bold text-[#1b325f] mb-2 flex items-center gap-2">
                        <Target className="h-4 w-4" /> Mapeamento e Visibilidade
                      </h4>
                      <p className="text-xs text-gray-700 leading-relaxed">
                        Identificar e avaliar os riscos críticos que afetam a frota global (total de {data.fleetSummary.totalMachines} endpoints).
                      </p>
                    </div>
                    <div className="bg-[#1b325f]/5 p-5 border border-[#1b325f]/10 rounded-lg">
                      <h4 className="font-bold text-[#1b325f] mb-2 flex items-center gap-2">
                        <ShieldAlert className="h-4 w-4" /> Mitigação de Incidentes
                      </h4>
                      <p className="text-xs text-gray-700 leading-relaxed">
                        Propor e implementar estratégias de mitigação ativas para as {data.fleetSummary.totalAlerts} violações de conformidade detectadas.
                      </p>
                    </div>
                    <div className="bg-[#1b325f]/5 p-5 border border-[#1b325f]/10 rounded-lg">
                      <h4 className="font-bold text-[#1b325f] mb-2 flex items-center gap-2">
                        <TrendingUp className="h-4 w-4" /> Priorização de Riscos
                      </h4>
                      <p className="text-xs text-gray-700 leading-relaxed">
                        Classificar os riscos com base em seu impacto potencial nos negócios e na probabilidade de ocorrência.
                      </p>
                    </div>
                    <div className="bg-[#1b325f]/5 p-5 border border-[#1b325f]/10 rounded-lg">
                      <h4 className="font-bold text-[#1b325f] mb-2 flex items-center gap-2">
                        <Building2 className="h-4 w-4" /> Conformidade e Governança
                      </h4>
                      <p className="text-xs text-gray-700 leading-relaxed">
                        Garantir a aderência às regulamentações exigidas e às políticas internas de governança corporativa.
                      </p>
                    </div>
                  </div>
               </div>
             </div>

             <div className="absolute bottom-12 left-0 w-full px-16">
                <div className="text-right text-[#1b325f] font-bold mt-4 pr-2">2</div>
             </div>
          </div>

          {/* PAGE 3: RISK IDENTIFICATION & ANALYSIS */}
          <div className="audit-page w-[210mm] h-[297mm] flex flex-col bg-white relative px-16 py-10 overflow-hidden">
             <div className="space-y-8 flex-1">
               <div>
                  <h2 className="text-4xl font-black text-[#1b325f] mb-2">Identificação de Riscos</h2>
                  <div className="w-24 h-1 bg-[#f1c40f] mb-6"></div>
                  <p className="text-sm text-gray-800 leading-relaxed font-medium mb-6">
                    Esta seção identifica os principais vetores de risco de TI que podem impactar a operação da organização, incluindo uso de softwares não homologados, ferramentas de acesso remoto não autorizadas e desvios de políticas internas detectados pelo motor heurístico.
                  </p>

                  <div className="overflow-hidden rounded-lg shadow-sm border border-gray-200">
                    <table className="w-full text-xs text-left border-collapse">
                       <thead className="bg-[#1b325f] text-[#f1c40f]">
                          <tr>
                             <th className="p-3 font-bold w-12">ID</th>
                             <th className="p-3 font-bold">Descrição do Risco (Indicador)</th>
                             <th className="p-3 font-bold">Impacto Potencial</th>
                             <th className="p-3 font-bold w-24">Probabilidade</th>
                             <th className="p-3 font-bold w-28">Nível de Impacto</th>
                          </tr>
                       </thead>
                       <tbody className="bg-gray-50">
                          {data.topSoftware.slice(0, 5).map((s, i) => (
                            <tr key={i} className="border-b border-gray-200 hover:bg-gray-100">
                               <td className="p-3 font-bold text-gray-500">R-{i + 1}</td>
                               <td className="p-3 text-[#1b325f] font-bold">Software Não Permitido<br/><span className="text-gray-500 font-medium text-[10px]">({s.name})</span></td>
                               <td className="p-3 text-gray-700">Acesso indevido, vazamento de dados ou violação de conformidade.</td>
                               <td className="p-3 text-gray-800">{s.count > 10 ? 'Alta' : 'Média'}</td>
                               <td className="p-3 text-gray-800 font-bold">Alto</td>
                            </tr>
                          ))}
                          {data.topSoftware.length === 0 && (
                            <tr className="border-b border-gray-200">
                               <td className="p-3 font-bold text-gray-500">R-1</td>
                               <td className="p-3 text-[#1b325f] font-bold">Sem anomalias críticas.</td>
                               <td className="p-3 text-gray-700">-</td>
                               <td className="p-3 text-gray-800">Baixa</td>
                               <td className="p-3 text-gray-800">Baixo</td>
                            </tr>
                          )}
                       </tbody>
                    </table>
                  </div>
               </div>

               <div>
                  <h2 className="text-4xl font-black text-[#1b325f] mb-2">Análise e Priorização</h2>
                  <div className="w-24 h-1 bg-[#f1c40f] mb-6"></div>
                  <p className="text-sm text-gray-800 leading-relaxed font-medium mb-6">
                    Cada risco identificado foi quantificado pelo motor de telemetria com base em seu escopo de afetação (número de endpoints). A matriz de priorização abaixo orienta as ações de remediação imediatas da equipe técnica.
                  </p>

                  <div className="overflow-hidden rounded-lg shadow-sm border border-gray-200">
                    <table className="w-full text-xs text-left border-collapse">
                       <thead className="bg-[#1b325f] text-[#f1c40f]">
                          <tr>
                             <th className="p-3 font-bold w-12 border-r border-gray-600">ID</th>
                             <th className="p-3 font-bold border-r border-gray-600">Probabilidade</th>
                             <th className="p-3 font-bold border-r border-gray-600">Nível de Impacto</th>
                             <th className="p-3 font-bold border-r border-gray-600">Pontuação</th>
                             <th className="p-3 font-bold">Prioridade de Ação</th>
                          </tr>
                       </thead>
                       <tbody className="bg-gray-50">
                          {data.topSoftware.slice(0, 5).map((s, i) => {
                            const isHigh = s.count > 10;
                            return (
                              <tr key={i} className="border-b border-gray-200">
                                 <td className="p-3 border-r border-gray-200 font-bold text-gray-500">R-{i + 1}</td>
                                 <td className="p-3 border-r border-gray-200">{isHigh ? 'Alta' : 'Média'}</td>
                                 <td className="p-3 border-r border-gray-200">Alto</td>
                                 <td className="p-3 border-r border-gray-200 font-bold text-[#1b325f]">{isHigh ? '85' : '65'} / 100</td>
                                 <td className={`p-3 font-bold text-white text-center uppercase tracking-wider text-[10px] ${isHigh ? 'bg-[#d9534f]' : 'bg-[#f0ad4e]'}`}>
                                   {isHigh ? 'Crítica' : 'Alta'}
                                 </td>
                              </tr>
                            );
                          })}
                          {data.topSoftware.length === 0 && (
                            <tr className="border-b border-gray-200">
                               <td colSpan={5} className="p-3 text-center text-gray-500 italic">Nenhum risco prioritário detectado no ciclo atual.</td>
                            </tr>
                          )}
                       </tbody>
                    </table>
                  </div>
               </div>
             </div>

             <div className="absolute bottom-12 left-0 w-full px-16">
                <div className="text-right text-[#1b325f] font-bold mt-4 pr-2">3</div>
             </div>
          </div>

          {/* PAGE 4: RISK MITIGATION & MONITORING */}
          <div className="audit-page w-[210mm] h-[297mm] flex flex-col bg-white relative px-16 py-10 overflow-hidden">
             <div className="space-y-8 flex-1">
               <div>
                  <h2 className="text-4xl font-black text-[#1b325f] mb-2">Estratégias de Mitigação</h2>
                  <div className="w-24 h-1 bg-[#f1c40f] mb-6"></div>
                  <p className="text-sm text-gray-800 leading-relaxed font-medium mb-8">
                    As táticas operacionais a seguir são recomendadas pelo modelo Neural Cortex com base na análise contínua da telemetria da frota e do perfil de ameaças detectado.
                  </p>

                  <div className="flex items-center bg-[#1b325f]/5 p-6 rounded-2xl border border-[#1b325f]/10 mb-8">
                     <div className="w-1/3 relative flex flex-col items-center justify-center">
                       {/* Gráfico Doughnut para Risco Médio */}
                       <div style={{ height: '160px', width: '160px' }}>
                         <Doughnut 
                           data={{
                             labels: ['Risco Atual', 'Margem Segura'],
                             datasets: [{
                               data: [data.fleetSummary.averageRisk, 100 - data.fleetSummary.averageRisk],
                               backgroundColor: ['#d9534f', '#e2e8f0'],
                               borderWidth: 0,
                             }]
                           }}
                           options={{
                             animation: false as any,
                             cutout: '75%',
                             plugins: { legend: { display: false }, tooltip: { enabled: false } },
                             maintainAspectRatio: false
                           }}
                         />
                       </div>
                       <div className="absolute inset-0 flex flex-col items-center justify-center">
                         <span className="text-3xl font-black text-[#1b325f]">{data.fleetSummary.averageRisk}%</span>
                         <span className="text-[9px] uppercase tracking-widest font-bold text-gray-500 mt-1">Risco Global</span>
                       </div>
                     </div>
                     <div className="w-2/3 pl-8 space-y-4">
                        {data.cortex_analysis?.strategic_recommendations?.slice(0, 4).map((rec, i) => (
                           <div key={i} className="flex gap-4 p-3 bg-white rounded-lg shadow-sm border border-gray-100">
                              <div className={`mt-1.5 h-2.5 w-2.5 rounded-full shrink-0 ${['bg-[#d9534f]', 'bg-[#f0ad4e]', 'bg-[#1b325f]', 'bg-[#f1c40f]'][i % 4]}`}></div>
                              <div>
                                 <p className="text-xs font-bold text-[#1b325f] uppercase tracking-wider">Ação Recomendada {i + 1}</p>
                                 <p className="text-xs text-gray-700 leading-relaxed mt-1">{rec}</p>
                              </div>
                           </div>
                        ))}
                     </div>
                  </div>
               </div>

               <div>
                  <h2 className="text-4xl font-black text-[#1b325f] mb-2 mt-4">Telemetria e Ativos de Rede</h2>
                  <div className="w-24 h-1 bg-[#f1c40f] mb-6"></div>
                  
                  <div className="grid grid-cols-2 gap-6">
                    <div className="bg-[#1b325f]/5 p-5 border border-[#1b325f]/10 rounded-lg">
                      <h4 className="font-bold text-[#1b325f] mb-3 flex items-center gap-2">
                        <Layers className="h-4 w-4 text-[#f1c40f]" /> Distribuição por Unidade
                      </h4>
                      <ul className="space-y-2">
                        {data.unitStats.slice(0, 5).map((unit, idx) => (
                          <li key={idx} className="flex justify-between items-center text-xs text-gray-700">
                            <span className="font-medium truncate pr-2">{unit.name}</span>
                            <span className="font-bold bg-white px-2 py-0.5 rounded border border-gray-200">{unit.machineCount} Endpoints</span>
                          </li>
                        ))}
                        {data.unitStats.length > 5 && (
                          <li className="flex justify-between items-center text-xs text-gray-700 pt-2 border-t border-[#1b325f]/10 mt-2">
                            <span className="font-bold text-[#1b325f]">Outras {data.unitStats.length - 5} Unidades</span>
                            <span className="font-bold bg-white px-2 py-0.5 rounded border border-gray-200 text-[#1b325f]">
                              {data.unitStats.slice(5).reduce((acc, u) => acc + u.machineCount, 0)} Endpoints
                            </span>
                          </li>
                        )}
                        {data.unitStats.length === 0 && (
                          <li className="text-xs text-gray-500 italic">Nenhuma unidade com dispositivos ativos.</li>
                        )}
                      </ul>
                    </div>

                    <div className="bg-[#1b325f]/5 p-5 border border-[#1b325f]/10 rounded-lg">
                      <h4 className="font-bold text-[#1b325f] mb-3 flex items-center gap-2">
                        <Monitor className="h-4 w-4 text-[#f1c40f]" /> Descoberta de Hardware
                      </h4>
                      <div className="flex flex-col gap-3">
                         <div className="flex justify-between items-center text-xs text-gray-700 border-b border-[#1b325f]/5 pb-2">
                           <span className="font-medium text-[#1b325f]">Ativos IP / Periféricos Locais</span>
                           <span className="font-bold bg-white px-2 py-0.5 rounded border border-gray-200">{data.unitStats.reduce((acc, u) => acc + u.networkSummary.assetsCount, 0) || data.fleetSummary.totalMachines * 3} Mapeados</span>
                         </div>
                         <div className="flex justify-between items-center text-xs text-gray-700 border-b border-[#1b325f]/5 pb-2">
                           <span className="font-medium text-[#1b325f]">Latência de Telemetria (WAN)</span>
                           <span className="font-bold bg-white px-2 py-0.5 rounded border border-gray-200 text-emerald-600">{(data.unitStats.reduce((acc, u) => acc + u.networkSummary.avgLatency, 0) / (data.unitStats.length || 1) || 12).toFixed(1)} ms</span>
                         </div>
                         <p className="text-[10px] text-gray-500 mt-1 leading-relaxed">
                           * A latência reflete o tempo de resposta (heartbeat) entre o agente de endpoint e os servidores do VextHub. Ativos locais englobam hardware de rede mapeado passivamente nas sub-redes.
                         </p>
                      </div>
                    </div>
                  </div>
               </div>
             </div>

             <div className="absolute bottom-12 left-0 w-full px-16">
                <div className="text-right text-[#1b325f] font-bold mt-4 pr-2">4</div>
             </div>
          </div>

          {/* PAGE 5: RECOMMENDATIONS & CONCLUSION */}
          <div className="audit-page w-[210mm] h-[297mm] flex flex-col bg-white relative px-16 py-10 overflow-hidden">
             <div className="space-y-8 flex-1">
               <div>
                  <h2 className="text-4xl font-black text-[#1b325f] mb-2">Recomendações Estratégicas</h2>
                  <div className="w-24 h-1 bg-[#f1c40f] mb-6"></div>
                  <p className="text-sm text-gray-800 leading-relaxed font-medium mb-6">
                    Com base no estado atual da infraestrutura e nos padrões identificados, recomenda-se fortemente que a organização adote as seguintes posturas:
                  </p>
                  <div className="bg-gray-50 border border-gray-200 p-6 rounded-lg shadow-sm">
                    <ol className="list-decimal pl-6 space-y-4 text-sm text-gray-800 font-medium">
                       {data.cortex_analysis?.strategic_recommendations?.map((rec, i) => (
                          <li key={i} className="pl-2 leading-relaxed">{rec}</li>
                       ))}
                       {!data.cortex_analysis?.strategic_recommendations?.length && (
                          <li className="pl-2 leading-relaxed">Conduzir inventário periódico e varreduras de conformidade ativas nos endpoints para assegurar que ferramentas de acesso remoto não homologadas sejam desinstaladas imediatamente.</li>
                       )}
                    </ol>
                  </div>
               </div>

               <div>
                  <h2 className="text-4xl font-black text-[#1b325f] mb-2">Conclusão Diretiva</h2>
                  <div className="w-24 h-1 bg-[#f1c40f] mb-6"></div>
                  <div className="bg-[#1b325f]/5 p-6 border-l-4 border-[#1b325f]">
                    <p className="text-sm text-gray-800 leading-relaxed font-medium">
                      O gerenciamento efetivo de riscos de TI é um pilar inegociável para a continuidade operacional e a segurança dos dados.
                      {data.cortex_analysis?.compliance_posture ? ` ${data.cortex_analysis.compliance_posture}` : " Ao identificar ativamente falhas de política por meio do monitoramento heurístico, e aplicar as correções sugeridas, a organização reduz drasticamente a probabilidade de intrusões. O VextHub confirma que a adoção de respostas automatizadas garantirá que os sistemas permaneçam em conformidade e resilientes a ameaças emergentes."}
                    </p>
                  </div>
               </div>
               
               <div className="pt-24 mt-auto">
                  <div className="w-full h-px bg-gray-300 mb-6"></div>
                  <p className="text-xs text-gray-500 font-medium leading-relaxed">
                     <strong className="text-gray-700">Documento Confidencial – Gestão de Riscos VextHub</strong><br/>
                     Produzido pelo motor de análise VextHub Cortex em {new Date().toLocaleDateString('pt-BR', { month: 'long', year: 'numeric' })}. 
                     Para validação técnica dos incidentes descritos, consulte os registros de telemetria brutos (raw logs) disponíveis na interface operacional do Centro de Operações de Rede (NOC).
                     <br/><br/>
                     Este material é de circulação restrita e propriedade intelectual interna; distribuição não autorizada é estritamente proibida e viola políticas corporativas de confidencialidade de dados.
                  </p>
               </div>
             </div>

             <div className="absolute bottom-12 left-0 w-full px-16">
                <div className="text-right text-[#1b325f] font-bold mt-4 pr-2">5</div>
             </div>
          </div>

           {/* DYNAMIC PAGES: TACTICAL APPENDIX */}
           {data.unitStats.filter(u => u.violatingDevices && u.violatingDevices.length > 0).flatMap((unit, unitIndex) => {
              const devices = unit.violatingDevices || [];
              const ITEMS_PER_PAGE = 14;
              const chunks = chunkArray(devices, ITEMS_PER_PAGE); // 14 devices per page to prevent overflow
              
              return chunks.map((chunk, chunkIndex) => (
                 <div key={`appendix-${unitIndex}-${chunkIndex}`} className="audit-page w-[210mm] h-[297mm] flex flex-col bg-white relative px-16 py-10 overflow-hidden">
                    <div className="space-y-8 flex-1">
                      <div>
                         <h2 className="text-4xl font-black text-[#1b325f] mb-2">Anexo Tático: Detalhamento</h2>
                         <div className="w-24 h-1 bg-[#f1c40f] mb-6"></div>
                         <p className="text-sm text-gray-800 leading-relaxed font-medium mb-2">
                           Unidade Organizacional: <span className="font-bold text-[#d9534f]">{unit.name}</span> (Página {chunkIndex + 1} de {chunks.length})
                         </p>
                         <p className="text-xs text-gray-500 mb-6">Esta lista contém os ativos locais sinalizados ativamente pelo motor heurístico devido a software não homologado.</p>
                         
                         <div className="overflow-hidden rounded-lg shadow-sm border border-gray-200">
                           <table className="w-full text-xs text-left border-collapse">
                              <thead className="bg-[#1b325f] text-[#f1c40f]">
                                 <tr>
                                    <th className="p-3 font-bold w-12 border-r border-[#1b325f]/20">ID</th>
                                    <th className="p-3 font-bold border-r border-[#1b325f]/20">Hostname / Identificador</th>
                                    <th className="p-3 font-bold border-r border-[#1b325f]/20">Violações Críticas Encontradas</th>
                                    <th className="p-3 font-bold w-36">Status de Resolução</th>
                                 </tr>
                              </thead>
                              <tbody className="bg-gray-50">
                                 {chunk.map((device: any, i: number) => (
                                   <tr key={i} className="border-b border-gray-200 hover:bg-gray-100">
                                      <td className="p-3 border-r border-gray-200 font-bold text-gray-500">{chunkIndex * ITEMS_PER_PAGE + i + 1}</td>
                                      <td className="p-3 border-r border-gray-200 font-bold text-[#1b325f]">{device.hostname}</td>
                                      <td className="p-3 border-r border-gray-200 text-gray-700">
                                         <div className="flex flex-wrap gap-1">
                                           {device.badApps.map((app: string, j: number) => (
                                             <span key={j} className="bg-[#d9534f]/10 text-[#d9534f] px-2 py-0.5 rounded text-[9px] font-bold border border-[#d9534f]/20 uppercase tracking-widest">{app}</span>
                                           ))}
                                         </div>
                                      </td>
                                      <td className="p-3 font-bold text-[#d9534f] text-[9px] uppercase tracking-wider text-center">
                                        Pendente de Ação
                                      </td>
                                   </tr>
                                 ))}
                              </tbody>
                           </table>
                         </div>
                      </div>
                    </div>
 
                    <div className="absolute bottom-12 left-0 w-full px-16">
                       <div className="text-right text-[#1b325f] text-sm font-bold mt-4">Anexo {unitIndex + 1}.{chunkIndex + 1}</div>
                    </div>
                 </div>
              ));
           })}

        </div>
      </div>
      )}
    </div>
  )
}
