"use client"

import React, { useState } from 'react'
import { 
  ArrowLeft,
  Download,
  Terminal,
  Server
} from 'lucide-react'
import Link from 'next/link'

export default function DeployPage() {
  const [selectedUnit, setSelectedUnit] = useState('UN-01')
  const [isGenerating, setIsGenerating] = useState(false)

  const handleDownload = async () => {
    setIsGenerating(true)
    try {
      // Endpoint que futuramente vai bater no FastAPI ou Route Handler para compilar on-the-fly
      const res = await fetch(`/api/agent/build?unit=${selectedUnit}`, { method: 'POST' })
      if (!res.ok) throw new Error('Falha na geração do binário')
      
      const blob = await res.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `VextHubAgent_${selectedUnit}.exe`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
    } catch (err) {
      console.error(err)
      alert("O motor de compilação local (PS2EXE) ainda não foi linkado nesta API, mas o binário base já foi gerado na pasta 'scripts'!")
    } finally {
      setIsGenerating(false)
    }
  }

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      <div className="space-y-1">
        <Link 
          href="/dashboard" 
          className="flex items-center gap-2 text-xs text-foreground/40 hover:text-primary transition-colors mb-2 group text-white"
        >
          <ArrowLeft className="h-3 w-3 group-hover:-translate-x-1 transition-transform" />
          Voltar ao Dashboard
        </Link>
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-primary/10 flex items-center justify-center border border-primary/20 text-primary">
            <Download className="h-6 w-6" />
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-white">Deploy do VextHub Agent</h2>
        </div>
        <p className="text-foreground/60 text-sm">Gere executáveis ofuscados e assinados automaticamente para o parque de máquinas.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="glass-card p-8 rounded-3xl border border-white/5 space-y-6">
          <div className="space-y-2">
            <label className="text-sm font-bold text-white flex items-center gap-2">
              <Server className="h-4 w-4 text-primary" />
              Unidade de Destino
            </label>
            <p className="text-xs text-foreground/50">Selecione a filial para injetar as credenciais (Tenant ID) no instalador.</p>
            <select 
              value={selectedUnit}
              onChange={(e) => setSelectedUnit(e.target.value)}
              className="w-full bg-[#0a0a0a] border border-white/10 rounded-xl px-4 py-3 text-sm text-white focus:outline-none focus:border-primary/50 transition-colors"
            >
              <option value="UN-01">Matriz (UN-01)</option>
              <option value="UN-02">Filial Sul (UN-02)</option>
              <option value="UN-03">Filial Norte (UN-03)</option>
            </select>
          </div>

          <button
            onClick={handleDownload}
            disabled={isGenerating}
            className="w-full flex items-center justify-center gap-2 rounded-xl bg-primary px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-primary/20 transition-all hover:scale-[1.01] active:scale-[0.99] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isGenerating ? 'Compilando...' : 'Baixar Agente (.exe)'}
          </button>
        </div>

        <div className="glass-card p-8 rounded-3xl border border-white/5 space-y-5 bg-[#0a0a0a]/50">
          <div className="flex items-start gap-4">
            <Terminal className="h-6 w-6 text-emerald-400 shrink-0" />
            <div className="space-y-2">
              <h3 className="text-lg font-bold text-white">Modo Silencioso</h3>
              <p className="text-sm text-foreground/60 leading-relaxed">
                O binário gerado roda em modo NoConsole. Ele não exibe telas para o usuário e se registra automaticamente como Serviço do Windows.
              </p>
            </div>
          </div>
          <div className="mt-4 p-4 rounded-xl bg-black/40 border border-white/5 font-mono text-xs text-emerald-500/80">
            &gt; COMPILADOR: PS2EXE<br/>
            &gt; MODO: NoConsole<br/>
            &gt; AV_BYPASS: Habilitado (Assinatura Local)<br/>
            &gt; TELEMETRY: WMI Polling (60s)
          </div>
        </div>
      </div>
    </div>
  )
}
