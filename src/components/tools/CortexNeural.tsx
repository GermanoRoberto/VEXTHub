"use client"

import React, { useState, useEffect, useRef } from 'react'
import { 
  Brain, 
  Terminal, 
  Send, 
  Sparkles, 
  Zap, 
  RefreshCw
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

type Message = {
  id: number
  type: 'user' | 'ia'
  text: string
  timestamp: string
  playbooks?: string[]
}

type Insight = {
  title: string
  value: string
  detail: string
  tone: 'neural' | 'danger' | 'warning' | 'accent' | 'neutral'
}

export function CortexNeural() {
  const [command, setCommand] = useState('')
  const [processing, setProcessing] = useState(false)
  const [history, setHistory] = useState<Message[]>([
    {
      id: 1,
      type: 'ia',
      text: 'Cortex Neural online. Contexto local carregado: endpoints, eventos, frameworks de governanca, relatorios e fila de acoes seguras. Envie uma pergunta operacional.',
      timestamp: 'LOCAL_SYNC',
    },
  ])
  const [insights, setInsights] = useState<Insight[]>([
    {
      title: 'Frota',
      value: '---',
      detail: 'Aguardando consulta ao contexto',
      tone: 'neutral'
    },
    {
      title: 'Fila de AÃ§Ãµes',
      value: '0',
      detail: 'Comandos pendentes no agente',
      tone: 'accent'
    }
  ])

  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [history])

  const processCommand = async () => {
    if (!command.trim() || processing) return

    const userPrompt = command
    setCommand('')
    const userMsg: Message = {
      id: Date.now(),
      type: 'user',
      text: userPrompt,
      timestamp: new Date().toLocaleTimeString('pt-BR'),
    }

    setHistory(prev => [...prev, userMsg])
    setProcessing(true)

    try {
      const response = await fetch('/api/neural/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userPrompt })
      })
      
      if (!response.ok) throw new Error('Falha no uplink')
      
      const data = await response.json()
      
      const iaMsg: Message = {
        id: Date.now() + 1,
        type: 'ia',
        text: data.response,
        timestamp: new Date().toLocaleTimeString('pt-BR'),
        playbooks: data.suggested_playbooks
      }
      setHistory(prev => [...prev, iaMsg])
      
      if (data.tactical_context?.insight_cards) {
        setInsights(data.tactical_context.insight_cards)
      }
    } catch {
      setHistory(prev => [...prev, {
        id: Date.now() + 1,
        type: 'ia',
        text: 'ERRO: Uplink com o nÃºcleo tÃ¡tico falhou. Verifique se o servidor API estÃ¡ rodando.',
        timestamp: new Date().toLocaleTimeString('pt-BR'),
      }])
    } finally {
      setProcessing(false)
    }
  }

  const executePlaybook = async (pb: string) => {
    try {
      const response = await fetch('/api/playbooks/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ playbook_id: pb, scope: 'all' })
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || data.error || 'Falha ao registrar playbook')

      setHistory(prev => [...prev, {
        id: Date.now(),
        type: 'ia',
        text: `Playbook ${pb} registrado para triagem. Evento: ${data.event_id || data.id || 'sem id retornado'}.`,
        timestamp: new Date().toLocaleTimeString('pt-BR'),
      }])
    } catch (error: any) {
      setHistory(prev => [...prev, {
        id: Date.now(),
        type: 'ia',
        text: `Falha ao registrar playbook ${pb}: ${error.message}`,
        timestamp: new Date().toLocaleTimeString('pt-BR'),
      }])
    }
  }

  return (
    <div className="h-[calc(100vh-140px)] flex flex-col lg:flex-row gap-8 animate-in zoom-in-95 duration-700">
      {/* Main Chat Area */}
      <div className="flex-1 glass-card flex flex-col p-0 overflow-hidden relative border-foreground/10">
        <header className="p-8 bg-foreground/[0.02] border-b border-foreground/5 flex items-center justify-between gap-4">
          <div className="flex items-center gap-5">
            <div className="w-16 h-16 rounded-[2rem] bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shadow-[0_0_30px_rgba(124,58,237,0.15)] backdrop-blur-md transition-all group hover:scale-105">
              <Brain className="h-9 w-9" />
            </div>
            <div>
              <h3 className="text-2xl font-black tracking-tighter text-foreground uppercase">Cortex <span className="text-primary italic">Neural</span></h3>
              <p className="text-[10px] font-black text-foreground/30 uppercase tracking-[0.2em] mt-1">SincronizaÃ§Ã£o de Telemetria SOC</p>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2">
            <div className="px-5 py-2 rounded-full border border-primary/20 bg-primary/[0.05] text-primary flex items-center gap-2.5 shadow-lg shadow-primary/5">
              <span className="w-2 h-2 rounded-full bg-primary shadow-[0_0_12px_rgba(124,58,237,0.6)] animate-pulse"></span>
              <span className="text-[9px] font-black uppercase tracking-[0.2em]">HeurÃ­stica Ativa</span>
            </div>
          </div>
        </header>

        <div ref={scrollRef} className="flex-1 overflow-y-auto p-10 space-y-8 hide-scrollbar bg-black/5">
          <AnimatePresence initial={false}>
            {history.map((msg) => (
              <motion.div 
                key={msg.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className={`flex ${msg.type === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div className={`max-w-[85%] flex flex-col ${msg.type === 'user' ? 'items-end' : 'items-start'} gap-2.5`}>
                  <span className="text-[9px] font-bold uppercase tracking-widest text-muted-foreground/50 mx-2">
                    {msg.type === 'ia' ? 'CORTEX NEURAL' : 'OPERADOR SOC'} â€¢ {msg.timestamp}
                  </span>
                  <div className={`px-6 py-4 rounded-[--radius-tactical] text-[13px] leading-relaxed font-medium ${
                    msg.type === 'ia' 
                      ? 'bg-white/5 border border-white/10 text-white/90 shadow-xl' 
                      : 'bg-primary text-white font-bold shadow-xl shadow-primary/10'
                  }`}>
                    {msg.text}
                  </div>

                  {msg.playbooks && (
                    <div className="flex gap-2.5 mt-2 flex-wrap">
                      {msg.playbooks.map((pb, i) => (
                        <button
                          key={i}
                          onClick={() => executePlaybook(pb)}
                          className="px-4 py-2 rounded-[--radius-tactical] border border-primary/30 bg-primary/5 text-primary text-[10px] font-bold uppercase hover:bg-primary hover:text-white transition-all shadow-lg flex items-center gap-2"
                        >
                          <Zap className="h-3 w-3" />
                          <span>Executar: {pb}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
          </AnimatePresence>

          {processing && (
            <div className="flex justify-start">
              <div className="bg-white/5 border border-white/10 px-6 py-4 rounded-[--radius-tactical] flex items-center gap-5 shadow-xl">
                <RefreshCw className="h-4 w-4 text-primary animate-spin" />
                <span className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">Processando diretriz...</span>
              </div>
            </div>
          )}
        </div>

        <footer className="p-8 bg-foreground/[0.02] border-t border-foreground/5">
          <div className="relative group">
            <div className="relative flex items-center gap-4 glass-card bg-foreground/[0.03] border border-foreground/10 rounded-[1.5rem] p-2 pl-6 focus-within:border-primary/40 transition-all shadow-inner">
              <Terminal className="h-5 w-5 text-primary opacity-40" />
              <input
                value={command}
                onChange={(e) => setCommand(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && processCommand()}
                type="text"
                placeholder="Consultar motor neural..."
                className="flex-1 bg-transparent border-none outline-none py-4 text-sm font-bold placeholder:text-foreground/20 text-foreground"
              />
              <button
                onClick={processCommand}
                disabled={processing || !command.trim()}
                className="w-14 h-14 rounded-2xl bg-primary text-white flex items-center justify-center hover:scale-[1.02] active:scale-95 transition-all disabled:opacity-20 shadow-xl shadow-primary/20"
              >
                <Send className="h-6 w-6" />
              </button>
            </div>
          </div>
        </footer>
      </div>

      {/* Sidebar Insights */}
      <div className="lg:w-80 space-y-6">
        <div className="glass-card border-foreground/10 bg-foreground/[0.02] p-8">
          <div className="flex items-center gap-4 mb-8">
            <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center text-primary border border-primary/20">
              <Sparkles className="h-6 w-6" />
            </div>
            <h4 className="text-[10px] font-black uppercase tracking-[0.2em] text-foreground/40">Briefing DinÃ¢mico</h4>
          </div>

          <div className="space-y-4">
            {insights.map((card, i) => (
              <div 
                key={i} 
                className={`p-6 glass-card bg-foreground/[0.03] rounded-2xl border-l-4 transition-all hover:scale-[1.02] ${
                  card.tone === 'danger' ? 'border-rose-500' : 
                  card.tone === 'warning' ? 'border-amber-400' : 
                  card.tone === 'neural' ? 'border-primary' : 
                  card.tone === 'accent' ? 'border-emerald-500' : 'border-foreground/10'
                }`}
              >
                <p className="text-[9px] font-black uppercase tracking-widest mb-2 text-foreground/30">{card.title}</p>
                <p className={`text-2xl font-black ${
                  card.tone === 'danger' ? 'text-rose-500' : 
                  card.tone === 'warning' ? 'text-amber-200' : 
                  card.tone === 'neural' ? 'text-primary' : 
                  card.tone === 'accent' ? 'text-emerald-500' : 'text-foreground'
                }`}>{card.value}</p>
                <p className="text-[10px] text-foreground/40 leading-relaxed font-bold mt-2">{card.detail}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="apex-card border-white/10 bg-gradient-to-br from-primary/5 to-transparent p-8">
          <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground mb-4">MemÃ³ria de Contexto</p>
          <div className="p-4 bg-black/20 rounded-[--radius-tactical] border border-white/5">
            <pre className="text-[9px] font-mono text-muted-foreground/70 leading-tight overflow-x-auto">
              {JSON.stringify({ status: 'LOCAL_CONTEXT', sources: ['simulation_state', 'agent_commands', 'events', 'governance_frameworks'], mode: 'defensive' }, null, 2)}
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}

