"use client"

import React, { useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import {
  X,
  RefreshCcw,
  ShieldCheck,
  Building2,
  Globe,
  Loader2,
  AlertCircle,
  CheckCircle2,
  UploadCloud,
} from "lucide-react"

interface CommandCenterProps {
  isOpen: boolean
  onClose: () => void
  currentUnit?: string
}

const safeActions = [
  {
    id: "REFRESH_INVENTORY",
    label: "Atualizar inventario",
    description: "Solicita nova coleta defensiva de software e dados basicos do endpoint.",
    icon: RefreshCcw,
  },
  {
    id: "RUN_COMPLIANCE_SCAN",
    label: "Revalidar compliance",
    description: "Marca os endpoints para revalidacao de politicas no proximo pulso.",
    icon: ShieldCheck,
  },
  {
    id: "UPDATE_AGENT",
    label: "Sincronizar agente",
    description: "Reserva a acao para atualizacoes assinadas e publicadas pelo VextHub.",
    icon: UploadCloud,
  },
]

export function CommandCenter({ isOpen, onClose, currentUnit }: CommandCenterProps) {
  const [scope, setScope] = useState<"ALL" | "UNIT">(currentUnit ? "UNIT" : "ALL")
  const [commandType, setCommandType] = useState("REFRESH_INVENTORY")
  const [targetNote, setTargetNote] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [status, setStatus] = useState<{ type: "success" | "error"; message: string } | null>(null)

  const handleDispatch = async () => {
    setIsLoading(true)
    setStatus(null)

    try {
      const response = await fetch("/api/agent/commands/enqueue/broadcast", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_audience: scope,
          unit_name: currentUnit,
          command_type: commandType,
          target_script: targetNote,
        }),
      })

      const data = await response.json()
      if (response.ok) {
        setStatus({ type: "success", message: data.message })
        setTargetNote("")
      } else {
        throw new Error(data.error || "Erro ao enfileirar acao")
      }
    } catch (err: any) {
      setStatus({ type: "error", message: err.message })
    } finally {
      setIsLoading(false)
    }
  }

  if (!isOpen) return null

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        />

        <motion.div
          initial={{ scale: 0.97, opacity: 0, y: 16 }}
          animate={{ scale: 1, opacity: 1, y: 0 }}
          exit={{ scale: 0.97, opacity: 0, y: 16 }}
          className="relative w-full max-w-xl bg-background border border-foreground/10 rounded-lg shadow-2xl overflow-hidden flex flex-col"
        >
          <div className="p-6 border-b border-foreground/10 bg-foreground/[0.02] flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="h-11 w-11 rounded-lg bg-emerald-500/10 flex items-center justify-center border border-emerald-500/20">
                <ShieldCheck className="h-6 w-6 text-emerald-500" />
              </div>
              <div>
                <h2 className="text-lg font-bold tracking-tight">Acoes Seguras</h2>
                <p className="text-xs text-foreground/45 mt-0.5">Execucao restrita por allowlist e auditoria.</p>
              </div>
            </div>
            <button onClick={onClose} className="p-2 hover:bg-foreground/5 rounded-lg transition-colors">
              <X className="h-5 w-5 text-foreground/50" />
            </button>
          </div>

          <div className="p-6 space-y-6 overflow-y-auto">
            <div className="space-y-3">
              <label className="text-[11px] font-bold uppercase tracking-[0.16em] text-foreground/40 px-1">Escopo</label>
              <div className="grid grid-cols-2 gap-3">
                <button
                  onClick={() => setScope("ALL")}
                  className={`p-4 rounded-lg border transition-all flex items-center gap-3 ${scope === "ALL" ? "bg-primary/10 border-primary/40" : "bg-foreground/[0.02] border-foreground/10 hover:border-foreground/20"}`}
                >
                  <Globe className={`h-5 w-5 ${scope === "ALL" ? "text-primary" : "text-foreground/35"}`} />
                  <span className="text-sm font-semibold">Todos</span>
                </button>
                <button
                  onClick={() => setScope("UNIT")}
                  className={`p-4 rounded-lg border transition-all flex items-center gap-3 ${scope === "UNIT" ? "bg-indigo-500/10 border-indigo-500/40" : "bg-foreground/[0.02] border-foreground/10 hover:border-foreground/20"}`}
                >
                  <Building2 className={`h-5 w-5 ${scope === "UNIT" ? "text-indigo-400" : "text-foreground/35"}`} />
                  <span className="text-sm font-semibold truncate">Unidade {currentUnit ? `(${currentUnit})` : ""}</span>
                </button>
              </div>
            </div>

            <div className="space-y-3">
              <label className="text-[11px] font-bold uppercase tracking-[0.16em] text-foreground/40 px-1">Acao</label>
              <div className="space-y-2">
                {safeActions.map((action) => (
                  <button
                    key={action.id}
                    onClick={() => setCommandType(action.id)}
                    className={`w-full p-4 rounded-lg border text-left transition-all flex items-start gap-3 ${commandType === action.id ? "bg-emerald-500/10 border-emerald-500/30" : "bg-foreground/[0.02] border-foreground/10 hover:border-foreground/20"}`}
                  >
                    <action.icon className={`h-5 w-5 mt-0.5 ${commandType === action.id ? "text-emerald-500" : "text-foreground/35"}`} />
                    <span>
                      <span className="block text-sm font-semibold">{action.label}</span>
                      <span className="block text-xs text-foreground/45 mt-1 leading-relaxed">{action.description}</span>
                    </span>
                  </button>
                ))}
              </div>
            </div>

            <div className="space-y-3">
              <label className="text-[11px] font-bold uppercase tracking-[0.16em] text-foreground/40 px-1">Referencia opcional</label>
              <input
                value={targetNote}
                onChange={(event) => setTargetNote(event.target.value)}
                placeholder="Ex.: politica, software ou ticket relacionado"
                maxLength={160}
                className="w-full h-11 px-3 bg-foreground/[0.03] border border-foreground/10 rounded-lg text-sm outline-none focus:border-primary/40"
              />
            </div>

            {status && (
              <motion.div
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                className={`p-4 rounded-lg flex items-start gap-3 ${status.type === "success" ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-500" : "bg-rose-500/10 border border-rose-500/20 text-rose-500"}`}
              >
                {status.type === "success" ? <CheckCircle2 className="h-4 w-4 mt-0.5" /> : <AlertCircle className="h-4 w-4 mt-0.5" />}
                <p className="text-xs font-medium">{status.message}</p>
              </motion.div>
            )}
          </div>

          <div className="p-6 bg-foreground/[0.02] border-t border-foreground/10 flex items-center justify-end">
            <button
              onClick={handleDispatch}
              disabled={isLoading}
              className="px-6 py-3 rounded-lg bg-emerald-600 text-white text-xs font-bold uppercase tracking-widest hover:bg-emerald-700 transition-all disabled:opacity-50 flex items-center gap-3"
            >
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
              {isLoading ? "Enfileirando..." : "Enfileirar Acao"}
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  )
}
