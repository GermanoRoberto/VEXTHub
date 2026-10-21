"use client"

import React, { createContext, useContext, useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { CheckCircle2, AlertCircle, Info, X, Zap } from 'lucide-react'

type ToastType = 'success' | 'error' | 'info' | 'tactical'

interface Toast {
  id: string
  message: string
  type: ToastType
}

interface ToastContextType {
  toast: {
    success: (msg: string) => void
    error: (msg: string) => void
    info: (msg: string) => void
    tactical: (msg: string) => void
  }
}

const ToastContext = createContext<ToastContextType | undefined>(undefined)

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const addToast = useCallback((message: string, type: ToastType) => {
    const id = Math.random().toString(36).substring(2, 9)
    setToasts((prev) => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, 5000)
  }, [])

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const toast = {
    success: (msg: string) => addToast(msg, 'success'),
    error: (msg: string) => addToast(msg, 'error'),
    info: (msg: string) => addToast(msg, 'info'),
    tactical: (msg: string) => addToast(msg, 'tactical'),
  }

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      <div className="fixed bottom-8 right-8 z-[100] flex flex-col gap-3 pointer-events-none">
        <AnimatePresence>
          {toasts.map((t) => (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, x: 20, scale: 0.9 }}
              animate={{ opacity: 1, x: 0, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9, transition: { duration: 0.2 } }}
              className="pointer-events-auto"
            >
              <div className={`
                flex items-center gap-4 px-6 py-4 rounded-[--radius-tactical] 
                bg-card/90 backdrop-blur-xl border-l-4 shadow-2xl min-w-[320px] max-w-md
                ${t.type === 'success' ? 'border-emerald-500 shadow-emerald-500/10' : 
                  t.type === 'error' ? 'border-rose-500 shadow-rose-500/10' : 
                  t.type === 'tactical' ? 'border-primary shadow-primary/20 bg-primary/5' :
                  'border-blue-500 shadow-blue-500/10'}
              `}>
                <div className={`
                  flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center
                  ${t.type === 'success' ? 'bg-emerald-500/20 text-emerald-500' : 
                    t.type === 'error' ? 'bg-rose-500/20 text-rose-500' : 
                    t.type === 'tactical' ? 'bg-primary/20 text-primary' :
                    'bg-blue-500/20 text-blue-500'}
                `}>
                  {t.type === 'success' && <CheckCircle2 className="h-4 w-4" />}
                  {t.type === 'error' && <AlertCircle className="h-4 w-4" />}
                  {t.type === 'info' && <Info className="h-4 w-4" />}
                  {t.type === 'tactical' && <Zap className="h-4 w-4" />}
                </div>
                
                <div className="flex-1">
                  <p className="text-[10px] font-black uppercase tracking-widest text-foreground/40 mb-1">
                    {t.type === 'tactical' ? 'Protocolo Sistema' : 'Notificação'}
                  </p>
                  <p className="text-sm font-semibold text-foreground/90 leading-tight">
                    {t.message}
                  </p>
                </div>

                <button 
                  onClick={() => removeToast(t.id)}
                  className="text-foreground/20 hover:text-foreground/60 transition-colors"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              
              {/* Tactical scanline effect for premium feel */}
              {t.type === 'tactical' && (
                <div className="absolute inset-0 pointer-events-none overflow-hidden rounded-[--radius-tactical]">
                  <div className="absolute inset-0 bg-gradient-to-b from-primary/0 via-primary/5 to-primary/0 animate-scanline" />
                </div>
              )}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  const context = useContext(ToastContext)
  if (context === undefined) {
    throw new Error('useToast must be used within a ToastProvider')
  }
  return context.toast
}
