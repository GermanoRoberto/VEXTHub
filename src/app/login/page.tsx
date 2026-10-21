"use client"

import { useState, useEffect } from 'react'
import { createClient } from '@/utils/supabase/client'
import { useRouter } from 'next/navigation'
import { motion } from 'framer-motion'
import { Zap, ShieldCheck, ArrowRight, Loader2 } from 'lucide-react'

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const router = useRouter()
  const supabase = createClient()
  const [companyName, setCompanyName] = useState('')

  useEffect(() => {
    let isMounted = true
    fetch('/api/config')
      .then(res => res.json())
      .then(data => {
        if (isMounted && data.company_name) setCompanyName(data.company_name)
      })
      .catch(() => {})
    return () => {
      isMounted = false
    }
  }, [])

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    
    const { error } = await supabase.auth.signInWithPassword({
      email,
      password,
    })

    if (error) {
      setError(error.message)
      setLoading(false)
    } else {
      router.push('/dashboard')
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4 relative overflow-hidden">
      {/* Background Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-primary/20 rounded-full blur-[120px] pointer-events-none" />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md glass-card p-10 rounded-3xl border border-foreground/5 shadow-2xl relative z-10"
      >
        <div className="flex flex-col items-center mb-10">
          <div className="h-14 w-14 rounded-2xl bg-primary flex items-center justify-center shadow-xl shadow-primary/20 mb-6">
            <Zap className="text-primary-foreground h-8 w-8" />
          </div>
          <h1 className="text-3xl font-bold tracking-tight">
            {companyName ? `Dashboard ${companyName}` : 'Bem-vindo ao Dashboard'}
          </h1>
          <p className="text-foreground/40 text-sm mt-2 text-center">Entre com suas credenciais para gerenciar a frota tática.</p>
        </div>

        <form onSubmit={handleLogin} className="space-y-6">
          <div className="space-y-2">
            <label className="text-xs font-semibold text-foreground/60 uppercase tracking-widest pl-1">E-mail</label>
            <input
              type="email"
              placeholder="seu@email.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-5 py-4 rounded-xl bg-foreground/5 border border-foreground/10 focus:border-primary/50 focus:bg-foreground/[0.08] transition-all outline-none text-sm"
              required
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-semibold text-foreground/60 uppercase tracking-widest pl-1">Senha</label>
            <input
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-5 py-4 rounded-xl bg-foreground/5 border border-foreground/10 focus:border-primary/50 focus:bg-foreground/[0.08] transition-all outline-none text-sm"
              required
            />
          </div>

          {error && (
            <motion.p
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-xs text-rose-500 font-medium bg-rose-500/10 p-3 rounded-lg border border-rose-500/20"
            >
              {error}
            </motion.p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-4 rounded-xl bg-primary text-primary-foreground font-bold text-sm shadow-lg shadow-primary/30 hover:scale-[1.02] active:scale-[0.98] transition-all flex items-center justify-center gap-2 group"
          >
            {loading ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <>
                Acessar Terminal
                <ArrowRight className="h-4 w-4 group-hover:translate-x-1 transition-transform" />
              </>
            )}
          </button>
        </form>

        <div className="mt-10 pt-6 border-t border-foreground/5 flex items-center justify-center gap-2 text-foreground/40">
          <ShieldCheck className="h-4 w-4 text-emerald-500/60" />
          <p className="text-[10px] text-foreground/40 font-medium uppercase tracking-widest">Conexão Criptografada (TLS 1.3)</p>
        </div>
      </motion.div>
    </div>
  )
}
