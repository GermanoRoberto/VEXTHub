"use client"

import React from 'react'
import { 
  User, 
  Mail, 
  Shield, 
  Clock, 
  LogOut, 
  Key, 
  Bell, 
  Activity,
  UserCircle
} from 'lucide-react'
import { useRouter } from 'next/navigation'
import { createClient } from '@/utils/supabase/client'

export default function ProfilePage() {
  const router = useRouter()
  const [user, setUser] = React.useState<any>(null)

  React.useEffect(() => {
    async function getProfile() {
      const supabase = createClient()
      const { data: { user: currentUser } } = await supabase.auth.getUser()
      setUser(currentUser)
    }
    getProfile()
  }, [])

  const handleLogout = async () => {
    const supabase = createClient()
    await supabase.auth.signOut()
    router.push('/login')
  }

  return (
    <main className="p-8">
      <div className="max-w-4xl mx-auto space-y-8">
        {/* Header Section */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-6">
          <div>
            <h1 className="text-4xl font-black text-foreground tracking-tighter uppercase mb-2">Perfil do Operador</h1>
            <p className="text-foreground/40 font-bold uppercase tracking-widest text-xs">Gestão de Identidade e Credenciais Táticas</p>
          </div>
          
          <button 
            onClick={handleLogout}
            className="flex items-center gap-2 px-6 py-3 rounded-2xl bg-rose-500/10 text-rose-500 border border-rose-500/20 font-black uppercase text-[10px] tracking-widest hover:bg-rose-500/20 transition-all active:scale-95"
          >
            <LogOut className="h-4 w-4" /> Terminar Sessão
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {/* Left Column: Info Cards */}
          <div className="lg:col-span-8 space-y-6">
            <div className="glass-card p-8 rounded-[2.5rem] relative overflow-hidden group">
              <div className="absolute inset-0 bg-gradient-to-br from-primary/[0.05] to-transparent pointer-events-none" />
              
              <div className="flex flex-col md:flex-row gap-8 items-center relative z-10">
                <div className="h-32 w-32 rounded-3xl bg-primary/10 flex items-center justify-center border border-primary/20 shadow-2xl relative">
                  <UserCircle className="h-20 w-20 text-primary/60" />
                  <div className="absolute -bottom-2 -right-2 h-8 w-8 rounded-full bg-emerald-500 border-4 border-background flex items-center justify-center">
                    <Activity className="h-4 w-4 text-white animate-pulse" />
                  </div>
                </div>

                <div className="flex-1 space-y-4 text-center md:text-left">
                  <div>
                    <h2 className="text-2xl font-black text-foreground tracking-tight">Administrador Tático</h2>
                    <p className="text-primary font-bold text-sm">Acesso de Nível 5 (Root)</p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                    <div className="flex items-center gap-3 text-foreground/60">
                      <div className="h-8 w-8 rounded-lg bg-foreground/5 flex items-center justify-center border border-foreground/10">
                        <Mail className="h-4 w-4" />
                      </div>
                      <span className="text-sm font-medium">{user?.email || 'admin@vexthub.com'}</span>
                    </div>
                    <div className="flex items-center gap-3 text-foreground/60">
                      <div className="h-8 w-8 rounded-lg bg-foreground/5 flex items-center justify-center border border-foreground/10">
                        <Shield className="h-4 w-4 text-emerald-500" />
                      </div>
                      <span className="text-sm font-medium">Status: Ativo / Online</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Security Settings */}
            <div className="glass-card p-8 rounded-[2.5rem] space-y-6">
              <h3 className="text-xs font-black uppercase tracking-[0.2em] text-foreground/40 flex items-center gap-2">
                <Key className="h-4 w-4 text-amber-500" /> Segurança da Conta
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <button className="flex items-center justify-between p-4 rounded-2xl bg-foreground/5 border border-foreground/10 hover:border-primary/30 transition-all text-left group">
                  <div className="space-y-1">
                    <p className="text-xs font-black uppercase tracking-wider text-foreground/80">Senha</p>
                    <p className="text-[10px] text-foreground/40 font-bold">Alterar credenciais de acesso</p>
                  </div>
                  <div className="h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center text-primary group-hover:scale-110 transition-transform">
                    <User className="h-4 w-4" />
                  </div>
                </button>

                <button className="flex items-center justify-between p-4 rounded-2xl bg-foreground/5 border border-foreground/10 hover:border-primary/30 transition-all text-left group">
                  <div className="space-y-1">
                    <p className="text-xs font-black uppercase tracking-wider text-foreground/80">MFA / 2FA</p>
                    <p className="text-[10px] text-foreground/40 font-bold">Autenticação multifator ativa</p>
                  </div>
                  <div className="h-8 w-8 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-500 group-hover:scale-110 transition-transform">
                    <Shield className="h-4 w-4" />
                  </div>
                </button>
              </div>
            </div>
          </div>

          {/* Right Column: Activity / Timeline */}
          <div className="lg:col-span-4 space-y-6">
            <div className="glass-card p-8 rounded-[2.5rem] flex flex-col h-full">
              <h3 className="text-xs font-black uppercase tracking-[0.2em] text-foreground/40 mb-8 flex items-center gap-2">
                <Clock className="h-4 w-4 text-primary" /> Atividade Recente
              </h3>
              
              <div className="space-y-6 flex-1">
                {[
                  { action: 'Login no Sistema', time: 'Há 5 minutos', icon: User, color: 'text-indigo-400' },
                  { action: 'Relatório Gerado', time: 'Há 2 horas', icon: Activity, color: 'text-emerald-400' },
                  { action: 'Alteração de Política', time: 'Há 1 dia', icon: Shield, color: 'text-amber-400' },
                ].map((item, i) => (
                  <div key={i} className="flex gap-4 group">
                    <div className={`h-10 w-10 shrink-0 rounded-xl bg-foreground/5 flex items-center justify-center border border-foreground/10 group-hover:border-primary/30 transition-colors ${item.color}`}>
                      <item.icon className="h-5 w-5" />
                    </div>
                    <div className="flex flex-col justify-center">
                      <p className="text-xs font-black text-foreground/80">{item.action}</p>
                      <p className="text-[9px] font-bold text-foreground/30 uppercase">{item.time}</p>
                    </div>
                  </div>
                ))}
              </div>

              <div className="mt-8 pt-6 border-t border-foreground/5">
                <div className="bg-primary/5 p-4 rounded-2xl border border-primary/10">
                  <div className="flex items-center gap-3 mb-2">
                    <Bell className="h-4 w-4 text-primary" />
                    <span className="text-[10px] font-black uppercase text-primary tracking-widest">Aviso de Segurança</span>
                  </div>
                  <p className="text-[10px] text-foreground/60 leading-relaxed font-medium">
                    Sua sessão expira em <span className="text-primary font-bold">4 horas</span>. 
                    Certifique-se de salvar todas as alterações táticas.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>
  )
}
