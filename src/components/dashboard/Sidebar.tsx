"use client"

import React from 'react'
import Link from 'next/link'
import Image from 'next/image'
import { usePathname, useRouter } from 'next/navigation'
import { createClient } from '@/utils/supabase/client'
import { 
  LayoutDashboard, 
  Monitor, 
  Layers, 
  Settings, 
  ShieldCheck,
  ShieldAlert,
  FileBarChart2,
  LogOut,
  Brain,
  Bug,
  Network,
  Swords,
  UserCircle
} from 'lucide-react'
import { ThemeToggle } from './ThemeToggle'
import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { motion } from 'framer-motion'

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

const navItems = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Dispositivos', href: '/dashboard/devices', icon: Monitor },
  { name: 'Segurança', href: '/dashboard/security', icon: ShieldAlert },
  { name: 'Políticas', href: '/dashboard/compliance', icon: ShieldCheck },
  { name: 'Cortex Neural', href: '/dashboard/neural', icon: Brain },
  { name: 'Lab Forense', href: '/dashboard/forensics', icon: Bug },
  { name: 'Unidades', href: '/dashboard/units', icon: Layers },
  { name: 'Relatórios', href: '/dashboard/intelligence', icon: FileBarChart2 },
  { name: 'Arsenal Tático', href: '/dashboard/playbooks', icon: Swords },
  { name: 'Topologia', href: '/dashboard/topology', icon: Network },
  { name: 'Configurações', href: '/dashboard/settings', icon: Settings },
]

export function Sidebar() {
  const pathname = usePathname()
  const router = useRouter()
  const supabase = createClient()

  const [companyName, setCompanyName] = React.useState('')

  React.useEffect(() => {
    async function fetchConfig() {
      try {
        const res = await fetch('/api/config')
        const data = await res.json()
        if (data.company_name) setCompanyName(data.company_name)
      } catch (err) {
        console.error('Sidebar config fetch error:', err)
      }
    }
    fetchConfig()
  }, [])

  const handleLogout = async () => {
    await supabase.auth.signOut()
    router.push('/login')
  }

  return (
    <div className="hidden lg:flex flex-col w-72 h-[calc(100vh-2rem)] m-4 fixed left-0 top-0 glass-card rounded-[2.5rem] border border-foreground/10 z-50 overflow-hidden shadow-[0_32px_64px_-15px_rgba(0,0,0,0.5)] shrink-0">
      <div className="absolute inset-0 bg-gradient-to-b from-primary/[0.05] to-transparent pointer-events-none" />
      
      {/* Header / Logo */}
      <div className="p-8 pb-4 relative">
        <Link href="/dashboard" className="flex items-center gap-4 group cursor-pointer">
          <div className="h-12 w-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 group-hover:bg-primary/20 transition-all duration-500 shadow-lg shadow-primary/10 overflow-hidden">
            <Image src="/icon.png" alt="VEXT" width={32} height={32} unoptimized priority className="h-8 w-8 object-contain" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center">
              <span className="font-black text-xl text-foreground tracking-tighter uppercase">{companyName || 'VEXT'}</span>
              <span className="font-thin text-xl text-primary tracking-tight italic ml-0.5">{companyName ? '' : 'HUB'}</span>
            </div>
          </div>
        </Link>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto hide-scrollbar relative">
        {navItems.map((item) => {
          const isActive = pathname === item.href
          const Icon = item.icon
          
          return (
            <Link 
              key={item.name} 
              href={item.href}
              className={cn(
                "relative flex items-center gap-4 px-5 py-3.5 rounded-2xl transition-all duration-300 group overflow-hidden",
                isActive 
                  ? "bg-primary/[0.08] text-primary shadow-[inset_0_0_20px_rgba(124,58,237,0.05)]" 
                  : "text-foreground/40 hover:text-foreground/80 hover:bg-foreground/[0.03]"
              )}
            >
              {isActive && (
                <motion.div 
                  layoutId="active-nav"
                  className="absolute left-0 w-1 h-6 bg-primary rounded-r-full shadow-[0_0_15px_rgba(124,58,237,0.5)]"
                />
              )}
              
              <Icon className={cn(
                "h-5 w-5 transition-all duration-300",
                isActive ? "text-primary scale-110" : "text-foreground/30 group-hover:text-foreground/60"
              )} />
              
              <span className={cn(
                "text-[11px] font-black tracking-[0.1em] uppercase transition-colors duration-300",
                isActive ? "text-primary" : "text-foreground/40 group-hover:text-foreground/60"
              )}>
                {item.name}
              </span>

              {isActive && (
                <div className="absolute right-4 w-1.5 h-1.5 rounded-full bg-primary/40 animate-pulse" />
              )}
            </Link>
          )
        })}
      </nav>

      {/* Footer / User */}
      <div className="p-4 mt-auto border-t border-foreground/5 relative">
        <div className="flex flex-col gap-3">
          <div 
            onClick={() => router.push('/dashboard/profile')}
            className="flex items-center gap-3 p-3 rounded-2xl bg-foreground/[0.03] hover:bg-foreground/[0.05] transition-all cursor-pointer group"
          >
            <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center border border-primary/20">
              <UserCircle className="h-6 w-6 text-primary/60" />
            </div>
            <div className="flex flex-col">
              <span className="text-xs font-bold text-foreground/80">Admin</span>
              <span className="text-[10px] text-emerald-500 font-bold uppercase tracking-wider">Online</span>
            </div>
          </div>

          <div className="flex items-center justify-between px-2">
            <ThemeToggle />
            <button 
              onClick={handleLogout}
              className="p-2.5 hover:bg-rose-500/10 rounded-xl transition-all group border border-transparent hover:border-rose-500/20"
              title="Encerrar Sessão"
            >
              <LogOut className="h-4 w-4 text-foreground/20 group-hover:text-rose-500 transition-colors" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
