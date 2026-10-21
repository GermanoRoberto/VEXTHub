"use client"

import React from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { motion } from 'framer-motion'
import { 
  LayoutDashboard, 
  Monitor, 
  Layers, 
  ShieldCheck,
  ShieldAlert,
  FileBarChart2
} from 'lucide-react'
import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

const navItems = [
  { name: 'Dash', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Sec', href: '/dashboard/security', icon: ShieldAlert },
  { name: 'Invent.', href: '/dashboard/devices', icon: Monitor },
  { name: 'Unid.', href: '/dashboard/units', icon: Layers },
  { name: 'Rules', href: '/dashboard/compliance', icon: ShieldCheck },
  { name: 'Report', href: '/dashboard/intelligence', icon: FileBarChart2 },
]

export function BottomNav() {
  const pathname = usePathname()

  return (
    <div className="lg:hidden fixed bottom-8 left-1/2 -translate-x-1/2 w-[calc(100%-2rem)] max-w-md z-50">
      <nav className="glass-card flex items-center justify-around p-3 rounded-2xl shadow-[0_20px_50px_rgba(0,0,0,0.3)]">
        {navItems.map((item) => {
          const isActive = pathname === item.href
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex flex-col items-center gap-1.5 p-2 rounded-xl transition-all duration-500 relative min-w-[64px]",
                isActive 
                  ? "text-primary scale-110" 
                  : "text-foreground/30 hover:text-foreground/50"
              )}
            >
              {isActive && (
                <motion.div 
                  layoutId="bottomNavGlow"
                  className="absolute inset-0 bg-primary/10 rounded-xl blur-md"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                />
              )}
              
              <item.icon className={cn(
                "h-5 w-5 transition-all duration-300 relative z-10",
                isActive ? "drop-shadow-[0_0_8px_rgba(124,58,237,0.5)]" : ""
              )} />
              <span className="text-[9px] font-black tracking-widest uppercase relative z-10">{item.name}</span>
              
              {isActive && (
                <motion.div 
                  layoutId="bottomNavDot"
                  className="absolute -bottom-1 h-1 w-4 rounded-full bg-primary shadow-[0_0_10px_#7C3AED]"
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                />
              )}
            </Link>
          )
        })}
      </nav>
    </div>
  )
}
