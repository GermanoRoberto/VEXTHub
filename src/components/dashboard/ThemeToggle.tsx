"use client"

import * as React from "react"
import { Moon, Sun, Monitor } from "lucide-react"
import { useTheme } from "next-themes"
import { motion } from "framer-motion"

export function ThemeToggle() {
  const { theme, setTheme } = useTheme()
  const [mounted, setMounted] = React.useState(false)

  // Prevenir erro de hidratação
  React.useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return <div className="h-9 w-9" />
  }

  const themes = [
    { id: "light", icon: Sun, label: "Claro" },
    { id: "dark", icon: Moon, label: "Escuro" },
    { id: "system", icon: Monitor, label: "Sistema" },
  ]

  return (
    <div className="flex bg-foreground/5 rounded-xl p-1 border border-foreground/10 gap-1 mt-auto">
      {themes.map(({ id, icon: Icon, label }) => (
        <button
          key={id}
          onClick={() => setTheme(id)}
          className={`relative p-2 rounded-lg flex-1 flex items-center justify-center transition-all group ${
            theme === id 
              ? "text-primary shadow-sm" 
              : "text-foreground/40 hover:text-foreground/60 hover:bg-foreground/5"
          }`}
          title={label}
        >
          {theme === id && (
            <motion.div
              layoutId="activeTheme"
              className="absolute inset-0 bg-background rounded-lg shadow-sm border border-foreground/5"
              transition={{ type: "spring", bounce: 0.2, duration: 0.6 }}
            />
          )}
          <Icon className="h-4 w-4 relative z-10 transition-transform group-active:scale-95" />
        </button>
      ))}
    </div>
  )
}
