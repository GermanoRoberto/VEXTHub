"use client"

import React, { useState } from 'react'
import { MachineTable } from '@/components/dashboard/MachineTable'
import { Machine } from '@/components/dashboard/DeviceDetails'
import { Monitor, Search, FileSpreadsheet, FileText, Loader2 } from 'lucide-react'
import {
  exportDevicesCsv,
  exportDevicesPdf,
  DeviceExportItem,
} from '@/utils/export/reports'
import { analyzeTelemetryInventory } from '@/utils/security/telemetry-detection'

interface RawApiMachine {
  id: string
  hostname: string
  serial_number?: string
  unit?: string
  os_name?: string
  telemetry?: { cpu?: number; ram?: number; disk?: number }
  cpu_info?: string
  ram_total?: string
  agent_version?: string
  last_pulse?: string
  inventory_data?: Machine['inventory_data']
}

export default function DevicesPage() {
  const [search, setSearch] = useState('')
  const [machines, setMachines] = useState<Machine[]>([])
  const [exportingCsv, setExportingCsv] = useState(false)
  const [exportingPdf, setExportingPdf] = useState(false)

  const normalizeMachineToExportItem = (m: Machine): DeviceExportItem => {
    const getStatus = (lastPulse: string): 'online' | 'away' | 'offline' => {
      if (!lastPulse) return 'offline'
      const diff = Date.now() - new Date(lastPulse).getTime()
      const minutes = diff / 1000 / 60
      if (minutes < 15) return 'online'
      if (minutes < 60) return 'away'
      return 'offline'
    }

    const status = getStatus(m.last_pulse)
    const sysDetails = m.inventory_data?.system_details
    const secAnalysis = m.inventory_data?.security_analysis

    let riskScore = 0
    let riskLevel = 'baixo'

    if (typeof secAnalysis?.score === 'number') {
      riskScore = secAnalysis.score
      riskLevel =
        secAnalysis.risk_level ||
        (riskScore >= 70 ? 'crítico' : riskScore >= 40 ? 'médio' : 'baixo')
    } else if (m.inventory_data) {
      const analysis = analyzeTelemetryInventory(m.inventory_data)
      riskScore = analysis.score
      riskLevel = analysis.risk_level
    }

    return {
      id: m.id,
      hostname: m.hostname || 'Desconhecido',
      unit: m.unit || 'Geral',
      status,
      ip: sysDetails?.local_ip || 'N/A',
      user: sysDetails?.active_user || 'N/A',
      os: m.os_name || 'Windows',
      cpu: m.cpu_info || 'N/A',
      ram: m.ram_total || 'N/A',
      agentVersion: m.agent_version || 'v4.0.0',
      riskScore,
      riskLevel,
      lastPulse: m.last_pulse
        ? new Date(m.last_pulse).toLocaleString('pt-BR')
        : 'Sem registro',
    }
  }

  const ensureFleetData = async (): Promise<Machine[]> => {
    if (machines.length > 0) return machines
    const res = await fetch('/api/inventory/machines')
    if (!res.ok) throw new Error('Falha ao carregar lista de dispositivos')
    const data: RawApiMachine[] = await res.json()
    const mapped: Machine[] = data.map((m) => ({
      id: m.id,
      hostname: m.hostname,
      serial_number: m.serial_number || '',
      unit: m.unit || 'Geral',
      os_name: m.os_name || 'Windows',
      cpu_info: m.telemetry ? `${m.telemetry.cpu}% CPU` : m.cpu_info || 'N/A',
      ram_total: m.telemetry ? `${m.telemetry.ram}% RAM` : m.ram_total || 'N/A',
      agent_version: m.agent_version || 'v4.0.0-sim',
      last_pulse: m.last_pulse || new Date().toISOString(),
      inventory_data: m.inventory_data || {},
    }))
    setMachines(mapped)
    return mapped
  }

  const handleExportCsv = async () => {
    try {
      setExportingCsv(true)
      const fleet = await ensureFleetData()
      const items = fleet.map(normalizeMachineToExportItem)
      exportDevicesCsv(items)
    } catch (err) {
      console.error('Erro ao exportar CSV de dispositivos:', err)
    } finally {
      setExportingCsv(false)
    }
  }

  const handleExportPdf = async () => {
    try {
      setExportingPdf(true)
      const fleet = await ensureFleetData()
      const items = fleet.map(normalizeMachineToExportItem)
      await exportDevicesPdf(items)
    } catch (err) {
      console.error('Erro ao gerar laudo PDF de dispositivos:', err)
    } finally {
      setExportingPdf(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-black text-foreground flex items-center gap-3">
            <Monitor className="h-7 w-7 text-primary" />
            Dispositivos
          </h1>
          <p className="text-sm text-foreground/50 mt-1">
            Inventário consolidado de endpoints e status operacional em tempo real
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative w-full sm:w-64">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-foreground/40" />
            <input
              type="text"
              placeholder="Buscar por host, IP ou usuário..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 rounded-xl bg-foreground/[0.03] border border-foreground/10 text-sm focus:outline-none focus:border-primary/50 text-foreground placeholder:text-foreground/30 transition-all"
            />
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleExportCsv}
              disabled={exportingCsv || exportingPdf}
              className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-foreground/[0.04] hover:bg-foreground/[0.08] border border-foreground/10 text-xs font-bold text-foreground transition-all hover:border-emerald-500/40 disabled:opacity-50"
              title="Exportar inventário em formato CSV (RFC-4180)"
            >
              {exportingCsv ? (
                <Loader2 className="h-4 w-4 animate-spin text-emerald-400" />
              ) : (
                <FileSpreadsheet className="h-4 w-4 text-emerald-400" />
              )}
              <span>Exportar CSV</span>
            </button>

            <button
              type="button"
              onClick={handleExportPdf}
              disabled={exportingCsv || exportingPdf}
              className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-primary/10 hover:bg-primary/20 border border-primary/20 text-xs font-bold text-primary transition-all shadow-sm hover:border-primary/40 disabled:opacity-50"
              title="Gerar laudo executivo em PDF A4"
            >
              {exportingPdf ? (
                <Loader2 className="h-4 w-4 animate-spin text-primary" />
              ) : (
                <FileText className="h-4 w-4 text-primary" />
              )}
              <span>Laudo PDF</span>
            </button>
          </div>
        </div>
      </div>

      <MachineTable search={search} onDataLoaded={setMachines} />
    </div>
  )
}
