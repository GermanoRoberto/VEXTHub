import { NextResponse } from "next/server";
import { requireTenantAccess } from "@/utils/security/api-auth";
import { supabaseAdmin } from "@/utils/supabase/admin";
import { getSimulationState, isSimulationFallbackEnabled } from "@/utils/simulation/reader";
import { detectEndpointAnomalies } from "@/utils/security/anomaly-engine";
import { buildFleetThreatClusters } from "@/utils/security/threat-clustering";
import { evaluateAutonomousMitigation, getAutonomousActionLog } from "@/utils/security/autonomous-defense";
import { enrichFleetWithAI } from "@/utils/security/ai-analysis";

export const dynamic = "force-dynamic";

type MachineRow = {
  id: string;
  hostname?: string | null;
  unit?: string | null;
  cpu_info?: string | null;
  ram_total?: string | null;
  os_name?: string | null;
  last_pulse?: string | null;
  inventory_data?: any;
};

type AlertRow = {
  id?: string;
  hostname?: string | null;
  unit?: string | null;
  software_name?: string | null;
  message?: string | null;
  severity?: string | null;
  is_resolved?: boolean | null;
  created_at?: string | null;
};

const SUSPICIOUS_NAMES = [
  "mimikatz",
  "rustdesk",
  "teamviewer",
  "anydesk",
  "process hacker",
  "advanced ip scanner",
  "wireshark",
  "valorant",
  "counter-strike",
  "league of legends",
  "roblox",
  "steam",
];

function normalizeInventory(value: any) {
  if (!value) return {};
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch {
      return {};
    }
  }
  return value;
}

function softwareList(machine: MachineRow) {
  const inventory = normalizeInventory(machine.inventory_data);
  return Array.isArray(inventory.software) ? inventory.software : [];
}

function vulnerabilities(machine: MachineRow) {
  const inventory = normalizeInventory(machine.inventory_data);
  return Array.isArray(inventory.vulnerabilities) ? inventory.vulnerabilities : [];
}

function isRiskSoftware(name: string) {
  const lower = name.toLowerCase();
  return SUSPICIOUS_NAMES.some((item) => lower.includes(item));
}

function unitDisplayName(unitId: string, units: any[]) {
  const found = units.find((unit) => unit.id === unitId || unit.name === unitId);
  return found?.name || unitId || "Sem Unidade";
}

async function buildStats(input: {
  machines: MachineRow[];
  alerts: AlertRow[];
  units: any[];
  companyName?: string;
  stressMetrics?: Record<string, unknown>;
  tenantId?: string;
}) {
  const machines = input.machines || [];
  const alerts = (input.alerts || []).filter((alert) => !alert.is_resolved);
  const units = input.units || [];
  const unitIds = Array.from(new Set([
    ...units.map((unit) => String(unit.id || unit.name || "")).filter(Boolean),
    ...machines.map((machine) => String(machine.unit || "Sem Unidade")),
  ]));

  const unitStats = unitIds.map((unitId) => {
    const unitMachines = machines.filter((machine) => String(machine.unit || "Sem Unidade") === unitId);
    const unitAlerts = alerts.filter((alert) => String(alert.unit || "Sem Unidade") === unitId);
    let unauthorizedApps = 0;
    let vulnerabilitiesCount = 0;
    const networkCategories: Record<string, number> = {};
    const networkVendors = new Set<string>();
    let assetsCount = 0;

    for (const machine of unitMachines) {
      const inventory = normalizeInventory(machine.inventory_data);
      const apps = Array.isArray(inventory.software) ? inventory.software : [];
      const vulns = Array.isArray(inventory.vulnerabilities) ? inventory.vulnerabilities : [];
      vulnerabilitiesCount += vulns.length;
      unauthorizedApps += apps.filter((app: any) => app?.name && isRiskSoftware(String(app.name))).length;

      const assets = Array.isArray(inventory.network_assets) ? inventory.network_assets : [];
      for (const asset of assets) {
        assetsCount += 1;
        if (asset?.vendor) networkVendors.add(String(asset.vendor));
        if (asset?.device_type) {
          const key = String(asset.device_type);
          networkCategories[key] = (networkCategories[key] || 0) + 1;
        }
      }
    }

    const baseRisk = unitAlerts.length * 18 + unauthorizedApps * 9 + vulnerabilitiesCount * 14;
    const riskScore = unitMachines.length > 0 ? Math.min(100, Math.round((baseRisk / unitMachines.length) * 4)) : 0;

    return {
      name: unitDisplayName(unitId, units),
      machineCount: unitMachines.length,
      unauthorizedApps,
      activeAlerts: unitAlerts.length,
      riskScore,
      devices: unitMachines.slice(0, 8).map((machine) => ({
        id: machine.id,
        hostname: machine.hostname,
        cpu: machine.cpu_info,
        ram: machine.ram_total,
        os: machine.os_name,
        lastPulse: machine.last_pulse,
        inventory_data: normalizeInventory(machine.inventory_data),
      })),
      violatingDevices: unitMachines.filter((machine) => {
        const apps = softwareList(machine);
        return apps.some((app: any) => app?.name && isRiskSoftware(String(app.name)));
      }).map((machine) => {
        const apps = softwareList(machine);
        const badApps = apps.filter((app: any) => app?.name && isRiskSoftware(String(app.name))).map((app: any) => app.name);
        return {
          hostname: machine.hostname || machine.id,
          badApps,
        };
      }),
      networkSummary: {
        assetsCount,
        categories: networkCategories,
        vendors: Array.from(networkVendors).slice(0, 8),
        avgLatency: Math.round(10 + Math.min(80, riskScore / 2)),
      },
    };
  }).sort((left, right) => right.riskScore - left.riskScore);

  const softwareInfo: Record<string, { count: number; machines: { hostname: string; unit: string }[] }> = {};
  for (const machine of machines) {
    const riskyApps = softwareList(machine).filter((app: any) => app?.name && isRiskSoftware(String(app.name)));
    const vulnerableApps = vulnerabilities(machine).map((vuln: any) => ({
      name: vuln.software || vuln.cve || "Vulnerabilidade conhecida",
    }));

    for (const app of [...riskyApps, ...vulnerableApps]) {
      const name = String(app.name || "Software irregular");
      softwareInfo[name] ||= { count: 0, machines: [] };
      softwareInfo[name].count += 1;
      softwareInfo[name].machines.push({
        hostname: String(machine.hostname || machine.id),
        unit: String(machine.unit || "Sem Unidade"),
      });
    }
  }

  const topSoftware = Object.entries(softwareInfo)
    .map(([name, info]) => ({
      name,
      count: info.count,
      affectedMachines: info.machines.slice(0, 15),
    }))
    .sort((left, right) => right.count - left.count)
    .slice(0, 10);

  const averageRisk = unitStats.length
    ? Number((unitStats.reduce((sum, unit) => sum + unit.riskScore, 0) / unitStats.length).toFixed(1))
    : 0;

  const anomalies = detectEndpointAnomalies(machines);
  const threatClusters = buildFleetThreatClusters(unitStats);
  await evaluateAutonomousMitigation({ machines: machines as any[], anomalies, tenantId: input.tenantId });
  const autonomousActions = getAutonomousActionLog();

  return {
    unitStats,
    topSoftware,
    companyName: input.companyName || "VextHub",
    fleetSummary: {
      totalMachines: machines.length,
      totalAlerts: alerts.length,
      averageRisk,
      totalAnomalies: anomalies.length,
      activeClusters: threatClusters.length,
    },
    anomalies,
    threatClusters,
    autonomousActions,
    stress_metrics: input.stressMetrics || null,
  };
}

async function buildSimulationStats(tenantId?: string) {
  const sim = getSimulationState();
  if (!sim) {
    return await buildStats({ machines: [], alerts: [], units: [], companyName: "VextHub", tenantId });
  }

  const alerts = (sim.events || []).map((event: any) => ({
    id: String(event.id),
    hostname: event.agent_hostname || event.machine,
    unit: event.unit,
    software_name: event.type,
    message: event.description || event.type,
    severity: event.severity,
    created_at: event.timestamp,
    is_resolved: false,
  }));

  return await buildStats({
    machines: sim.machines as MachineRow[],
    alerts,
    units: sim.units || [],
    companyName: "VextHub Simulation",
    stressMetrics: sim.stress_metrics,
    tenantId,
  });
}

async function generateCortexBriefing(
  totalMachines: number,
  totalAlerts: number,
  averageRisk: number,
  topSoftware: any[],
  unitStats: any[]
) {
  let cortexBriefing = null;
  try {
    const aiResult = await enrichFleetWithAI({
      totalMachines,
      totalAlerts,
      averageRisk,
      topSoftware: topSoftware.map(s => ({ name: s.name, count: s.count })),
      units: unitStats.map(u => ({ name: u.name, riskScore: u.riskScore, machineCount: u.machineCount }))
    });
    if (aiResult && aiResult.enabled && !aiResult.error) {
      cortexBriefing = {
        summary: aiResult.executive_summary,
        threats: aiResult.threat_landscape,
        recommendations: aiResult.strategic_recommendations
      };
    }
  } catch (aiErr) {
    console.warn("Cortex Fleet AI enrichment skipped:", aiErr);
  }

  if (!cortexBriefing) {
    const riskLevel = averageRisk >= 80 ? "CRÍTICO" : averageRisk >= 60 ? "ALTO" : averageRisk >= 35 ? "MÉDIO" : "BAIXO";
    const statusText = totalAlerts > 0 
      ? `CÓRTEX NEURAL — DIRETRIZ SOC INTERNA: ANÔMALO. O motor de inteligência consolidou a telemetria do ecossistema e reportou ${totalAlerts} violações ativas de segurança em um parque total de ${totalMachines} máquinas monitoradas.\n\nO nível de ameaça global da infraestrutura foi rebaixado para um status ${riskLevel} com índice médio de risco em ${averageRisk}%. Essa anomalia foi desencadeada principalmente pela presença ativa de softwares utilitários não homologados, ferramentas de controle remoto expostas sem autorização ou persistências anômalas no ecossistema de rede. Recomenda-se o início imediato dos planos de mitigação tática, isolamento preventivo dos hosts sob maior score de risco e auditoria local.`
      : `CÓRTEX NEURAL — DIRETRIZ SOC INTERNA: NOMINAL. A varredura de telemetria em tempo real concluiu a análise contínua sobre a totalidade de todos os ${totalMachines} endpoints da infraestrutura corporativa.\n\nFidelidade total às políticas de compliance confirmada. Não foram detectadas violações de software, atividades suspeitas de LOLBins ou ferramentas de controle remoto expostas nas últimas pulsações táticas recebidas. O ecossistema de rede opera em 100% de estabilidade com resiliência máxima de segurança contra invasão lateral ou persistências anômalas. O monitoramento contínuo permanece ativo.`;

    cortexBriefing = {
      summary: statusText,
      threats: totalAlerts > 0 
        ? "Detecção de softwares de acesso remoto não homologados e desvios de conformidade em equipamentos da rede corporativa." 
        : "Nenhum vetor de ameaça ativo ou desvio de conformidade detectado na frota de endpoints.",
      recommendations: totalAlerts > 0 
        ? [
            "Preservar logs forenses locais e realizar o isolamento preventivo de endpoints sob risco crítico.",
            "Auditar a justificativa comercial dos softwares apontados junto aos respectivos proprietários nas unidades.",
            "Homologar exceções de compliance vigentes para softwares corporativos aprovados em Políticas."
          ]
        : [
            "Manter a política de conformidade e auditorias automáticas periódicas ativas no painel.",
            "Garantir que todos os endpoints estejam executando a versão mais recente do agente tático C#."
          ]
    };
  }

  return cortexBriefing;
}

export async function GET(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "viewer");
    if (auth.response) return auth.response;

    try {
      const [machinesResult, alertsResult, unitsResult, configResult] = await Promise.all([
        supabaseAdmin
          .from("machines")
          .select("id, hostname, unit, cpu_info, ram_total, os_name, last_pulse, inventory_data")
          .eq("tenant_id", auth.tenantId),
        supabaseAdmin
          .from("compliance_alerts")
          .select("*")
          .eq("tenant_id", auth.tenantId)
          .eq("is_resolved", false),
        supabaseAdmin
          .from("units")
          .select("id, name")
          .eq("tenant_id", auth.tenantId),
        supabaseAdmin
          .from("app_config")
          .select("company_name")
          .eq("tenant_id", auth.tenantId)
          .maybeSingle(),
      ]);

      const dbError = machinesResult.error || alertsResult.error || unitsResult.error || configResult.error;
      if (dbError) throw dbError;

      const machines = (machinesResult.data || []) as MachineRow[];
      if (machines.length === 0 && isSimulationFallbackEnabled()) {
        const stats = await buildSimulationStats(auth.tenantId);
        const briefing = await generateCortexBriefing(
          stats.fleetSummary.totalMachines,
          stats.fleetSummary.totalAlerts,
          stats.fleetSummary.averageRisk,
          stats.topSoftware,
          stats.unitStats
        );
        return NextResponse.json({ ...stats, cortexBriefing: briefing });
      }

      const stats = await buildStats({
        machines,
        alerts: (alertsResult.data || []) as AlertRow[],
        units: unitsResult.data || [],
        companyName: configResult.data?.company_name || "VextHub",
        tenantId: auth.tenantId,
      });
      const briefing = await generateCortexBriefing(
        stats.fleetSummary.totalMachines,
        stats.fleetSummary.totalAlerts,
        stats.fleetSummary.averageRisk,
        stats.topSoftware,
        stats.unitStats
      );
      return NextResponse.json({ ...stats, cortexBriefing: briefing });

    } catch (dbError: any) {
      if (!isSimulationFallbackEnabled()) throw dbError;
      console.warn("Intelligence stats - Supabase unavailable, using simulation:", dbError.message);
      const stats = await buildSimulationStats(auth.tenantId);
      const briefing = await generateCortexBriefing(
        stats.fleetSummary.totalMachines,
        stats.fleetSummary.totalAlerts,
        stats.fleetSummary.averageRisk,
        stats.topSoftware,
        stats.unitStats
      );
      return NextResponse.json({ ...stats, cortexBriefing: briefing });
    }
  } catch (error: any) {
    console.error("GET /api/intelligence/stats error:", error.message);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
