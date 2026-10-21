import { NextResponse } from "next/server";
import { supabaseAdmin } from "@/utils/supabase/admin";
import { requireTenantAccess } from "@/utils/security/api-auth";
import { isSimulationFallbackEnabled, getSimulationState } from "@/utils/simulation/reader";

export const dynamic = "force-dynamic";

type MachineRow = {
  id: string;
  hostname?: string | null;
  unit?: string | null;
  last_pulse?: string | null;
  inventory_data?: {
    security_analysis?: {
      score?: number;
      risk_level?: string;
      findings?: unknown[];
      analyzed_at?: string;
    };
  } | null;
};

export async function GET(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "viewer");
    if (auth.response) return auth.response;

    let machines: any[] = [];
    let alerts: any[] = [];

    try {
      const [{ data: m, error: mE }, { data: a, error: aE }] = await Promise.all([
        supabaseAdmin
          .from("machines")
          .select("id, hostname, unit, last_pulse, inventory_data")
          .eq("tenant_id", auth.tenantId)
          .order("last_pulse", { ascending: false })
          .limit(250),
        supabaseAdmin
          .from("compliance_alerts")
          .select("*")
          .eq("tenant_id", auth.tenantId)
          .eq("is_resolved", false)
          .order("created_at", { ascending: false })
          .limit(100),
      ]);

      if (mE || aE) {
        console.warn("Security Realtime - Supabase errors:", mE || aE);
      } else {
        machines = m || [];
        alerts = a || [];
      }
    } catch {
      console.warn("Security Realtime - Connection failed.");
    }

    const endpoints = ((machines || []) as MachineRow[])
      .map((machine) => {
        const analysis = machine.inventory_data?.security_analysis;
        return {
          id: machine.id,
          hostname: machine.hostname,
          unit: machine.unit,
          last_pulse: machine.last_pulse,
          risk_score: analysis?.score || 0,
          risk_level: analysis?.risk_level || "low",
          findings_count: Array.isArray(analysis?.findings) ? analysis.findings.length : 0,
          analyzed_at: analysis?.analyzed_at || null,
        };
      })
      .sort((left, right) => right.risk_score - left.risk_score);

    // Simulation Fallback
    let finalEndpoints = endpoints;
    let finalAlerts = alerts || [];

    if (finalEndpoints.length === 0 && isSimulationFallbackEnabled()) {
      const sim = getSimulationState();
      if (sim) {
        finalEndpoints = sim.machines.slice(0, 50).map((m: any) => ({
          id: m.id,
          hostname: m.hostname,
          unit: m.unit,
          last_pulse: m.last_pulse,
          risk_score: Math.floor(Math.random() * 40),
          risk_level: "low",
          findings_count: 0,
          analyzed_at: m.last_pulse
        }));

        finalAlerts = sim.events.map((e: any) => ({
          id: String(e.id),
          hostname: e.agent_hostname,
          unit: "SIMULATION",
          software_name: e.type,
          message: `ALERTA SIMULADO: Detecção de ${e.type}`,
          severity: e.severity.toLowerCase(),
          created_at: e.timestamp
        }));
      }
    }

    return NextResponse.json({
      generated_at: new Date().toISOString(),
      summary: {
        endpoints: finalEndpoints.length,
        active_alerts: finalAlerts.length,
        high_risk_endpoints: finalEndpoints.filter((endpoint) => endpoint.risk_score >= 65).length,
        critical_endpoints: finalEndpoints.filter((endpoint) => endpoint.risk_score >= 85).length,
      },
      endpoints: finalEndpoints,
      alerts: finalAlerts,
    });
  } catch (err: any) {
    console.error("GET /api/security/realtime error:", err);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
