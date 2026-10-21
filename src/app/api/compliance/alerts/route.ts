import { supabaseAdmin } from "@/utils/supabase/admin";
import { NextResponse } from "next/server";
import { requireTenantAccess } from "@/utils/security/api-auth";
import { readLimitedJson, readStringField } from "@/utils/security/request-validation";
import { isSimulationFallbackEnabled, getSimulationState, saveSimulationState } from "@/utils/simulation/reader";

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "viewer");
    if (auth.response) return auth.response;

    let data: any[] = [];
    try {
      const { data: d, error } = await supabaseAdmin
        .from("compliance_alerts")
        .select("*")
        .eq("tenant_id", auth.tenantId)
        .eq("is_resolved", false)
        .order("created_at", { ascending: false });

      if (error) {
        console.warn("Compliance Alerts - Supabase error:", error);
      } else {
        data = d || [];
      }
    } catch {
      console.warn("Compliance Alerts - Connection failed.");
    }
    
    // Fallback to simulation
    if ((!data || data.length === 0) && isSimulationFallbackEnabled()) {
      const sim = getSimulationState();
      if (sim) {
        return NextResponse.json(sim.events.map((e: any) => ({
          id: String(e.id),
          hostname: e.agent_hostname,
          unit: "SIMULATION",
          software_name: e.type,
          message: `ALERTA SIMULADO: Detecção de ${e.type}`,
          created_at: e.timestamp
        })));
      }
    }

    return NextResponse.json(data);
  } catch (err: any) {
    console.error("GET /api/compliance/alerts error:", err);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

export async function DELETE(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "analyst");
    if (auth.response) return auth.response;

    const parsed = await readLimitedJson(request, 16 * 1024);
    if (parsed.response) return parsed.response;

    const id = readStringField(parsed.value as Record<string, unknown>, "id", 80);

    if (!id) {
      return NextResponse.json({ error: "ID do alerta e obrigatorio." }, { status: 400 });
    }

    try {
      const { error } = await supabaseAdmin
        .from("compliance_alerts")
        .update({ is_resolved: true })
        .eq("id", id)
        .eq("tenant_id", auth.tenantId);

      if (error) throw error;
      return NextResponse.json({ success: true });
    } catch (err) {
      if (isSimulationFallbackEnabled()) {
        console.warn("[ALERTS DELETE] Supabase offline, removing alert from simulation events.");
        const sim = getSimulationState();
        if (sim) {
          const originalLength = sim.events.length;
          sim.events = sim.events.filter((e: any) => String(e.id) !== id);
          if (sim.events.length !== originalLength) {
            saveSimulationState(sim);
          }
          return NextResponse.json({ success: true });
        }
      }
      throw err;
    }
  } catch (err: any) {
    console.error("DELETE /api/compliance/alerts error:", err);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
