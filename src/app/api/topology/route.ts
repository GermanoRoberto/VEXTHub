import { NextResponse } from "next/server";
import { getSimulationState, isSimulationFallbackEnabled } from "@/utils/simulation/reader";
import { supabaseAdmin } from "@/utils/supabase/admin";
import { requireTenantAccess } from "@/utils/security/api-auth";

export async function GET(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "viewer");
    if (auth.response) return auth.response;

    // 1. Try local simulation state
    const sim = isSimulationFallbackEnabled() ? getSimulationState() : null;
    if (sim) {
      return NextResponse.json({
        units: sim.units.map((u: any) => ({
          ...u,
          latitude: typeof u.latitude === 'number' ? u.latitude : u.lat,
          longitude: typeof u.longitude === 'number' ? u.longitude : u.lon
        })),
        // For 2,700 agents, we might want to sample or return all if the frontend can handle it
        // Let's return all but allow the frontend to decide
        machines: sim.machines.map((m: any) => ({
          id: m.id,
          hostname: m.hostname,
          ip: m.ip,
          unit: m.unit,
          status: m.status,
          // Random initial positions for the force graph if not provided
          x: Math.random() * 100,
          y: Math.random() * 100
        })),
        events: sim.events
      });
    }

    // 2. Fallback to Supabase
    const { data: units } = await supabaseAdmin.from("units").select("*").eq("tenant_id", auth.tenantId);
    const { data: machines } = await supabaseAdmin.from("machines").select("id, hostname, ip, unit, last_pulse").eq("tenant_id", auth.tenantId);

    return NextResponse.json({
      units: units || [],
      machines: machines?.map((m: any) => ({
        ...m,
        status: (new Date().getTime() - new Date(m.last_pulse).getTime()) < 300000 ? 'online' : 'offline',
        x: Math.random() * 100,
        y: Math.random() * 100
      })) || [],
      events: []
    });

  } catch (error: any) {
    console.error("Topology API Error:", error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
