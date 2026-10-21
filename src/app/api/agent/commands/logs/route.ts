import { supabaseAdmin } from "@/utils/supabase/admin";
import { NextResponse } from "next/server";
import { requireTenantAccess } from "@/utils/security/api-auth";
import { isSimulationFallbackEnabled, listSimulatedAgentCommands } from "@/utils/simulation/reader";

export async function GET(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "viewer");
    if (auth.response) return auth.response;

    const { searchParams } = new URL(request.url);
    const unit = searchParams.get("unit");
    const status = searchParams.get("status");

    let query = supabaseAdmin
      .from("agent_commands")
      .select(`
        *,
        machines (
          hostname,
          unit
        )
      `)
      .eq("tenant_id", auth.tenantId)
      .order("created_at", { ascending: false })
      .limit(200);

    if (status) {
      query = query.eq("status", status);
    }

    const { data, error } = await query;
    if (error) throw error;

    const filteredData = unit
      ? (data || []).filter((item: { machines?: { unit?: string } | null }) => item.machines?.unit === unit)
      : data;

    return NextResponse.json(filteredData);
  } catch (err: any) {
    if (!isSimulationFallbackEnabled()) {
      console.error("[VextHub Actions] Error fetching command logs:", err.message);
      return NextResponse.json({ error: err.message }, { status: 500 });
    }

    console.warn("[VextHub Actions] Supabase unavailable, reading simulation command logs:", err.message);
    try {
      const { searchParams } = new URL(request.url);
      return NextResponse.json(listSimulatedAgentCommands({
        unit: searchParams.get("unit"),
        status: searchParams.get("status"),
      }));
    } catch (fallbackErr: any) {
      console.error("[VextHub Actions] Error fetching simulated logs:", fallbackErr.message);
      return NextResponse.json({ error: fallbackErr.message }, { status: 500 });
    }
  }
}
