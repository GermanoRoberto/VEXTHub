import { supabaseAdmin } from "@/utils/supabase/admin";
import { NextResponse } from "next/server";
const AGENT_SOURCE_CODE = `
# VextHub Agent Code Mock
$AgentVersion = "4.2.0-stable"
`;
import { requireTenantAccess } from "@/utils/security/api-auth";
import { getSimulationState, isSimulationFallbackEnabled } from "@/utils/simulation/reader";

export const dynamic = "force-dynamic";

async function getLastPulseTimestamp(tenantId: string) {
  const createdAtQuery = await supabaseAdmin
    .from("pulses")
    .select("created_at")
    .eq("tenant_id", tenantId)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!createdAtQuery.error && createdAtQuery.data?.created_at) {
    return createdAtQuery.data.created_at as string;
  }

  const timestampQuery = await supabaseAdmin
    .from("pulses")
    .select("timestamp")
    .eq("tenant_id", tenantId)
    .order("timestamp", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!timestampQuery.error && timestampQuery.data?.timestamp) {
    return timestampQuery.data.timestamp as string;
  }

  return null;
}

function getSimulationLastPulseTimestamp() {
  const state = getSimulationState();
  if (!state?.machines?.length) return null;

  return (
    state.machines
      .map((machine) => machine.last_pulse)
      .filter(Boolean)
      .sort()
      .at(-1) || null
  );
}

function getLatestAgentVersion() {
  if (!AGENT_SOURCE_CODE) return "Desconhecida";

  const versionMatch = AGENT_SOURCE_CODE.match(/\$AgentVersion\s*=\s*"([^"]+)"/);
  return versionMatch?.[1] || "Desconhecida";
}

export async function GET(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "viewer");
    if (auth.response) return auth.response;

    const latestVersion = getLatestAgentVersion();
    let fleet: Array<{ agent_version?: string | null }> = [];
    let lastPulseTimestamp: string | null = null;

    try {
      const { data: machines, error } = await supabaseAdmin
        .from("machines")
        .select("agent_version")
        .eq("tenant_id", auth.tenantId);

      if (error) throw error;

      fleet = machines || [];
      lastPulseTimestamp = await getLastPulseTimestamp(auth.tenantId!);
    } catch (dbError: any) {
      if (!isSimulationFallbackEnabled()) throw dbError;

      console.warn("[UPDATES API] Supabase unavailable, using simulation fallback:", dbError.message);
      const state = getSimulationState();
      if (!state) throw dbError;

      fleet = state.machines.map((machine) => ({ agent_version: machine.agent_version }));
      lastPulseTimestamp = getSimulationLastPulseTimestamp();
    }

    const total = fleet.length;
    const updated = fleet.filter((machine) => machine.agent_version === latestVersion).length;
    const outdated = total - updated;

    return NextResponse.json({
      latest_version: latestVersion,
      last_pulse_debug: lastPulseTimestamp || "Nenhum pulso encontrado",
      stats: {
        total,
        updated,
        outdated,
        percentage: total > 0 ? Math.round((updated / total) * 100) : 100,
      },
    });
  } catch (err: any) {
    console.error("[UPDATES API] Error:", err.message);
    return NextResponse.json({ error: "Internal error" }, { status: 500 });
  }
}
