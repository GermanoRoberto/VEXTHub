import { NextResponse } from "next/server";
import { supabaseAdmin } from "@/utils/supabase/admin";
import { requireTenantAccess } from "@/utils/security/api-auth";
import { readLimitedJson, readOptionalStringField, readStringField } from "@/utils/security/request-validation";
import { isSimulationFallbackEnabled, enqueueSimulatedMassCompliance } from "@/utils/simulation/reader";

export async function POST(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "analyst");
    if (auth.response) return auth.response;

    const parsed = await readLimitedJson(request, 32 * 1024);
    if (parsed.response) return parsed.response;

    const body = parsed.value as Record<string, unknown>;
    const software_name = readStringField(body, "software_name", 160);
    const unit_name = readOptionalStringField(body, "unit_name", 160);

    if (!software_name) {
      return NextResponse.json({ error: "software_name is required for mass actions" }, { status: 400 });
    }

    try {
      let query = supabaseAdmin
        .from("machines")
        .select("id, hostname, unit, inventory_data")
        .eq("tenant_id", auth.tenantId);

      if (unit_name) {
        query = query.eq("unit", unit_name);
      }

      const { data: machines, error: fetchError } = await query;
      if (fetchError) throw fetchError;

      const targets = machines?.filter((machine: any) => {
        const software = machine.inventory_data?.software || [];
        return software.some((entry: any) => entry.name === software_name);
      }) || [];

      if (targets.length === 0) {
        return NextResponse.json({
          success: true,
          message: "No target machines found for this software.",
          count: 0,
        });
      }

      const commandsToInsert = targets.map((machine: any) => ({
        machine_id: machine.id,
        tenant_id: auth.tenantId,
        command_type: "RUN_COMPLIANCE_SCAN",
        target: String(software_name).slice(0, 160),
        status: "pending",
      }));

      const { data: enqueued, error: insertError } = await supabaseAdmin
        .from("agent_commands")
        .insert(commandsToInsert)
        .select();

      if (insertError) throw insertError;

      console.log(`[VextHub Actions] ${enqueued.length} compliance scans queued for: ${software_name}`);

      return NextResponse.json({
        success: true,
        message: `Revalidacao de compliance enfileirada para ${enqueued.length} maquinas.`,
        count: enqueued.length,
      });
    } catch (supabaseErr: any) {
      if (!isSimulationFallbackEnabled()) throw supabaseErr;

      console.warn("[VextHub Actions] Supabase unavailable, using simulation mass queue:", supabaseErr.message);
      const result = enqueueSimulatedMassCompliance({
        softwareName: software_name,
        unitName: unit_name,
        tenantId: auth.tenantId,
      });

      if (!result.ok) {
        return NextResponse.json({ error: result.error }, { status: 500 });
      }

      return NextResponse.json({
        success: true,
        message: `Revalidacao enfileirada para ${result.commands.length} maquinas simuladas.`,
        count: result.commands.length,
        source: "simulation",
      });
    }
  } catch (err: any) {
    console.error("[VextHub Actions] Error enqueuing mass compliance action:", err.message);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
