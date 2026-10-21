import { NextResponse } from "next/server";
import { supabaseAdmin } from "@/utils/supabase/admin";
import { normalizeAgentCommand, sanitizeCommandTarget } from "@/utils/security/agent-commands";
import { requireTenantAccess } from "@/utils/security/api-auth";
import { readLimitedJson, readOptionalStringField, readStringField } from "@/utils/security/request-validation";
import { isSimulationFallbackEnabled, enqueueSimulatedBroadcastCommands } from "@/utils/simulation/reader";

export async function POST(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "analyst");
    if (auth.response) return auth.response;

    const parsed = await readLimitedJson(request, 32 * 1024);
    if (parsed.response) return parsed.response;

    const body = parsed.value as Record<string, unknown>;
    const target_audience = readStringField(body, "target_audience", 32);
    const unit_name = readOptionalStringField(body, "unit_name", 160);
    const command_type = readStringField(body, "command_type", 80);
    const target_script = readOptionalStringField(body, "target_script", 160);
    const safeCommand = normalizeAgentCommand(command_type);

    if (!target_audience || !command_type) {
      return NextResponse.json({ error: "Missing required fields" }, { status: 400 });
    }

    if (!safeCommand) {
      return NextResponse.json({ error: "Unsupported agent action" }, { status: 400 });
    }

    try {
      let query = supabaseAdmin
        .from("machines")
        .select("id, hostname, unit")
        .eq("tenant_id", auth.tenantId);

      if (target_audience === "UNIT" && unit_name) {
        query = query.eq("unit", unit_name);
      }

      const { data: machines, error: fetchError } = await query;
      if (fetchError) throw fetchError;

      if (!machines || machines.length === 0) {
        return NextResponse.json({
          success: true,
          message: "No target machines found in the specified scope.",
          count: 0,
        });
      }

      const commandsToInsert = machines.map((machine: any) => ({
        machine_id: machine.id,
        tenant_id: auth.tenantId,
        command_type: safeCommand,
        target: sanitizeCommandTarget(target_script),
        status: "pending",
      }));

      const { data: enqueued, error: insertError } = await supabaseAdmin
        .from("agent_commands")
        .insert(commandsToInsert)
        .select();

      if (insertError) throw insertError;

      console.log(
        `[VextHub Actions] ${enqueued.length} actions (${safeCommand}) queued. Scope: ${target_audience}`,
      );

      return NextResponse.json({
        success: true,
        message: `Acao segura enfileirada para ${enqueued.length} maquinas.`,
        count: enqueued.length,
      });
    } catch (supabaseErr: any) {
      if (!isSimulationFallbackEnabled()) throw supabaseErr;

      console.warn("[VextHub Actions] Supabase unavailable, using simulation broadcast queue:", supabaseErr.message);
      const result = enqueueSimulatedBroadcastCommands({
        unitName: target_audience === "UNIT" ? unit_name : null,
        commandType: safeCommand,
        target: sanitizeCommandTarget(target_script),
        tenantId: auth.tenantId,
      });

      if (!result.ok) {
        return NextResponse.json({ error: result.error }, { status: 500 });
      }

      return NextResponse.json({
        success: true,
        message: `Acao segura enfileirada para ${result.commands.length} maquinas simuladas.`,
        count: result.commands.length,
        source: "simulation",
      });
    }
  } catch (err: any) {
    console.error("[VextHub Actions] Error enqueuing broadcast action:", err.message);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
