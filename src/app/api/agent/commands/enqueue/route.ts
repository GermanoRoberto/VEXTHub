import { NextResponse } from "next/server";
import { supabaseAdmin } from "@/utils/supabase/admin";
import { normalizeAgentCommand, sanitizeCommandTarget } from "@/utils/security/agent-commands";
import { logAuditEvent, requireTenantAccess } from "@/utils/security/api-auth";
import { readLimitedJson, readOptionalStringField, readStringField } from "@/utils/security/request-validation";
import { isSimulationFallbackEnabled, enqueueSimulatedAgentCommand } from "@/utils/simulation/reader";

export async function POST(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "analyst");
    if (auth.response) return auth.response;

    const parsed = await readLimitedJson(request, 32 * 1024);
    if (parsed.response) return parsed.response;

    const body = parsed.value as Record<string, unknown>;
    const machine_id = readOptionalStringField(body, "machine_id", 160);
    const hostname = readOptionalStringField(body, "hostname", 160);
    const command_type = readStringField(body, "command_type", 80);
    const target = readOptionalStringField(body, "target", 160);
    const safeCommand = normalizeAgentCommand(command_type);

    if (!machine_id && !hostname) {
      return NextResponse.json({ error: "machine_id or hostname missing" }, { status: 400 });
    }

    if (!safeCommand) {
      return NextResponse.json({ error: "Unsupported agent action" }, { status: 400 });
    }

    let finalMachineId = machine_id;

    try {
      if (!finalMachineId && hostname) {
        const { data: machine, error: lookupError } = await supabaseAdmin
          .from("machines")
          .select("id")
          .eq("tenant_id", auth.tenantId)
          .eq("hostname", hostname)
          .maybeSingle();
        if (lookupError) throw lookupError;
        finalMachineId = machine?.id;
      }

      if (!finalMachineId) {
        return NextResponse.json({ error: "Machine not found" }, { status: 404 });
      }

      const { data: targetMachine, error: targetError } = await supabaseAdmin
        .from("machines")
        .select("id")
        .eq("tenant_id", auth.tenantId)
        .eq("id", finalMachineId)
        .maybeSingle();

      if (targetError) throw targetError;

      if (!targetMachine) {
        return NextResponse.json({ error: "Machine not found in tenant" }, { status: 404 });
      }

      const { data, error } = await supabaseAdmin
        .from("agent_commands")
        .insert({
          machine_id: finalMachineId,
          tenant_id: auth.tenantId,
          command_type: safeCommand,
          target: sanitizeCommandTarget(target),
          status: "pending",
        })
        .select()
        .single();

      if (error) throw error;

      await logAuditEvent({
        tenantId: auth.tenantId,
        actorUserId: auth.user?.id,
        action: "COMMAND_ENQUEUE",
        targetType: "agent_commands",
        targetId: data?.id,
        details: { machine_id: finalMachineId, command_type: safeCommand, target },
      });

      return NextResponse.json({ success: true, command: data });
    } catch (supabaseErr: any) {
      if (!isSimulationFallbackEnabled()) throw supabaseErr;

      console.warn("[VextHub Actions] Supabase unavailable, using simulation command queue:", supabaseErr.message);
      const result = enqueueSimulatedAgentCommand({
        machineId: finalMachineId || machine_id,
        hostname,
        commandType: safeCommand,
        target: sanitizeCommandTarget(target),
        tenantId: auth.tenantId,
      });

      if (!result.ok) {
        return NextResponse.json({ error: result.error }, { status: result.error.includes("not found") ? 404 : 500 });
      }

      return NextResponse.json({
        success: true,
        command: result.command,
        source: "simulation",
        message: `Acao ${safeCommand} enfileirada para ${result.command.hostname}.`,
      });
    }
  } catch (err: any) {
    console.error("[VextHub Actions] Error enqueuing action:", err.message);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
