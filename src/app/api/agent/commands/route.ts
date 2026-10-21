import { supabaseAdmin } from "@/utils/supabase/admin";
import { NextResponse } from "next/server";
import { getAgentToken, verifyAgentBootstrapSecret, verifyAgentToken } from "@/utils/security/agent-auth";
import { readLimitedJson, readOptionalStringField, readStringField } from "@/utils/security/request-validation";
import { isSimulationFallbackEnabled, updateSimulatedAgentCommandStatus } from "@/utils/simulation/reader";

export async function POST(request: Request) {
  try {
    const parsed = await readLimitedJson(request, 64 * 1024);
    if (parsed.response) return parsed.response;

    const body = parsed.value as Record<string, unknown>;
    const command_id = readStringField(body, "command_id", 80);
    const machine_id = readStringField(body, "machine_id", 160);
    const status = readStringField(body, "status", 32);
    const output = readOptionalStringField(body, "output", 4000);
    const requestedStatus = status === "executed" ? "completed" : (status || "completed");
    const normalizedStatus: "completed" | "failed" | "rejected" =
      requestedStatus === "failed" || requestedStatus === "rejected" ? requestedStatus : "completed";

    if (!command_id || !machine_id) {
      return NextResponse.json({ error: "command_id and machine_id are required" }, { status: 400 });
    }

    try {
      const { data: command, error: commandError } = await supabaseAdmin
        .from("agent_commands")
        .select("id, tenant_id, machine_id")
        .eq("id", command_id)
        .eq("machine_id", machine_id)
        .maybeSingle();

      if (commandError) throw commandError;

      if (!command) {
        return NextResponse.json({ error: "Command not found" }, { status: 404 });
      }

      const { data: machine, error: machineError } = await supabaseAdmin
        .from("machines")
        .select("unit_id, unit, agent_token_hash")
        .eq("id", machine_id)
        .eq("tenant_id", command.tenant_id)
        .maybeSingle();

      if (machineError) throw machineError;

      let unitAgentKey: string | null = null;
      if (machine?.unit_id || machine?.unit) {
        try {
          let uQuery = supabaseAdmin.from("units").select("agent_key").eq("tenant_id", command.tenant_id);
          if (machine.unit_id) {
            uQuery = uQuery.eq("id", machine.unit_id);
          } else if (machine.unit) {
            uQuery = uQuery.eq("name", machine.unit);
          }
          const { data: unitData } = await uQuery.maybeSingle();
          if (unitData?.agent_key?.trim()) {
            unitAgentKey = unitData.agent_key.trim();
          }
        } catch {}
      }

      if (machine?.agent_token_hash) {
        if (!verifyAgentToken(getAgentToken(request), machine.agent_token_hash)) {
          return NextResponse.json({ error: "Unauthorized agent token." }, { status: 401 });
        }
      } else {
        const agentAuth = verifyAgentBootstrapSecret(request, unitAgentKey);
        if (!agentAuth.ok) {
          return NextResponse.json({ error: agentAuth.error }, { status: agentAuth.status });
        }
      }

      const { error } = await supabaseAdmin
        .from("agent_commands")
        .update({
          status: normalizedStatus,
          result: output || null,
          updated_at: new Date().toISOString(),
        })
        .eq("id", command_id)
        .eq("machine_id", machine_id)
        .eq("tenant_id", command.tenant_id);

      if (error) throw error;

      return NextResponse.json({ success: true });
    } catch (supabaseErr: any) {
      if (!isSimulationFallbackEnabled()) throw supabaseErr;

      const agentAuth = verifyAgentBootstrapSecret(request);
      if (!agentAuth.ok) {
        return NextResponse.json({ error: agentAuth.error }, { status: agentAuth.status });
      }

      console.warn("[VextHub Actions] Supabase unavailable, updating simulated command:", supabaseErr.message);
      const result = updateSimulatedAgentCommandStatus({
        commandId: command_id,
        machineId: machine_id,
        status: normalizedStatus,
        output,
      });

      if (!result.ok) {
        return NextResponse.json({ error: result.error }, { status: result.error.includes("not found") ? 404 : 500 });
      }

      return NextResponse.json({ success: true, source: "simulation" });
    }
  } catch (err: any) {
    console.error("[VextHub Actions] Error updating action status:", err.message);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
