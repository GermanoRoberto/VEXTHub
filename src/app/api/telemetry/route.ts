import { NextResponse } from "next/server";
import { addLog } from "@/utils/server-logger";
import { supabaseAdmin } from "@/utils/supabase/admin";
import {
  createAgentToken,
  getAgentToken,
  verifyAgentBootstrapSecret,
  verifyAgentToken,
} from "@/utils/security/agent-auth";
import { normalizeAgentCommand, sanitizeCommandTarget } from "@/utils/security/agent-commands";
import { readLimitedJson } from "@/utils/security/request-validation";
import { isSimulationFallbackEnabled, recordSimulatedTelemetryPulse, takePendingSimulatedAgentCommands } from "@/utils/simulation/reader";
import { redis } from "@/utils/redis";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const reqId = Math.random().toString(36).slice(2, 8);
  addLog("info", `[${reqId}] Telemetry request received`);

  try {
    const parsed = await readLimitedJson(request);
    if (parsed.response) return parsed.response;
    const payload: any = parsed.value;

    if (!payload || typeof payload !== "object") {
      return NextResponse.json({ error: "Invalid payload" }, { status: 400 });
    }

    const machineId = String(payload.machine_id || payload.machineId || payload.id || "").trim().slice(0, 160);
    const hostname = String(payload.hostname || payload.Hostname || "Unknown").trim().slice(0, 160) || "Unknown";
    const payloadTenantId = typeof payload.tenant_id === "string" ? payload.tenant_id.trim() : null;
    const simulationStressRequest =
      isSimulationFallbackEnabled() &&
      ["stress", "local"].includes((request.headers.get("x-vexthub-simulation") || "").toLowerCase());

    if (!machineId) {
      return NextResponse.json({ error: "Missing machine identification" }, { status: 400 });
    }

    let machine: { id: string; unit?: string | null; tenant_id?: string | null; agent_token_hash?: string | null } | null = null;

    if (!simulationStressRequest) {
      const { data } = await supabaseAdmin
        .from("machines")
        .select("id, unit, tenant_id, agent_token_hash")
        .eq("id", machineId)
        .maybeSingle();
      machine = data;
    }

    if (!machine && hostname !== "Unknown" && payloadTenantId) {
      if (!simulationStressRequest) {
        const { data: hostMachine } = await supabaseAdmin
          .from("machines")
          .select("id, unit, tenant_id, agent_token_hash")
          .eq("tenant_id", payloadTenantId)
          .eq("hostname", hostname)
          .maybeSingle();
        machine = hostMachine;
      }
    }

    const tenantId = machine?.tenant_id || payloadTenantId;
    if (!tenantId) {
      return NextResponse.json({ error: "Missing tenant identification" }, { status: 400 });
    }

    const presentedAgentToken = getAgentToken(request);
    let issuedAgentToken: string | null = null;

    let unitAgentKey: string | null = null;
    const unitName = typeof payload.unit === "string" ? payload.unit.trim() : (machine?.unit || null);
    if (tenantId && unitName) {
      try {
        const { data: unitData } = await supabaseAdmin
          .from("units")
          .select("agent_key")
          .eq("tenant_id", tenantId)
          .eq("name", unitName)
          .maybeSingle();
        if (unitData?.agent_key?.trim()) {
          unitAgentKey = unitData.agent_key.trim();
        }
      } catch (unitErr) {
        console.warn("Could not fetch unit agent_key:", unitErr);
      }
    }

    if (machine?.agent_token_hash) {
      if (!verifyAgentToken(presentedAgentToken, machine.agent_token_hash)) {
        return NextResponse.json({ error: "Unauthorized agent token." }, { status: 401 });
      }
    } else {
      const bootstrapAuth = verifyAgentBootstrapSecret(request, unitAgentKey);
      if (!bootstrapAuth.ok) {
        return NextResponse.json({ error: bootstrapAuth.error }, { status: bootstrapAuth.status });
      }
      issuedAgentToken = createAgentToken();
    }

    const finalId = machine?.id || machineId;

    // 1. Fetch commands synchronously so the agent receives them immediately
    let rawCommands: Array<{ id: string | number; command_type: string; target: string | null }> | null = null;
    let commandsError: unknown = null;
    
    let commandsFromSimulation = false;

    if (simulationStressRequest) {
      rawCommands = takePendingSimulatedAgentCommands(finalId, hostname);
      commandsFromSimulation = true;
    } else {
      const result = await supabaseAdmin
        .from("agent_commands")
        .select("id, command_type, target")
        .eq("tenant_id", tenantId)
        .eq("machine_id", finalId)
        .eq("status", "pending")
        .order("created_at", { ascending: true });
      rawCommands = result.data;
      commandsError = result.error;
    }

    if (commandsError) {
      if (isSimulationFallbackEnabled()) {
        try {
          rawCommands = takePendingSimulatedAgentCommands(finalId, hostname);
          commandsError = null;
          commandsFromSimulation = true;
        } catch {
          // Ignore
        }
      }
    }

    const commands: Array<{ id: string | number; command_type: string; target: string | null }> = [];
    const rejectedCommandIds: Array<string | number> = [];

    for (const command of rawCommands || []) {
      const commandType = normalizeAgentCommand(command.command_type);
      if (!commandType) {
        rejectedCommandIds.push(command.id);
        continue;
      }
      commands.push({ id: command.id, command_type: commandType, target: sanitizeCommandTarget(command.target) });
    }

    if (rejectedCommandIds.length > 0 && !commandsFromSimulation) {
      await supabaseAdmin.from("agent_commands").update({ status: "rejected", result: "Blocked by VextHub safe command allowlist" })
        .eq("tenant_id", tenantId).in("id", rejectedCommandIds);
    }
    if (commands.length > 0 && !commandsFromSimulation) {
      await supabaseAdmin.from("agent_commands").update({ status: "sent" })
        .eq("tenant_id", tenantId).in("id", commands.map((c: any) => c.id));
    }

    const mirrorToSimulation =
      isSimulationFallbackEnabled() &&
      process.env.VEXTHUB_SIMULATION_MIRROR_TELEMETRY !== "false";

    if (mirrorToSimulation) {
      const result = recordSimulatedTelemetryPulse({
        machineId: finalId,
        hostname,
        tenantId,
        payload,
      });
      if (!result.ok) {
        addLog("warn", `[${reqId}] Simulation telemetry mirror failed`, result.error);
      }
    }

    const skipQueue = simulationStressRequest && request.headers.get("x-vexthub-skip-queue") === "true";
    let queued = false;

    // 2. Queue the heavy processing to Redis
    const jobId = `tel_${reqId}`;
    if (!skipQueue) {
      try {
        await redis.lpush("vexthub:jobs", JSON.stringify({
          id: jobId,
          type: "telemetry.process",
          payload: {
            machineId: finalId,
            hostname,
            tenantId,
            issuedAgentToken,
            rawPayload: payload
          }
        }));
        queued = true;
        addLog("info", `[${reqId}] Telemetry queued to Redis for background processing`, { jobId });
      } catch (redisError: any) {
        addLog("error", `[${reqId}] Failed to push to Redis queue`, redisError.message);
        if (!isSimulationFallbackEnabled()) {
          return NextResponse.json({ error: "Telemetry queue unavailable" }, { status: 503 });
        }
      }
    }

    return NextResponse.json({
      success: true,
      status: queued ? "queued" : "mirrored_local",
      security_analysis: { score: 100, risk_level: "low", findings: 0 }, // Stubbed for instant response, calculated in background
      commands: commands || [],
      agent_id: finalId,
      ...(issuedAgentToken ? { agent_token: issuedAgentToken } : {}),
    });
  } catch (err: any) {
    addLog("error", `[${reqId}] Telemetry gateway crashed`, err?.message || String(err));
    return NextResponse.json(
      { error: "Internal Server Error", details: err?.message || String(err) },
      { status: 500 },
    );
  }
}
