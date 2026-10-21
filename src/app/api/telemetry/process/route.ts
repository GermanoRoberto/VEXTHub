import { NextResponse } from "next/server";
import { resolveVendor, getDeviceType } from "@/utils/network/resolver";
import { addLog } from "@/utils/server-logger";
import { supabaseAdmin } from "@/utils/supabase/admin";
import { createClient } from "@/utils/supabase/server";
import { hashAgentToken, verifyAgentBootstrapSecret } from "@/utils/security/agent-auth";
import { enrichTelemetryWithAI } from "@/utils/security/ai-analysis";
import { analyzeTelemetryInventory, type TelemetryFinding } from "@/utils/security/telemetry-detection";
import { isSimulationFallbackEnabled, getSimulationState, saveSimulationState } from "@/utils/simulation/reader";

export const dynamic = "force-dynamic";

async function authenticateProcessRequest(request: Request): Promise<boolean> {
  // 1. Check agent bootstrap secret (x-agent-secret, x-agent-key, x-vexthub-agent-key, Bearer secret)
  const agentAuth = verifyAgentBootstrapSecret(request);
  if (agentAuth.ok) {
    return true;
  }

  // 2. Check Authorization Bearer user JWT via Supabase Admin
  const authHeader = request.headers.get("authorization")?.trim();
  if (authHeader?.toLowerCase().startsWith("bearer ")) {
    const token = authHeader.slice(7).trim();
    if (token) {
      try {
        if (typeof supabaseAdmin?.auth?.getUser === "function") {
          const { data, error } = await supabaseAdmin.auth.getUser(token);
          if (!error && data?.user) {
            return true;
          }
        }
      } catch {
        // Fall through
      }
    }
  }

  // 3. Check Supabase user session via cookies
  const cookieHeader = request.headers.get("cookie")?.trim();
  if (cookieHeader) {
    try {
      const supabase = await createClient();
      const { data: { user }, error } = await supabase.auth.getUser();
      if (!error && user?.id && user.id !== "00000000-0000-0000-0000-000000000000") {
        return true;
      }
    } catch {
      // Fall through
    }
  }

  return false;
}

async function insertPulseRecord(machineId: string, unit: string, tenantId: string, reqId: string) {
  const now = new Date().toISOString();
  const attempts: Array<Record<string, string>> = [
    { machine_id: machineId, tenant_id: tenantId, unit },
    { machine_id: machineId, tenant_id: tenantId, unit, timestamp: now },
  ];

  for (const payload of attempts) {
    const { error } = await supabaseAdmin.from("pulses").insert(payload);
    if (!error) return;
    addLog("warn", `[${reqId}] Pulse insert attempt failed`, { payload, error: error.message });
  }
}

async function insertSecurityFindingAlert(
  finding: TelemetryFinding,
  hostname: string,
  unit: string,
  tenantId: string,
  machineId: string,
  reqId: string,
) {
  const softwareName = finding.software_name || finding.title;
  const message = `[${finding.severity.toUpperCase()}] ${finding.title}. Evidencia: ${finding.evidence}. Acao recomendada: ${finding.recommended_action}`;

  const { data: existingAlert } = await supabaseAdmin
    .from("compliance_alerts")
    .select("id")
    .eq("tenant_id", tenantId)
    .eq("hostname", hostname)
    .eq("software_name", softwareName)
    .eq("is_resolved", false)
    .maybeSingle();

  if (existingAlert) return;

  const richPayload = {
    tenant_id: tenantId,
    machine_id: machineId,
    hostname,
    unit,
    software_name: softwareName,
    message,
    severity: finding.severity,
    risk_score: finding.score,
    detection_category: finding.category,
    is_resolved: false,
    details: {
      category: finding.category,
      confidence: finding.confidence,
      score: finding.score,
      mitre: finding.mitre,
      evidence: finding.evidence,
      recommended_action: finding.recommended_action,
    },
  };

  const { error } = await supabaseAdmin.from("compliance_alerts").insert(richPayload);
  if (!error) return;

  addLog("warn", `[${reqId}] Rich security alert insert failed, retrying legacy shape`, { error: error.message });

  await supabaseAdmin.from("compliance_alerts").insert({
    tenant_id: tenantId,
    machine_id: machineId,
    hostname,
    unit,
    software_name: softwareName,
    message,
    is_resolved: false,
  });
}

export async function POST(request: Request) {
  const isAuth = await authenticateProcessRequest(request);
  if (!isAuth) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const reqId = Math.random().toString(36).slice(2, 8);
  addLog("info", `[${reqId}] Background telemetry processing started`);

  try {
    const body = await request.json();
    const { machineId, hostname, tenantId, issuedAgentToken, rawPayload: payload } = body;

    const agentVersion = String(payload.agent_version || payload.agentVersion || payload.version || "Unknown").trim().slice(0, 40);

    const normalizedInventory = payload.inventory_data && typeof payload.inventory_data === "object" ? { ...payload.inventory_data } : {};

    const rawNetworkAssets = Array.isArray(normalizedInventory.network_assets) ? normalizedInventory.network_assets : [];
    normalizedInventory.network_assets = rawNetworkAssets.map((asset: Record<string, unknown>) => {
      const mac = typeof asset.mac === "string" ? asset.mac : undefined;
      const ip = typeof asset.ip === "string" ? asset.ip : undefined;
      const assetHostname = typeof asset.hostname === "string" ? asset.hostname : undefined;
      const vendor = resolveVendor(mac);
      return { ...asset, mac, ip, hostname: assetHostname || null, vendor, device_type: getDeviceType(vendor, assetHostname, ip) };
    });

    normalizedInventory.software = Array.isArray(normalizedInventory.software) ? normalizedInventory.software : [];
    normalizedInventory.processes = Array.isArray(normalizedInventory.processes) ? normalizedInventory.processes : [];
    normalizedInventory.services = Array.isArray(normalizedInventory.services) ? normalizedInventory.services : [];
    normalizedInventory.startup_entries = Array.isArray(normalizedInventory.startup_entries) ? normalizedInventory.startup_entries : [];

    const realtimeAnalysis = analyzeTelemetryInventory(normalizedInventory);
    normalizedInventory.security_analysis = realtimeAnalysis;

    const unitName = typeof payload.unit === "string" && payload.unit.trim() ? payload.unit.trim().slice(0, 160) : "Sem Unidade";

    const machineData = {
      id: machineId,
      tenant_id: tenantId,
      hostname,
      serial_number: typeof payload.serial_number === "string" ? payload.serial_number.slice(0, 160) : null,
      unit: unitName,
      os_name: typeof payload.os_name === "string" ? payload.os_name.slice(0, 160) : null,
      cpu_info: typeof payload.cpu_info === "string" ? payload.cpu_info.slice(0, 240) : null,
      ram_total: typeof payload.ram_total === "string" ? payload.ram_total.slice(0, 80) : null,
      inventory_data: normalizedInventory,
      last_pulse: new Date().toISOString(),
      last_screenshot: payload.screenshot || null,
      agent_version: agentVersion,
      ...(issuedAgentToken ? { agent_token_hash: hashAgentToken(issuedAgentToken) } : {}),
    };

    let { error: machineError } = await supabaseAdmin.from("machines").upsert(machineData);
    if (machineError && machineError.message?.toLowerCase().includes("column")) {
      const safeData: Record<string, unknown> = { ...machineData };
      delete safeData.agent_version;
      delete safeData.last_screenshot;
      delete safeData.agent_token_hash;
      machineError = (await supabaseAdmin.from("machines").upsert(safeData)).error;
    }

    if (machineError) addLog("error", `[${reqId}] Machine upsert failed`, machineError);

    await insertPulseRecord(machineId, machineData.unit, tenantId, reqId);

    if (realtimeAnalysis.findings.length > 0) {
      for (const finding of realtimeAnalysis.findings) {
        await insertSecurityFindingAlert(finding, hostname, machineData.unit, tenantId, machineId, reqId);
      }
      const aiResult = await enrichTelemetryWithAI({
        hostname,
        unit: machineData.unit,
        riskScore: realtimeAnalysis.score,
        findings: realtimeAnalysis.findings,
      });
      if (aiResult.enabled) addLog(aiResult.error ? "warn" : "info", `[${reqId}] AI telemetry enrichment completed`, aiResult);
    }

    // --- COMPLIANCE ENGINE START ---
    try {
      const softwareList = normalizedInventory.software || [];
      if (softwareList.length > 0) {
        const { data: forbiddenPolicies } = await supabaseAdmin.from("software_policies").select("name").eq("tenant_id", tenantId).eq("status", "forbidden");
        const forbiddenNames = new Set(forbiddenPolicies?.map((p: any) => p.name) || []);
        const violations = softwareList.filter((s: any) => s.name && forbiddenNames.has(s.name));

        if (violations.length > 0) {
          for (const v of violations) {
            const { data: existingAlert } = await supabaseAdmin.from("compliance_alerts").select("id").eq("tenant_id", tenantId).eq("hostname", hostname).eq("software_name", v.name).eq("is_resolved", false).maybeSingle();
            if (!existingAlert) {
              await supabaseAdmin.from("compliance_alerts").insert({
                tenant_id: tenantId, machine_id: machineId, hostname: hostname,
                unit: machineData.unit, software_name: v.name, message: `Software proibido detectado: ${v.name}`, is_resolved: false
              });
            }
          }
        }
      }
    } catch (complianceErr) {
      addLog("error", `[${reqId}] Compliance Engine failed`, complianceErr);
    }

    // --- LOCAL PERSISTENCE SYNC ---
    if (isSimulationFallbackEnabled()) {
      try {
        const sim = getSimulationState();
        if (sim) {
          const existingIdx = sim.machines.findIndex((m: any) => m.id === machineId);
          const updatedMachine = {
            id: machineId, hostname: hostname, ip: payload.ip || "Unknown",
            unit: unitName, status: "online" as const, last_pulse: machineData.last_pulse,
            os_name: machineData.os_name, cpu_info: machineData.cpu_info, ram_total: machineData.ram_total,
            agent_version: machineData.agent_version, inventory_data: normalizedInventory,
            telemetry: { cpu: Math.floor(Math.random() * 20) + 10, ram: Math.floor(Math.random() * 30) + 40, disk: 50 }
          };
          if (existingIdx >= 0) sim.machines[existingIdx] = { ...sim.machines[existingIdx], ...updatedMachine };
          else sim.machines.push(updatedMachine);
          saveSimulationState(sim);
        }
      } catch (persistErr) {
        addLog("warn", `[${reqId}] Local persistence sync failed`, persistErr);
      }
    }

    addLog("info", `[${reqId}] Background telemetry processed successfully`);
    return NextResponse.json({ success: true });
  } catch (err: any) {
    addLog("error", `[${reqId}] Background telemetry crashed`, err?.message || String(err));
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  }
}
