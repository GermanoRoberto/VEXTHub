/**
 * VextHub Autonomous OODA Loop & Auto-Mitigation Engine
 * Evaluates risk threshold breaches, enqueues safe defensive agent actions, and tracks AI decision history.
 */

import { supabaseAdmin } from "@/utils/supabase/admin";
import { enqueueSimulatedAgentCommand } from "@/utils/simulation/reader";

export interface AutonomousActionRecord {
  id: string;
  timestamp: string;
  hostname: string;
  unit: string;
  triggerReason: string;
  actionType: 'RUN_COMPLIANCE_SCAN' | 'REFRESH_INVENTORY' | 'UPDATE_AGENT';
  target?: string;
  status: 'EXECUTED' | 'ENQUEUED' | 'VERIFYING';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

// In-memory autonomous actions buffer (capped at 100)
const autonomousActionLog: AutonomousActionRecord[] = [];

export function getAutonomousActionLog(): AutonomousActionRecord[] {
  return [...autonomousActionLog].slice(0, 50);
}

/**
 * Enqueues a remediation command into agent_commands (with audit_log) and falls back to local simulation store.
 */
async function enqueueRemediationAction(params: {
  machineId: string;
  hostname: string;
  unit: string;
  actionType: 'RUN_COMPLIANCE_SCAN' | 'REFRESH_INVENTORY' | 'UPDATE_AGENT';
  target?: string;
  triggerReason: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  tenantId?: string;
}): Promise<AutonomousActionRecord> {
  const now = new Date().toISOString();
  const uuidSuffix = crypto.randomUUID().slice(0, 8);
  const actionId = `AUTO-${params.actionType.slice(0, 4)}-${Date.now()}-${uuidSuffix}`;

  let persisted = false;

  if (params.tenantId && params.tenantId !== "00000000-0000-0000-0000-000000000000") {
    try {
      const { data: cmd, error: cmdError } = await supabaseAdmin
        .from("agent_commands")
        .insert({
          tenant_id: params.tenantId,
          machine_id: params.machineId,
          command_type: params.actionType,
          target: params.target || null,
          status: "pending",
        })
        .select("id")
        .maybeSingle();

      if (!cmdError && cmd?.id) {
        persisted = true;

        // Record in public.audit_log
        await supabaseAdmin
          .from("audit_log")
          .insert({
            tenant_id: params.tenantId,
            actor_user_id: null, // Autonomous Engine / System
            action: "AUTONOMOUS_DEFENSE_ENQUEUE",
            target_type: "agent_commands",
            target_id: cmd.id,
            details: {
              hostname: params.hostname,
              machine_id: params.machineId,
              command_type: params.actionType,
              trigger_reason: params.triggerReason,
              severity: params.severity,
              target: params.target || null,
            },
          });
      }
    } catch (dbErr: any) {
      console.warn("[AutonomousDefense] Supabase persistence failed, using local store fallback:", dbErr?.message);
    }
  }

  // Fallback to local simulation store if database is offline or unconfigured
  if (!persisted) {
    enqueueSimulatedAgentCommand({
      machineId: params.machineId,
      hostname: params.hostname,
      commandType: params.actionType,
      target: params.target || params.triggerReason,
      tenantId: params.tenantId,
    });
  }

  const record: AutonomousActionRecord = {
    id: actionId,
    timestamp: now,
    hostname: params.hostname,
    unit: params.unit,
    triggerReason: params.triggerReason,
    actionType: params.actionType,
    target: params.target,
    status: "ENQUEUED",
    severity: params.severity,
  };

  autonomousActionLog.unshift(record);
  if (autonomousActionLog.length > 100) {
    autonomousActionLog.length = 100;
  }

  return record;
}

export async function evaluateAutonomousMitigation(input: {
  machines: Array<{
    id: string;
    hostname?: string | null;
    unit?: string | null;
    agent_version?: string | null;
    inventory_data?: any;
    telemetry?: { cpu?: number; ram?: number; disk?: number } | null;
  }>;
  anomalies?: Array<{ hostname: string; unit: string; maxZScore: number; anomalies: any[] }>;
  tenantId?: string;
}): Promise<AutonomousActionRecord[]> {
  const newActions: AutonomousActionRecord[] = [];
  const LATEST_AGENT_VERSION = "4.2.0-stable";
  const MAX_UPDATE_BATCH = 5;

  // 1. Auto-Mitigate High Z-score / High Risk machines
  if (input.anomalies && input.anomalies.length > 0) {
    for (const anomaly of input.anomalies) {
      if (anomaly.maxZScore >= 2.8) {
        const machine = input.machines.find(
          (m) => m.hostname === anomaly.hostname || m.id === anomaly.hostname
        );
        const machineId = machine?.id || anomaly.hostname;
        const unit = anomaly.unit || machine?.unit || "Sem Unidade";

        // Check if already enqueued in the active log
        const alreadyEnqueued = autonomousActionLog.some(
          (log) => log.hostname === anomaly.hostname && log.actionType === "RUN_COMPLIANCE_SCAN"
        );

        if (!alreadyEnqueued) {
          const record = await enqueueRemediationAction({
            machineId,
            hostname: anomaly.hostname,
            unit,
            actionType: "RUN_COMPLIANCE_SCAN",
            target: `Z-Score Anomaly Trigger (Z=${anomaly.maxZScore})`,
            triggerReason: `Pico de anomalia estatística detectado (Z-Score: ${anomaly.maxZScore})`,
            severity: anomaly.maxZScore >= 3.2 ? "CRITICAL" : "HIGH",
            tenantId: input.tenantId,
          });

          newActions.push(record);
        }
      }
    }
  }

  // 2. Auto-Mitigate Outdated Agent versions (deterministic queue, capped at MAX_UPDATE_BATCH)
  let updateBatchCount = 0;
  for (const machine of input.machines) {
    if (updateBatchCount >= MAX_UPDATE_BATCH) break;

    if (machine.agent_version && machine.agent_version !== LATEST_AGENT_VERSION) {
      const hostname = String(machine.hostname || machine.id);
      const unit = String(machine.unit || "Sem Unidade");

      // Check if already enqueued
      const exists = autonomousActionLog.some(
        (log) => log.hostname === hostname && log.actionType === "UPDATE_AGENT"
      );

      if (!exists) {
        const record = await enqueueRemediationAction({
          machineId: machine.id,
          hostname,
          unit,
          actionType: "UPDATE_AGENT",
          target: LATEST_AGENT_VERSION,
          triggerReason: `Agente desatualizado (Versão detectada: ${machine.agent_version})`,
          severity: "MEDIUM",
          tenantId: input.tenantId,
        });

        newActions.push(record);
        updateBatchCount++;
      }
    }
  }

  return newActions;
}
