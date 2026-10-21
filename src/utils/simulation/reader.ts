import fs from 'fs';
import path from 'path';

export interface SimulatedMachine {
  id: string;
  hostname: string;
  ip: string;
  unit: string;
  status: 'online' | 'offline';
  last_pulse: string;
  os_name?: string;
  cpu_info?: string;
  ram_total?: string;
  agent_version?: string;
  serial_number?: string;
  inventory_data?: {
    software?: Array<{ name?: string; [key: string]: unknown }>;
    system_details?: {
      active_user?: string;
      local_ip?: string;
      disk_total_gb?: number;
      disk_free_gb?: number;
      domain?: string;
    };
    [key: string]: unknown;
  };
  telemetry: {
    cpu: number;
    ram: number;
    disk: number;
  };
}

export interface SimulatedUnit {
  id: string;
  name: string;
  city?: string;
  state?: string;
  location: string;
  lat: number;
  lon: number;
  agent_key?: string;
  network_assets?: Array<Record<string, unknown>>;
}

export interface SimulatedEvent {
  id: number | string;
  agent_hostname?: string;
  machine?: string;
  unit?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'info';
  type: string;
  timestamp: string;
  description?: string;
  details?: Record<string, unknown>;
}

export interface SimulatedAgentCommand {
  id: string;
  machine_id: string;
  hostname: string;
  unit: string;
  tenant_id?: string;
  command_type: string;
  target: string | null;
  status: 'pending' | 'sent' | 'completed' | 'failed' | 'rejected';
  result?: string | null;
  created_at: string;
  updated_at: string;
}

export interface SimulationState {
  units: SimulatedUnit[];
  machines: SimulatedMachine[];
  events: SimulatedEvent[];
  agent_commands?: SimulatedAgentCommand[];
  stress_metrics?: Record<string, unknown>;
  software_policies?: Array<{ tenant_id?: string; name: string; status: string }>;
  unit_software_policies?: Array<{ tenant_id?: string; software_name: string; unit_name: string; status: string }>;
}

const STATE_FILE = path.join(process.cwd(), 'scripts', 'simulation_state.json');

// Performance Cache
let cachedState: SimulationState | null = null;
let lastCacheUpdate = 0;
let lastFileMtime = 0;
let lastStateWrite = 0;
const CACHE_TTL = 60000; // 60 seconds cache

export function isSimulationFallbackEnabled() {
  return process.env.VEXTHUB_ENABLE_SIMULATION_FALLBACK === 'true' || process.env.NODE_ENV !== 'production';
}

export function getSimulationState(): SimulationState | null {
  try {
    if (!fs.existsSync(STATE_FILE)) return cachedState;
    
    const now = Date.now();
    const stats = fs.statSync(STATE_FILE);
    const mtime = stats.mtimeMs;

    // 1. If cache exists AND file hasn't changed AND TTL is still valid -> Return Cache
    if (cachedState && mtime === lastFileMtime && (now - lastCacheUpdate < CACHE_TTL)) {
      return cachedState;
    }

    // 2. If file has changed OR cache is stale -> Re-read
    const data = fs.readFileSync(STATE_FILE, 'utf8');
    if (!data || data.trim().length === 0) return cachedState;

    cachedState = JSON.parse(data);
    lastCacheUpdate = now;
    lastFileMtime = mtime;
    
    return cachedState;
  } catch (error) {
    console.error('Error reading simulation state:', error);
    return cachedState;
  }
}

export function saveSimulationState(state: SimulationState, options: { throttleMs?: number } = {}): boolean {
  try {
    const now = Date.now();
    cachedState = state;
    lastCacheUpdate = now;

    if (options.throttleMs && now - lastStateWrite < options.throttleMs) {
      return true;
    }

    const tempFile = `${STATE_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(state, null, 2), 'utf8');
    fs.renameSync(tempFile, STATE_FILE);

    lastStateWrite = now;
    lastFileMtime = fs.statSync(STATE_FILE).mtimeMs;
    return true;
  } catch (error) {
    console.error('Error saving simulation state:', error);
    return false;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function boundedNumber(value: unknown, fallback: number, min: number, max: number) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.round(parsed)));
}

function buildFallbackSystemDetails(machine: SimulatedMachine, payload: Record<string, unknown>) {
  const seq = Number(machine.id.split('-').at(-1)) || 1;
  const diskTotal = seq % 3 === 0 ? 256 : 512;
  const diskUsed = boundedNumber(machine.telemetry?.disk, 50, 0, 100);
  const diskFree = Math.max(12, Math.round((diskTotal * (100 - diskUsed)) / 100));

  return {
    active_user: `${machine.unit.toLowerCase()}\\operador${String(seq).padStart(3, '0')}`,
    local_ip: String(payload.ip || machine.ip || '0.0.0.0'),
    disk_total_gb: diskTotal,
    disk_free_gb: diskFree,
    domain: `VEXT-${machine.unit}`,
  };
}

function detectSimulatedEvent(machine: SimulatedMachine, inventory: Record<string, unknown>) {
  const software = Array.isArray(inventory.software) ? inventory.software : [];
  const names = software
    .map((entry: any) => String(entry?.name || '').toLowerCase())
    .filter(Boolean);

  const vulnerabilities = Array.isArray(inventory.vulnerabilities) ? inventory.vulnerabilities : [];
  const hasCriticalVulnerability = vulnerabilities.length > 0;
  const hasSuspiciousTool = names.some((name) => (
    name.includes('mimikatz') ||
    name.includes('rustdesk') ||
    name.includes('teamviewer') ||
    name.includes('process hacker') ||
    name.includes('advanced ip scanner')
  ));

  if (hasCriticalVulnerability) {
    const first = vulnerabilities[0] as { cve?: string; software?: string };
    return {
      severity: 'CRITICAL' as const,
      type: `Exploit Detectado: ${first.cve || first.software || 'vulnerabilidade conhecida'}`,
    };
  }

  if (hasSuspiciousTool || inventory.is_infected) {
    return {
      severity: 'HIGH' as const,
      type: 'Cortex Forensics: ferramenta suspeita detectada no inventario',
    };
  }

  return null;
}

function ensureCommandQueue(state: SimulationState) {
  if (!Array.isArray(state.agent_commands)) {
    state.agent_commands = [];
  }
  return state.agent_commands;
}

function findSimulatedMachine(
  state: SimulationState,
  machineId?: string | null,
  hostname?: string | null,
) {
  const id = machineId?.trim();
  const host = hostname?.trim();
  return state.machines.find((machine) => {
    return (id && machine.id === id) || (host && machine.hostname === host);
  }) || null;
}

function newSimulationCommandId() {
  return `sim-cmd-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function prependCommandEvent(
  state: SimulationState,
  machine: SimulatedMachine,
  commandType: string,
  status: SimulatedAgentCommand['status'],
) {
  const label = status === 'pending' ? 'enfileirado' : status;
  state.events.unshift({
    id: `EVT-CMD-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date().toISOString(),
    agent_hostname: machine.hostname,
    unit: machine.unit,
    severity: 'LOW',
    type: `Comando de agente ${label}: ${commandType}`,
    description: `Acao defensiva ${commandType} registrada para ${machine.hostname}.`,
    details: {
      command_type: commandType,
      status,
      machine_id: machine.id,
    },
  });
  state.events = state.events.slice(0, 100);
}

export function enqueueSimulatedAgentCommand(input: {
  machineId?: string | null;
  hostname?: string | null;
  commandType: string;
  target?: string | null;
  tenantId?: string | null;
}) {
  const state = getSimulationState();
  if (!state) {
    return { ok: false as const, error: 'Simulation state not found.' };
  }

  const machine = findSimulatedMachine(state, input.machineId, input.hostname);
  if (!machine) {
    return { ok: false as const, error: 'Machine not found in simulation.' };
  }

  const now = new Date().toISOString();
  const command: SimulatedAgentCommand = {
    id: newSimulationCommandId(),
    machine_id: machine.id,
    hostname: machine.hostname,
    unit: machine.unit,
    tenant_id: input.tenantId || undefined,
    command_type: input.commandType,
    target: input.target || null,
    status: 'pending',
    created_at: now,
    updated_at: now,
  };

  ensureCommandQueue(state).unshift(command);
  prependCommandEvent(state, machine, input.commandType, 'pending');

  if (!saveSimulationState(state)) {
    return { ok: false as const, error: 'Failed to save simulation state.' };
  }

  return { ok: true as const, command };
}

export function enqueueSimulatedBroadcastCommands(input: {
  unitName?: string | null;
  commandType: string;
  target?: string | null;
  tenantId?: string | null;
}) {
  const state = getSimulationState();
  if (!state) {
    return { ok: false as const, error: 'Simulation state not found.' };
  }

  const machines = state.machines.filter((machine) => !input.unitName || machine.unit === input.unitName);
  const now = new Date().toISOString();
  const commands = machines.map((machine) => ({
    id: newSimulationCommandId(),
    machine_id: machine.id,
    hostname: machine.hostname,
    unit: machine.unit,
    tenant_id: input.tenantId || undefined,
    command_type: input.commandType,
    target: input.target || null,
    status: 'pending' as const,
    created_at: now,
    updated_at: now,
  }));

  ensureCommandQueue(state).unshift(...commands);
  if (machines[0]) {
    prependCommandEvent(state, machines[0], input.commandType, 'pending');
  }

  if (!saveSimulationState(state)) {
    return { ok: false as const, error: 'Failed to save simulation state.' };
  }

  return { ok: true as const, commands };
}

export function enqueueSimulatedMassCompliance(input: {
  softwareName: string;
  unitName?: string | null;
  tenantId?: string | null;
}) {
  const state = getSimulationState();
  if (!state) {
    return { ok: false as const, error: 'Simulation state not found.' };
  }

  const targets = state.machines.filter((machine) => {
    if (input.unitName && machine.unit !== input.unitName) return false;
    const software = machine.inventory_data?.software || [];
    return software.some((entry: any) => entry.name === input.softwareName);
  });

  const now = new Date().toISOString();
  const commands = targets.map((machine) => ({
    id: newSimulationCommandId(),
    machine_id: machine.id,
    hostname: machine.hostname,
    unit: machine.unit,
    tenant_id: input.tenantId || undefined,
    command_type: 'RUN_COMPLIANCE_SCAN',
    target: input.softwareName,
    status: 'pending' as const,
    created_at: now,
    updated_at: now,
  }));

  ensureCommandQueue(state).unshift(...commands);
  if (targets[0]) {
    prependCommandEvent(state, targets[0], 'RUN_COMPLIANCE_SCAN', 'pending');
  }

  if (!saveSimulationState(state)) {
    return { ok: false as const, error: 'Failed to save simulation state.' };
  }

  return { ok: true as const, commands };
}

export function listSimulatedAgentCommands(filters: {
  unit?: string | null;
  status?: string | null;
} = {}) {
  const state = getSimulationState();
  if (!state) return [];

  return ensureCommandQueue(state)
    .filter((command) => !filters.unit || command.unit === filters.unit)
    .filter((command) => !filters.status || command.status === filters.status)
    .slice(0, 200)
    .map((command) => ({
      ...command,
      machines: {
        hostname: command.hostname,
        unit: command.unit,
      },
    }));
}

export function takePendingSimulatedAgentCommands(machineId: string, hostname?: string | null) {
  const state = getSimulationState();
  if (!state) return [];

  const commands = ensureCommandQueue(state);
  const now = new Date().toISOString();
  const pending = commands.filter((command) => {
    return command.status === 'pending' && (command.machine_id === machineId || (!!hostname && command.hostname === hostname));
  });

  pending.forEach((command) => {
    command.status = 'sent';
    command.updated_at = now;
  });

  if (pending.length > 0) {
    saveSimulationState(state);
  }

  return pending.map((command) => ({
    id: command.id,
    command_type: command.command_type,
    target: command.target,
  }));
}

export function recordSimulatedTelemetryPulse(input: {
  machineId: string;
  hostname: string;
  tenantId?: string | null;
  payload: Record<string, unknown>;
}) {
  const state = getSimulationState();
  if (!state) {
    return { ok: false as const, error: 'Simulation state not found.' };
  }

  const now = new Date().toISOString();
  const payload = input.payload || {};
  const existing = findSimulatedMachine(state, input.machineId, input.hostname);
  const unit = String(payload.unit || existing?.unit || 'UN-STRESS');
  const telemetryPayload = isPlainObject(payload.telemetry) ? payload.telemetry : {};
  const inventoryPayload = isPlainObject(payload.inventory_data) ? payload.inventory_data : {};
  const existingInventory = isPlainObject(existing?.inventory_data) ? existing.inventory_data : {};

  const machine: SimulatedMachine = existing || {
    id: input.machineId,
    hostname: input.hostname,
    ip: String(payload.ip || '0.0.0.0'),
    unit,
    status: 'online',
    last_pulse: now,
    telemetry: { cpu: 10, ram: 30, disk: 50 },
  };

  machine.hostname = input.hostname || machine.hostname;
  machine.ip = String(payload.ip || machine.ip || '0.0.0.0');
  machine.unit = unit;
  machine.status = 'online';
  machine.last_pulse = now;
  machine.os_name = typeof payload.os_name === 'string' ? payload.os_name.slice(0, 160) : machine.os_name;
  machine.cpu_info = typeof payload.cpu_info === 'string' ? payload.cpu_info.slice(0, 240) : machine.cpu_info;
  machine.ram_total = typeof payload.ram_total === 'string' ? payload.ram_total.slice(0, 80) : machine.ram_total;
  machine.agent_version = typeof payload.agent_version === 'string' ? payload.agent_version.slice(0, 40) : machine.agent_version;
  machine.serial_number = typeof payload.serial_number === 'string'
    ? payload.serial_number.slice(0, 160)
    : machine.serial_number || `VEXT-${unit.replace('-', '')}-${String(machine.id.split('-').at(-1) || '1').padStart(5, '0')}`;
  machine.telemetry = {
    cpu: boundedNumber(telemetryPayload.cpu, machine.telemetry?.cpu || 10, 0, 100),
    ram: boundedNumber(telemetryPayload.ram, machine.telemetry?.ram || 30, 0, 100),
    disk: boundedNumber(telemetryPayload.disk, machine.telemetry?.disk || 50, 0, 100),
  };

  const mergedInventory: Record<string, unknown> = {
    ...existingInventory,
    ...inventoryPayload,
  };
  const systemDetails = isPlainObject(mergedInventory.system_details) ? mergedInventory.system_details : {};
  mergedInventory.system_details = {
    ...buildFallbackSystemDetails(machine, payload),
    ...systemDetails,
  };
  machine.inventory_data = mergedInventory;

  if (!existing) {
    state.machines.unshift(machine);
  }

  const event = detectSimulatedEvent(machine, mergedInventory);
  if (event) {
    state.events.unshift({
      id: `EVT-STRESS-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      timestamp: now,
      agent_hostname: machine.hostname,
      unit: machine.unit,
      severity: event.severity,
      type: event.type,
      description: `Pulso de stress registrou ${event.type} em ${machine.hostname}.`,
      details: {
        source: 'telemetry_stress',
        tenant_id: input.tenantId || null,
        machine_id: machine.id,
      },
    });
  }

  state.events = state.events.slice(0, 1000);
  const metrics = (state.stress_metrics || {}) as Record<string, unknown>;
  state.stress_metrics = {
    ...metrics,
    last_pulse_at: now,
    last_machine_id: machine.id,
    last_hostname: machine.hostname,
    total_pulses: Number(metrics.total_pulses || 0) + 1,
    touched_machines: new Set([
      ...String(metrics.touched_machine_ids || '').split(',').filter(Boolean),
      machine.id,
    ]).size,
    touched_machine_ids: [
      ...new Set([
        ...String(metrics.touched_machine_ids || '').split(',').filter(Boolean),
      machine.id,
      ]),
    ].slice(-500).join(','),
  };

  const throttleMs = boundedNumber(process.env.VEXTHUB_SIMULATION_WRITE_THROTTLE_MS, 750, 0, 10000);
  if (!saveSimulationState(state, { throttleMs })) {
    return { ok: false as const, error: 'Failed to save simulation state.' };
  }

  return { ok: true as const, machine };
}

export function updateSimulatedAgentCommandStatus(input: {
  commandId: string;
  machineId: string;
  status: SimulatedAgentCommand['status'];
  output?: string | null;
}) {
  const state = getSimulationState();
  if (!state) {
    return { ok: false as const, error: 'Simulation state not found.' };
  }

  const command = ensureCommandQueue(state).find((item) => item.id === input.commandId && item.machine_id === input.machineId);
  if (!command) {
    return { ok: false as const, error: 'Command not found in simulation.' };
  }

  command.status = input.status;
  command.result = input.output || null;
  command.updated_at = new Date().toISOString();

  const machine = findSimulatedMachine(state, input.machineId, command.hostname);
  if (machine) {
    prependCommandEvent(state, machine, command.command_type, input.status);
  }

  if (!saveSimulationState(state)) {
    return { ok: false as const, error: 'Failed to save simulation state.' };
  }

  return { ok: true as const, command };
}
