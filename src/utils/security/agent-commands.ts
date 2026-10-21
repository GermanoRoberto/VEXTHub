export const SAFE_AGENT_COMMANDS = [
  "REFRESH_INVENTORY",
  "RUN_COMPLIANCE_SCAN",
  "UPDATE_AGENT",
] as const;

export type SafeAgentCommand = (typeof SAFE_AGENT_COMMANDS)[number];

const SAFE_COMMAND_SET = new Set<string>(SAFE_AGENT_COMMANDS);

export function normalizeAgentCommand(value: unknown): SafeAgentCommand | null {
  const normalized = String(value || "").trim().toUpperCase();
  if (!SAFE_COMMAND_SET.has(normalized)) {
    return null;
  }
  return normalized as SafeAgentCommand;
}

export function sanitizeCommandTarget(value: unknown) {
  if (value === null || value === undefined) {
    return null;
  }

  const target = String(value).trim();
  if (!target) {
    return null;
  }

  return target.slice(0, 160);
}

export function commandLabel(command: SafeAgentCommand) {
  switch (command) {
    case "REFRESH_INVENTORY":
      return "Atualizar inventario";
    case "RUN_COMPLIANCE_SCAN":
      return "Revalidar compliance";
    case "UPDATE_AGENT":
      return "Atualizar agente";
  }
}
