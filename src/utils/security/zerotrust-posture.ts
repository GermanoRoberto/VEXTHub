import {
  scanHostVulnerabilities,
  type HostVulnerabilityReport,
  type DetectedVulnerability,
} from "./cve-scanner";
import type {
  TelemetrySoftware,
  TelemetryProcess,
  TelemetryService,
  TelemetryStartupEntry,
  TelemetryListeningPort,
  TelemetryExternalConnection,
  TelemetryFinding,
} from "./telemetry-detection";

export type ZeroTrustVerdict = "TRUSTED" | "RESTRICTED" | "QUARANTINED";

export type ZeroTrustFeedFormat =
  | "json"
  | "pfsense"
  | "plain"
  | "fortigate"
  | "mikrotik"
  | "iptables";

export type TunnelToolCategory =
  | "reverse_proxy_tunnel"
  | "zero_trust_mesh"
  | "anonymity_network"
  | "ssh_tunnel"
  | "unauthorized_vpn"
  | "unusual_c2_egress";

export interface TunnelDetectionFinding {
  id: string;
  tool: string;
  category: TunnelToolCategory;
  severity: "high" | "critical";
  confidence: number;
  matched_indicator: string;
  process_name?: string;
  command_line?: string;
  remote_address?: string;
  remote_port?: number;
  local_port?: number;
  description: string;
  mitre?: string;
  recommended_action: string;
}

export interface PostureFactorEvaluation {
  factor:
    | "tunnel_radar"
    | "cve_vulnerabilities"
    | "network_exposure"
    | "active_threats"
    | "endpoint_hygiene";
  status: "pass" | "warn" | "fail";
  score_impact: number;
  details: string;
}

export interface ZeroTrustPostureReport {
  machine_id: string;
  hostname: string;
  ip: string;
  unit: string;
  verdict: ZeroTrustVerdict;
  posture_score: number; // 0 - 100 (100 = plenamente confiável)
  risk_score: number;    // 0 - 100 (100 = risco máximo)
  quarantine_reasons: string[];
  remediation_steps: string[];
  tunnel_radar: {
    has_tunnels: boolean;
    findings: TunnelDetectionFinding[];
    unusual_ports: number[];
  };
  factors: PostureFactorEvaluation[];
  evaluated_at: string;
}

export interface QuarantineBlocklistEntry {
  ip: string;
  hostname: string;
  machine_id: string;
  unit: string;
  verdict: ZeroTrustVerdict;
  reason: string;
  severity: "high" | "critical";
  quarantined_at: string;
  recommended_firewall_action: "DROP" | "REJECT" | "ISOLATE";
}

export interface ZeroTrustFleetSummary {
  total_evaluated: number;
  trusted_count: number;
  restricted_count: number;
  quarantined_count: number;
  quarantine_rate_percent: number;
  blocked_ips_count: number;
  active_tunnels_count: number;
}

export interface FleetPostureEvaluation {
  summary: ZeroTrustFleetSummary;
  reports: ZeroTrustPostureReport[];
  quarantinedHosts: QuarantineBlocklistEntry[];
  blockedIps: string[];
}

interface TunnelRule {
  id: string;
  tool: string;
  category: TunnelToolCategory;
  severity: "high" | "critical";
  confidence: number;
  processMatches: string[];
  commandMatches: string[];
  remotePorts?: number[];
  localPorts?: number[];
  mitre: string;
  description: string;
  recommended_action: string;
}

export const TUNNEL_RADAR_RULES: TunnelRule[] = [
  // 1. ngrok
  {
    id: "tun-ngrok",
    tool: "ngrok",
    category: "reverse_proxy_tunnel",
    severity: "critical",
    confidence: 0.98,
    processMatches: ["ngrok.exe", "ngrok"],
    commandMatches: ["ngrok http", "ngrok tcp", "ngrok start", "ngrok.exe"],
    remotePorts: [4443],
    mitre: "T1572 / T1090",
    description: "Túnel reverso ngrok ativo permitindo exposição de serviços internos sem autenticação corporativa",
    recommended_action: "Terminar processo ngrok imediatamente, revogar túnel na nuvem e bloquear conexões para *.ngrok.io",
  },
  // 2. Cloudflare Tunnel (cloudflared)
  {
    id: "tun-cloudflared",
    tool: "cloudflared",
    category: "zero_trust_mesh",
    severity: "critical",
    confidence: 0.96,
    processMatches: ["cloudflared.exe", "cloudflared"],
    commandMatches: ["cloudflared tunnel", "tunnel run", "tunnel --url", "cloudflared.exe"],
    mitre: "T1572",
    description: "Cloudflare Tunnel (cloudflared) em execução no endpoint contornando regras de borda corporativas",
    recommended_action: "Verificar autorização do túnel no Cloudflare Zero Trust e interromper o processo cloudflared não homologado",
  },
  // 3. Tailscale
  {
    id: "tun-tailscale",
    tool: "tailscale",
    category: "zero_trust_mesh",
    severity: "high",
    confidence: 0.94,
    processMatches: ["tailscale.exe", "tailscaled.exe", "tailscale", "tailscaled"],
    commandMatches: ["tailscale up", "tailscale.exe", "tailscaled.exe"],
    mitre: "T1090",
    description: "Rede mesh privada Tailscale (WireGuard) em execução estabelecendo comunicação ponto-a-ponto não inspecionada",
    recommended_action: "Validar aderência à política corporativa de VPN mesh ou desinstalar o cliente Tailscale",
  },
  // 4. ZeroTier
  {
    id: "tun-zerotier",
    tool: "zerotier",
    category: "zero_trust_mesh",
    severity: "high",
    confidence: 0.94,
    processMatches: ["zerotier-one.exe", "zerotier-cli.exe", "zerotier-one", "zerotier-cli"],
    commandMatches: ["zerotier-cli", "zerotier-one"],
    remotePorts: [9993],
    localPorts: [9993],
    mitre: "T1090",
    description: "Rede virtual ZeroTier One ativa criando túnel de camada 2 transparente sobre a rede corporativa",
    recommended_action: "Revogar participação na rede ZeroTier e suspender o serviço zerotier-one",
  },
  // 5. Tor Anonymity Network
  {
    id: "tun-tor",
    tool: "tor",
    category: "anonymity_network",
    severity: "critical",
    confidence: 0.99,
    processMatches: ["tor.exe", "tor", "obfs4proxy.exe", "obfs4proxy", "tor-browser"],
    commandMatches: ["tor.exe", "--service install tor", "obfs4proxy"],
    remotePorts: [9001, 9050, 9051, 9150],
    localPorts: [9050, 9051, 9150],
    mitre: "T1090.003",
    description: "Roteamento anônimo Tor / proxy onion detectado no endpoint, frequentemente associado a exfiltração ou C2 evasivo",
    recommended_action: "Isolar a máquina da rede imediatamente, investigar tráfego para nós Tor e terminar processos vinculados",
  },
  // 6. Chisel (Reverse Tunnel)
  {
    id: "tun-chisel",
    tool: "chisel",
    category: "reverse_proxy_tunnel",
    severity: "critical",
    confidence: 0.99,
    processMatches: ["chisel.exe", "chisel"],
    commandMatches: ["chisel client", "chisel server", "chisel.exe", " R:", " r:"],
    mitre: "T1572",
    description: "Ferramenta de tunelamento TCP/UDP reverso Chisel sobre HTTP/WebSocket detectada",
    recommended_action: "Quarentenar host imediatamente, encerrar o processo chisel e inspecionar endpoint remoto de conexão",
  },
  // 7. PuTTY Plink / SSH Reverse Tunnel
  {
    id: "tun-plink",
    tool: "plink",
    category: "ssh_tunnel",
    severity: "critical",
    confidence: 0.95,
    processMatches: ["plink.exe", "plink"],
    commandMatches: [" -r ", " -d ", "plink.exe -r", "plink -r"],
    mitre: "T1572",
    description: "Túnel reverso ou proxy dinâmico SSH via PuTTY Plink contornando firewalls de entrada",
    recommended_action: "Encerrar sessão SSH reversa, revogar chaves públicas vinculadas e monitorar porta remota de pivô",
  },
  // 8. OpenSSH Reverse Tunnel
  {
    id: "tun-ssh-reverse",
    tool: "ssh",
    category: "ssh_tunnel",
    severity: "critical",
    confidence: 0.95,
    processMatches: ["ssh.exe", "ssh"],
    commandMatches: [" -r ", "ssh.exe -r", "ssh -r"],
    mitre: "T1572",
    description: "Sessão OpenSSH estabelecendo redirecionamento reverso (-R) de portas internas para servidor externo",
    recommended_action: "Matar processo SSH, fechar canal reverso e bloquear IP remoto do servidor SSH",
  },
  // 9. Unauthorized VPNs (WireGuard, OpenVPN, Hamachi)
  {
    id: "tun-unauthorized-vpn",
    tool: "unauthorized_vpn",
    category: "unauthorized_vpn",
    severity: "high",
    confidence: 0.92,
    processMatches: [
      "wireguard.exe",
      "wireguard",
      "openvpn.exe",
      "openvpn",
      "openvpn-gui.exe",
      "hamachi-2.exe",
      "hamachi-2",
      "logmein-hamachi",
    ],
    commandMatches: ["wireguard /installtunnelservice", "openvpn --config", "hamachi-2"],
    mitre: "T1133",
    description: "Cliente de VPN não homologado (WireGuard / OpenVPN / Hamachi) criando túnel criptografado direto",
    recommended_action: "Validar se a conexão VPN possui aprovação formal de segurança corporativa ou desativar interface",
  },
  // 10. FRP (Fast Reverse Proxy)
  {
    id: "tun-frp",
    tool: "frp",
    category: "reverse_proxy_tunnel",
    severity: "critical",
    confidence: 0.98,
    processMatches: ["frpc.exe", "frps.exe", "frpc", "frps"],
    commandMatches: ["frpc -c", "frpc.ini", "frpc.toml", "frps -c"],
    mitre: "T1572",
    description: "Fast Reverse Proxy (frp) de alto desempenho expondo portas de rede locais para servidor FRP externo",
    recommended_action: "Terminar processo frpc, revogar túnel e inspecionar portas internas redirecionadas",
  },
  // 11. Bore (Modern reverse proxy)
  {
    id: "tun-bore",
    tool: "bore",
    category: "reverse_proxy_tunnel",
    severity: "critical",
    confidence: 0.97,
    processMatches: ["bore.exe", "bore"],
    commandMatches: ["bore local", "bore server", "bore.exe"],
    mitre: "T1572",
    description: "Túnel reverso Bore ativo encaminhando tráfego de borda diretamente para serviços locais",
    recommended_action: "Encerrar processo bore e bloquear portas no firewall de perímetro",
  },
];

interface C2EgressRule {
  port: number;
  tool: string;
  severity: "high" | "critical";
  confidence: number;
  description: string;
  mitre: string;
}

export const C2_EGRESS_PORT_RULES: C2EgressRule[] = [
  {
    port: 4444,
    tool: "Metasploit C2 Egress",
    severity: "critical",
    confidence: 0.96,
    description: "Conexão de saída ativa estabelecida na porta padrão de payload/handler do Metasploit (tcp/4444)",
    mitre: "T1071 / T1095",
  },
  {
    port: 1337,
    tool: "Elite C2 Egress",
    severity: "critical",
    confidence: 0.95,
    description: "Conexão de saída ativa estabelecida na porta clássica de Command & Control hacker (tcp/1337)",
    mitre: "T1071",
  },
  {
    port: 3333,
    tool: "Stratum Mining / Backdoor C2",
    severity: "critical",
    confidence: 0.94,
    description: "Conexão de saída ativa na porta 3333 associada a botnets de mineração e C2 de malware",
    mitre: "T1496 / T1071",
  },
  {
    port: 8443,
    tool: "Alt HTTPS C2 / Proxy Bypass",
    severity: "high",
    confidence: 0.88,
    description: "Conexão de saída externa na porta alternativa 8443 com características de proxy de evasão ou C2",
    mitre: "T1071",
  },
  {
    port: 6667,
    tool: "IRC Botnet Egress",
    severity: "high",
    confidence: 0.93,
    description: "Conexão de saída estabelecida para servidor IRC clássico (porta 6667), típico de botnets legadas",
    mitre: "T1071.001",
  },
  {
    port: 6697,
    tool: "IRC SSL Botnet Egress",
    severity: "high",
    confidence: 0.93,
    description: "Conexão de saída estabelecida para servidor IRC SSL (porta 6697), associado a canal de comando botnet",
    mitre: "T1071.001",
  },
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeString(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function toPortNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isInteger(value) && value > 0 && value <= 65535) {
    return value;
  }
  if (typeof value === "string") {
    const num = parseInt(value.trim(), 10);
    if (!Number.isNaN(num) && num > 0 && num <= 65535) return num;
  }
  return null;
}

function isLoopbackOrZeroIp(ip: string): boolean {
  const norm = ip.trim().toLowerCase();
  return (
    norm === "" ||
    norm === "127.0.0.1" ||
    norm === "::1" ||
    norm === "0.0.0.0" ||
    norm === "::" ||
    norm === "localhost" ||
    norm.startsWith("127.")
  );
}

export function isValidIp(ip: string): boolean {
  if (!ip || typeof ip !== "string") return false;
  const trimmed = ip.trim();
  if (isLoopbackOrZeroIp(trimmed)) return false;

  // IPv4 format check
  const ipv4Match = trimmed.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const octets = ipv4Match.slice(1).map((o) => parseInt(o, 10));
    return octets.every((o) => o >= 0 && o <= 255);
  }

  // Basic IPv6 check
  if (trimmed.includes(":") && trimmed.length >= 3) {
    return true;
  }

  return false;
}

/**
 * Extracts the primary IP address of a host from varied machine telemetry representations.
 */
export function extractHostIp(machine: unknown): string {
  if (!isRecord(machine)) return "0.0.0.0";

  // 1. Direct machine.ip
  if (typeof machine.ip === "string" && isValidIp(machine.ip)) {
    return machine.ip.trim();
  }

  const inv = isRecord(machine.inventory_data) ? machine.inventory_data : machine;

  // 2. inventory_data.system_details.local_ip or external_ip
  if (isRecord(inv.system_details)) {
    if (typeof inv.system_details.local_ip === "string" && isValidIp(inv.system_details.local_ip)) {
      return inv.system_details.local_ip.trim();
    }
    if (typeof inv.system_details.external_ip === "string" && isValidIp(inv.system_details.external_ip)) {
      return inv.system_details.external_ip.trim();
    }
  }

  // 3. inventory_data.local_ip or inventory_data.ip
  if (typeof inv.local_ip === "string" && isValidIp(inv.local_ip)) {
    return inv.local_ip.trim();
  }
  if (typeof inv.ip === "string" && isValidIp(inv.ip)) {
    return inv.ip.trim();
  }

  // 4. Established connection local_address
  const net = isRecord(inv.network_connections) ? inv.network_connections : inv;
  if (Array.isArray(net.established_external_tcp) && net.established_external_tcp.length > 0) {
    for (const conn of net.established_external_tcp) {
      if (isRecord(conn) && typeof conn.local_address === "string" && isValidIp(conn.local_address)) {
        return conn.local_address.trim();
      }
    }
  }

  // 5. Fallback string if machine.ip exists even if non-standard
  if (typeof machine.ip === "string" && machine.ip.trim() !== "") {
    return machine.ip.trim();
  }

  return "0.0.0.0";
}

/**
 * Analyzes endpoint inventory (processes, services, startup, network connections)
 * to detect Shadow IT reverse tunnels, unauthorized VPNs, and C2 egress communication.
 */
export function detectReverseTunnels(inventoryData: unknown): TunnelDetectionFinding[] {
  const findings: TunnelDetectionFinding[] = [];
  if (!isRecord(inventoryData)) return findings;

  const inv = isRecord(inventoryData.inventory_data) ? inventoryData.inventory_data : inventoryData;

  const processes: TelemetryProcess[] = Array.isArray(inv.processes)
    ? (inv.processes.filter(isRecord) as TelemetryProcess[])
    : [];
  const services: TelemetryService[] = Array.isArray(inv.services)
    ? (inv.services.filter(isRecord) as TelemetryService[])
    : [];
  const startupEntries: TelemetryStartupEntry[] = Array.isArray(inv.startup_entries)
    ? (inv.startup_entries.filter(isRecord) as TelemetryStartupEntry[])
    : [];
  const softwares: TelemetrySoftware[] = Array.isArray(inv.software)
    ? (inv.software.filter(isRecord) as TelemetrySoftware[])
    : [];

  const net = isRecord(inv.network_connections) ? inv.network_connections : inv;
  const externalConnections: TelemetryExternalConnection[] = Array.isArray(net.established_external_tcp)
    ? (net.established_external_tcp.filter(isRecord) as TelemetryExternalConnection[])
    : [];
  const listeningPorts: TelemetryListeningPort[] = Array.isArray(net.listening_tcp_ports)
    ? (net.listening_tcp_ports.filter(isRecord) as TelemetryListeningPort[])
    : [];

  const matchedRules = new Set<string>();

  // 1. Process matching
  for (const proc of processes) {
    const procName = normalizeString(proc.name);
    const procPath = normalizeString(proc.path);
    const cmdLine = normalizeString(proc.command_line);

    for (const rule of TUNNEL_RADAR_RULES) {
      const matchName = rule.processMatches.some(
        (pm) => procName === pm.toLowerCase() || procPath.endsWith(`\\${pm.toLowerCase()}`) || procPath.endsWith(`/${pm.toLowerCase()}`)
      );
      const matchCmd = rule.commandMatches.some((cm) => cmdLine.includes(cm.toLowerCase()));

      if (matchName || matchCmd) {
        const key = `${rule.id}:${procName || "cmd"}`;
        if (!matchedRules.has(key)) {
          matchedRules.add(key);
          findings.push({
            id: key,
            tool: rule.tool,
            category: rule.category,
            severity: rule.severity,
            confidence: rule.confidence,
            matched_indicator: matchCmd ? `Linha de comando: ${proc.command_line || cmdLine}` : `Processo: ${proc.name || procName}`,
            process_name: proc.name,
            command_line: proc.command_line,
            description: rule.description,
            mitre: rule.mitre,
            recommended_action: rule.recommended_action,
          });
        }
      }
    }
  }

  // 2. Services & Startup Entries matching
  for (const svc of services) {
    const sName = normalizeString(svc.name);
    const dName = normalizeString(svc.display_name);
    const pName = normalizeString(svc.path_name);

    for (const rule of TUNNEL_RADAR_RULES) {
      const matchSvc = rule.processMatches.some(
        (pm) => sName.includes(pm.toLowerCase().replace(/\.exe$/, "")) ||
                dName.includes(pm.toLowerCase().replace(/\.exe$/, "")) ||
                pName.includes(pm.toLowerCase())
      );
      if (matchSvc) {
        const key = `${rule.id}:svc:${sName}`;
        if (!matchedRules.has(key)) {
          matchedRules.add(key);
          findings.push({
            id: key,
            tool: rule.tool,
            category: rule.category,
            severity: rule.severity,
            confidence: Math.max(0.85, rule.confidence - 0.05),
            matched_indicator: `Serviço do Windows: ${svc.display_name || svc.name}`,
            description: `${rule.description} (instalado como serviço persistente)`,
            mitre: rule.mitre,
            recommended_action: rule.recommended_action,
          });
        }
      }
    }
  }

  for (const st of startupEntries) {
    const stName = normalizeString(st.name);
    const stCmd = normalizeString(st.command);

    for (const rule of TUNNEL_RADAR_RULES) {
      const matchStartup = rule.processMatches.some(
        (pm) => stName.includes(pm.toLowerCase().replace(/\.exe$/, "")) || stCmd.includes(pm.toLowerCase())
      );
      if (matchStartup) {
        const key = `${rule.id}:startup:${stName}`;
        if (!matchedRules.has(key)) {
          matchedRules.add(key);
          findings.push({
            id: key,
            tool: rule.tool,
            category: rule.category,
            severity: rule.severity,
            confidence: Math.max(0.85, rule.confidence - 0.05),
            matched_indicator: `Entrada de inicialização automática: ${st.name} (${st.command || ""})`,
            description: `${rule.description} (configurado para execução na inicialização)`,
            mitre: rule.mitre,
            recommended_action: rule.recommended_action,
          });
        }
      }
    }
  }

  // 3. Installed Software matching
  for (const sw of softwares) {
    const swName = normalizeString(sw.name);
    for (const rule of TUNNEL_RADAR_RULES) {
      if (rule.category === "zero_trust_mesh" || rule.category === "unauthorized_vpn" || rule.category === "anonymity_network") {
        const matchSoftware = rule.processMatches.some((pm) => swName.includes(pm.toLowerCase().replace(/\.exe$/, "")));
        if (matchSoftware) {
          const key = `${rule.id}:sw:${swName}`;
          if (!matchedRules.has(key)) {
            matchedRules.add(key);
            findings.push({
              id: key,
              tool: rule.tool,
              category: rule.category,
              severity: rule.severity,
              confidence: 0.88,
              matched_indicator: `Software instalado: ${sw.name}`,
              description: `${rule.description} (instalado no inventário)`,
              mitre: rule.mitre,
              recommended_action: rule.recommended_action,
            });
          }
        }
      }
    }
  }

  // 4. Established External TCP Connections (C2 Egress & Specific Tunnel Remote Ports)
  for (const conn of externalConnections) {
    const remotePort = toPortNumber(conn.remote_port);
    const localPort = toPortNumber(conn.local_port);
    const remoteAddress = typeof conn.remote_address === "string" ? conn.remote_address.trim() : "";
    const state = normalizeString(conn.state);

    if (state === "closed" || state === "time_wait" || state === "close_wait") {
      continue;
    }

    if (remotePort) {
      // Check C2 Egress Rules
      const c2Rule = C2_EGRESS_PORT_RULES.find((r) => r.port === remotePort);
      if (c2Rule) {
        const key = `c2-port:${remotePort}:${remoteAddress}`;
        if (!matchedRules.has(key)) {
          matchedRules.add(key);
          findings.push({
            id: key,
            tool: c2Rule.tool,
            category: "unusual_c2_egress",
            severity: c2Rule.severity,
            confidence: c2Rule.confidence,
            matched_indicator: `Conexão TCP externa ativa: ${conn.local_address || "local"}:${localPort || "?"} -> ${remoteAddress}:${remotePort} (${conn.state || "ESTABLISHED"})`,
            remote_address: remoteAddress,
            remote_port: remotePort,
            local_port: localPort ?? undefined,
            description: c2Rule.description,
            mitre: c2Rule.mitre,
            recommended_action: `Bloquear porta ${remotePort} e endereço ${remoteAddress} no firewall perimetral; investigar payload da sessão`,
          });
        }
      }

      // Check Tunnel Specific Remote Ports (e.g. 4443 for ngrok, 9993 for ZeroTier, 9001/9050 for Tor)
      for (const rule of TUNNEL_RADAR_RULES) {
        if (rule.remotePorts && rule.remotePorts.includes(remotePort)) {
          const key = `${rule.id}:remote-port:${remotePort}:${remoteAddress}`;
          if (!matchedRules.has(key)) {
            matchedRules.add(key);
            findings.push({
              id: key,
              tool: rule.tool,
              category: rule.category,
              severity: rule.severity,
              confidence: 0.9,
              matched_indicator: `Conexão externa ativa para porta de túnel ${remotePort}: ${remoteAddress}`,
              remote_address: remoteAddress,
              remote_port: remotePort,
              local_port: localPort ?? undefined,
              description: `${rule.description} (tráfego na porta remota ${remotePort})`,
              mitre: rule.mitre,
              recommended_action: rule.recommended_action,
            });
          }
        }
      }
    }
  }

  // 5. Listening Ports (Tor or ZeroTier local proxy listeners)
  for (const listener of listeningPorts) {
    const lPort = toPortNumber(listener.local_port);
    if (lPort) {
      for (const rule of TUNNEL_RADAR_RULES) {
        if (rule.localPorts && rule.localPorts.includes(lPort)) {
          const key = `${rule.id}:listen-port:${lPort}`;
          if (!matchedRules.has(key)) {
            matchedRules.add(key);
            findings.push({
              id: key,
              tool: rule.tool,
              category: rule.category,
              severity: rule.severity,
              confidence: 0.92,
              matched_indicator: `Porta local em escuta para serviço de túnel/proxy: tcp/${lPort} (${listener.exposure || "local"})`,
              local_port: lPort,
              description: `${rule.description} (serviço em escuta na porta ${lPort})`,
              mitre: rule.mitre,
              recommended_action: rule.recommended_action,
            });
          }
        }
      }
    }
  }

  return findings;
}

/**
 * Extracts a list of unusual C2 or tunnel ports matched during radar detection.
 */
function extractUnusualPorts(findings: TunnelDetectionFinding[]): number[] {
  const ports = new Set<number>();
  for (const f of findings) {
    if (typeof f.remote_port === "number") ports.add(f.remote_port);
    if (typeof f.local_port === "number") ports.add(f.local_port);
  }
  return Array.from(ports).sort((a, b) => a - b);
}

/**
 * Evaluates the continuous Zero Trust Device Posture of a single machine.
 * Returns score (0-100), verdict (TRUSTED, RESTRICTED, QUARANTINED), factors, and remediation steps.
 */
export function evaluateZeroTrustPosture(
  machine: unknown,
  cveData?: unknown,
): ZeroTrustPostureReport {
  let postureScore = 100;
  const quarantineReasons: string[] = [];
  const remediationSteps: string[] = [];
  const factors: PostureFactorEvaluation[] = [];

  const rawMachine = isRecord(machine) ? machine : {};
  const machineId = typeof rawMachine.id === "string" ? rawMachine.id : "unknown-id";
  const hostname = typeof rawMachine.hostname === "string" ? rawMachine.hostname : "unknown-host";
  const unit = typeof rawMachine.unit === "string" ? rawMachine.unit : "Sem Unidade";
  const ip = extractHostIp(rawMachine);

  const invData = isRecord(rawMachine.inventory_data) ? rawMachine.inventory_data : rawMachine;

  // --------------------------------------------------------------------------
  // Factor 1: Shadow IT & Reverse Tunnel Radar
  // --------------------------------------------------------------------------
  const tunnelFindings = detectReverseTunnels(invData);
  if (tunnelFindings.length > 0) {
    const hasCriticalTunnel = tunnelFindings.some((f) => f.severity === "critical");
    const tunnelPenalty = hasCriticalTunnel ? 55 : 30;
    postureScore -= tunnelPenalty;

    for (const f of tunnelFindings) {
      if (f.severity === "critical") {
        quarantineReasons.push(`[Túnel Crítico/Shadow IT] ${f.tool}: ${f.description} (${f.matched_indicator})`);
      }
      remediationSteps.push(`[${f.tool}] ${f.recommended_action}`);
    }

    factors.push({
      factor: "tunnel_radar",
      status: hasCriticalTunnel ? "fail" : "warn",
      score_impact: -tunnelPenalty,
      details: `${tunnelFindings.length} ferramenta(s) de tunelamento / bypass perimetral detectada(s)`,
    });
  } else {
    factors.push({
      factor: "tunnel_radar",
      status: "pass",
      score_impact: 0,
      details: "Nenhum túnel reverso, bypass perimetral ou porta C2 anômala detectada",
    });
  }

  // --------------------------------------------------------------------------
  // Factor 2: CVE Vulnerabilities & CISA KEV (TVM)
  // --------------------------------------------------------------------------
  let resolvedCveReport: HostVulnerabilityReport | null = null;
  if (isRecord(cveData)) {
    const maxCvss = typeof cveData.maxCvssScore === "number"
      ? cveData.maxCvssScore
      : typeof cveData.maxCvss === "number"
      ? cveData.maxCvss
      : 0;
    const hasKev = Boolean(cveData.hasCisaKev);
    const vulnList = Array.isArray(cveData.vulnerabilities)
      ? (cveData.vulnerabilities.filter(isRecord) as unknown as DetectedVulnerability[])
      : [];

    resolvedCveReport = {
      totalScanned: typeof cveData.totalScanned === "number" ? cveData.totalScanned : vulnList.length,
      totalVulnerabilities: typeof cveData.totalVulnerabilities === "number" ? cveData.totalVulnerabilities : vulnList.length,
      maxCvssScore: maxCvss,
      hasCisaKev: hasKev,
      vulnerabilities: vulnList,
      scannedAt: typeof cveData.scannedAt === "string" ? cveData.scannedAt : new Date().toISOString(),
    };
  } else if (Array.isArray(invData.software) && invData.software.length > 0) {
    resolvedCveReport = scanHostVulnerabilities(invData.software as TelemetrySoftware[]);
  }

  if (resolvedCveReport && resolvedCveReport.totalVulnerabilities > 0) {
    if (resolvedCveReport.hasCisaKev) {
      postureScore -= 60;
      quarantineReasons.push("Vulnerabilidade explorada ativamente no catálogo CISA KEV presente no software do host");
      remediationSteps.push("Aplicar patch de segurança emergencial prioritário conforme catálogo CISA KEV.");
      factors.push({
        factor: "cve_vulnerabilities",
        status: "fail",
        score_impact: -60,
        details: `CISA KEV ativo detectado (CVSS máx: ${resolvedCveReport.maxCvssScore.toFixed(1)})`,
      });
    } else if (resolvedCveReport.maxCvssScore >= 9.0) {
      postureScore -= 50;
      quarantineReasons.push(`CVE de severidade crítica detectada no host (CVSS ${resolvedCveReport.maxCvssScore.toFixed(1)})`);
      remediationSteps.push("Atualizar imediatamente a versão do software com vulnerabilidade crítica.");
      factors.push({
        factor: "cve_vulnerabilities",
        status: "fail",
        score_impact: -50,
        details: `Vulnerabilidade crítica CVSS >= 9.0 (${resolvedCveReport.totalVulnerabilities} vulnerabilidade(s) encontrada(s))`,
      });
    } else if (resolvedCveReport.maxCvssScore >= 7.0) {
      postureScore -= 25;
      remediationSteps.push("Agendar atualização de segurança para componentes de software com CVSS alto.");
      factors.push({
        factor: "cve_vulnerabilities",
        status: "warn",
        score_impact: -25,
        details: `Vulnerabilidade de alto risco detectada (CVSS ${resolvedCveReport.maxCvssScore.toFixed(1)})`,
      });
    } else {
      postureScore -= 10;
      factors.push({
        factor: "cve_vulnerabilities",
        status: "warn",
        score_impact: -10,
        details: `Vulnerabilidade de severidade média/baixa (CVSS ${resolvedCveReport.maxCvssScore.toFixed(1)})`,
      });
    }
  } else {
    factors.push({
      factor: "cve_vulnerabilities",
      status: "pass",
      score_impact: 0,
      details: "Sem vulnerabilidades CVE críticas ou ativas identificadas no software instalado",
    });
  }

  // --------------------------------------------------------------------------
  // Factor 3: Network Surface Exposure (Sensitive Ports 3389, 445, 5900, 22)
  // --------------------------------------------------------------------------
  const net = isRecord(invData.network_connections) ? invData.network_connections : invData;
  const listeningPorts: TelemetryListeningPort[] = Array.isArray(net.listening_tcp_ports)
    ? (net.listening_tcp_ports.filter(isRecord) as TelemetryListeningPort[])
    : [];

  const sensitivePorts = [3389, 445, 5900, 22];
  let hasPublicSensitivePort = false;
  let hasPrivateSensitivePort = false;
  const exposedPortList: string[] = [];

  for (const listener of listeningPorts) {
    const port = toPortNumber(listener.local_port);
    if (port && sensitivePorts.includes(port)) {
      const exposure = normalizeString(listener.exposure);
      const addr = normalizeString(listener.local_address);
      const isPublic = exposure === "public_interface" || exposure === "all_interfaces" || addr === "0.0.0.0" || addr === "::";

      if (isPublic) {
        hasPublicSensitivePort = true;
        exposedPortList.push(`tcp/${port} [Pública]`);
      } else if (!isLoopbackOrZeroIp(addr)) {
        hasPrivateSensitivePort = true;
        exposedPortList.push(`tcp/${port} [Privada]`);
      }
    }
  }

  if (hasPublicSensitivePort) {
    postureScore -= 30;
    quarantineReasons.push(`Porta(s) de gerenciamento sensível(is) exposta(s) em interface pública: ${exposedPortList.join(", ")}`);
    remediationSteps.push("Fechar portas de gerenciamento (RDP 3389, SMB 445, VNC 5900, SSH 22) em interfaces públicas.");
    factors.push({
      factor: "network_exposure",
      status: "fail",
      score_impact: -30,
      details: `Exposição de superfície pública crítica: ${exposedPortList.join(", ")}`,
    });
  } else if (hasPrivateSensitivePort) {
    postureScore -= 10;
    remediationSteps.push("Assegurar que portas RDP/SMB na rede privada estejam restritas por firewall de host.");
    factors.push({
      factor: "network_exposure",
      status: "warn",
      score_impact: -10,
      details: `Portas sensíveis ativas em rede privada: ${exposedPortList.join(", ")}`,
    });
  } else {
    factors.push({
      factor: "network_exposure",
      status: "pass",
      score_impact: 0,
      details: "Sem portas sensíveis de administração abertas ou expostas",
    });
  }

  // --------------------------------------------------------------------------
  // Factor 4: Active Threats & Toxic Combinations (TDR & RATs)
  // --------------------------------------------------------------------------
  const findingsList: TelemetryFinding[] = Array.isArray(invData.telemetry_findings)
    ? (invData.telemetry_findings.filter(isRecord) as unknown as TelemetryFinding[])
    : Array.isArray(invData.findings)
    ? (invData.findings.filter(isRecord) as unknown as TelemetryFinding[])
    : [];

  const toxicCombinationFinding = findingsList.find(
    (f) => f.category === "toxic_combination" || (typeof f.id === "string" && f.id.startsWith("toxic-path:"))
  );

  // Check processes for Mimikatz / Credential Dumpers
  const processes: TelemetryProcess[] = Array.isArray(invData.processes)
    ? (invData.processes.filter(isRecord) as TelemetryProcess[])
    : [];
  const hasCredentialTool = processes.some((p) => {
    const name = normalizeString(p.name);
    const cmd = normalizeString(p.command_line);
    return (
      name.includes("mimikatz") ||
      cmd.includes("mimikatz") ||
      cmd.includes("sekurlsa") ||
      cmd.includes("procdump") && cmd.includes("lsass") ||
      name.includes("pwdump")
    );
  });

  // Check unapproved RMM tools (AnyDesk, TeamViewer, RustDesk, UltraViewer, Supremo)
  const hasUnapprovedRmm = processes.some((p) => {
    const name = normalizeString(p.name);
    return (
      name.includes("anydesk") ||
      name.includes("teamviewer") ||
      name.includes("rustdesk") ||
      name.includes("ultraviewer") ||
      name.includes("supremo")
    );
  });

  if (toxicCombinationFinding) {
    postureScore -= 60;
    quarantineReasons.push(`[Caminho de Ataque Correlacionado] ${toxicCombinationFinding.title}`);
    remediationSteps.push(toxicCombinationFinding.recommended_action || "Isolar o host e acionar equipe de resposta a incidentes.");
    factors.push({
      factor: "active_threats",
      status: "fail",
      score_impact: -60,
      details: `Toxic Combination ativo: ${toxicCombinationFinding.title}`,
    });
  } else if (hasCredentialTool) {
    postureScore -= 50;
    quarantineReasons.push("Ferramenta de extração de credenciais (Mimikatz / LSASS dump) detectada em execução");
    remediationSteps.push("Isolar endpoint, revogar credenciais de administrador e redefinir hashes Kerberos/NTLM.");
    factors.push({
      factor: "active_threats",
      status: "fail",
      score_impact: -50,
      details: "Indicador hostil de extração de credenciais em processo",
    });
  } else if (hasUnapprovedRmm) {
    postureScore -= 20;
    remediationSteps.push("Verificar autorização do software de acesso remoto (RMM) instalado.");
    factors.push({
      factor: "active_threats",
      status: "warn",
      score_impact: -20,
      details: "Ferramenta de controle remoto comercial detectada no host",
    });
  } else {
    factors.push({
      factor: "active_threats",
      status: "pass",
      score_impact: 0,
      details: "Nenhuma ameaça ativa, RAT ou cadeia de ataque identificada",
    });
  }

  // --------------------------------------------------------------------------
  // Factor 5: Endpoint Hygiene & Agent Status
  // --------------------------------------------------------------------------
  const statusStr = normalizeString(rawMachine.status);
  const lastPulseStr = typeof rawMachine.last_pulse === "string" ? rawMachine.last_pulse : null;
  let isStalePulse = false;
  if (lastPulseStr) {
    const pulseTime = new Date(lastPulseStr).getTime();
    if (!Number.isNaN(pulseTime)) {
      const now = Date.now();
      const diffDays = (now - pulseTime) / (1000 * 60 * 60 * 24);
      if (diffDays > 7) {
        isStalePulse = true;
      }
    }
  }

  if (statusStr === "offline" || isStalePulse) {
    postureScore -= 10;
    remediationSteps.push("Verificar conectividade do agente VextHub no endpoint e restabelecer comunicação.");
    factors.push({
      factor: "endpoint_hygiene",
      status: "warn",
      score_impact: -10,
      details: statusStr === "offline" ? "Endpoint em estado offline" : "Última pulsação do agente há mais de 7 dias",
    });
  } else {
    factors.push({
      factor: "endpoint_hygiene",
      status: "pass",
      score_impact: 0,
      details: "Agente comunicando normalmente com telemetria atualizada",
    });
  }

  // --------------------------------------------------------------------------
  // Verdict Determination
  // --------------------------------------------------------------------------
  postureScore = Math.max(0, Math.min(100, Math.round(postureScore)));
  const riskScore = 100 - postureScore;

  // Strict quarantine criteria per dispatch requirements:
  // - Active critical breach path / toxic combination / Mimikatz
  // - Unauthorized reverse tunnel (ngrok, chisel, tor, cloudflared, plink -R, frp, bore)
  // - C2 egress connection (ports 4444, 1337, 8443, 3333, 6667)
  // - Actively exploited CISA KEV or CVSS >= 9.0 CVE
  // - Or postureScore < 40 / riskScore >= 85
  const isQuarantined =
    quarantineReasons.length > 0 ||
    postureScore < 40 ||
    riskScore >= 85;

  const hasWarningFactor = factors.some((f) => f.status === "warn");

  let verdict: ZeroTrustVerdict = "TRUSTED";
  if (isQuarantined) {
    verdict = "QUARANTINED";
    if (quarantineReasons.length === 0) {
      quarantineReasons.push("Score de postura de segurança abaixo do limite mínimo aceitável (< 40)");
    }
  } else if (postureScore < 80 || riskScore >= 35 || hasWarningFactor) {
    verdict = "RESTRICTED";
  }

  // Deduplicate and clean arrays
  const uniqueReasons = Array.from(new Set(quarantineReasons));
  const uniqueRemediations = Array.from(new Set(remediationSteps));

  return {
    machine_id: machineId,
    hostname,
    ip,
    unit,
    verdict,
    posture_score: postureScore,
    risk_score: riskScore,
    quarantine_reasons: uniqueReasons,
    remediation_steps: uniqueRemediations,
    tunnel_radar: {
      has_tunnels: tunnelFindings.length > 0,
      findings: tunnelFindings,
      unusual_ports: extractUnusualPorts(tunnelFindings),
    },
    factors,
    evaluated_at: new Date().toISOString(),
  };
}

/**
 * Evaluates the entire fleet of machines for Zero Trust posture and aggregates
 * summary statistics, quarantined hosts list, and blocked IPs feed.
 */
export function evaluateFleetZeroTrustPosture(machines: unknown[]): FleetPostureEvaluation {
  const safeMachines = Array.isArray(machines) ? machines : [];
  const reports: ZeroTrustPostureReport[] = [];
  const quarantinedHosts: QuarantineBlocklistEntry[] = [];
  const blockedIpSet = new Set<string>();

  let trustedCount = 0;
  let restrictedCount = 0;
  let quarantinedCount = 0;
  let activeTunnelsCount = 0;

  for (const machine of safeMachines) {
    const report = evaluateZeroTrustPosture(machine);
    reports.push(report);

    if (report.tunnel_radar.has_tunnels) {
      activeTunnelsCount++;
    }

    if (report.verdict === "QUARANTINED") {
      quarantinedCount++;

      const hasCriticalFinding =
        report.factors.some((f) => f.status === "fail") ||
        report.tunnel_radar.findings.some((f) => f.severity === "critical");

      quarantinedHosts.push({
        ip: report.ip,
        hostname: report.hostname,
        machine_id: report.machine_id,
        unit: report.unit,
        verdict: report.verdict,
        reason: report.quarantine_reasons.join(" | ") || "Postura de segurança degradada",
        severity: hasCriticalFinding ? "critical" : "high",
        quarantined_at: report.evaluated_at,
        recommended_firewall_action: "DROP",
      });

      if (isValidIp(report.ip)) {
        blockedIpSet.add(report.ip);
      }

      // Also include remote C2 addresses in blocked IPs list
      for (const f of report.tunnel_radar.findings) {
        if (f.remote_address && isValidIp(f.remote_address)) {
          blockedIpSet.add(f.remote_address);
        }
      }
    } else if (report.verdict === "RESTRICTED") {
      restrictedCount++;
    } else {
      trustedCount++;
    }
  }

  const totalEvaluated = reports.length;
  const quarantineRate =
    totalEvaluated > 0 ? Math.round((quarantinedCount / totalEvaluated) * 1000) / 10 : 0;

  const blockedIps = Array.from(blockedIpSet).sort();

  return {
    summary: {
      total_evaluated: totalEvaluated,
      trusted_count: trustedCount,
      restricted_count: restrictedCount,
      quarantined_count: quarantinedCount,
      quarantine_rate_percent: quarantineRate,
      blocked_ips_count: blockedIps.length,
      active_tunnels_count: activeTunnelsCount,
    },
    reports,
    quarantinedHosts,
    blockedIps,
  };
}

/**
 * Formats live quarantine blocklist and high-risk IPs for firewall ingestion:
 * - json: Pretty JSON feed
 * - pfsense / plain: Plain text list of IPs with # comments
 * - fortigate: FortiGate External Threat Feed format (IP/32)
 * - mikrotik: MikroTik RouterOS /ip firewall address-list CLI script
 * - iptables: Linux ipset + iptables drop rules script
 */
export function formatFirewallFeed(
  quarantinedHosts: QuarantineBlocklistEntry[],
  blockedIps: string[],
  format: ZeroTrustFeedFormat,
  tenantId = "00000000-0000-0000-0000-000000000000",
  summary?: Partial<ZeroTrustFleetSummary>,
): string {
  const timestamp = new Date().toISOString();
  const safeBlockedIps = Array.isArray(blockedIps) ? blockedIps.filter(isValidIp) : [];
  const safeHosts = Array.isArray(quarantinedHosts) ? quarantinedHosts : [];

  switch (format) {
    case "json": {
      return JSON.stringify(
        {
          version: "1.0.0",
          feed_type: "zerotrust_quarantine_feed",
          generated_at: timestamp,
          tenant_id: tenantId,
          summary: summary || {
            total_quarantined: safeHosts.length,
            blocked_ips_count: safeBlockedIps.length,
          },
          blocked_ips: safeBlockedIps,
          quarantined_hosts: safeHosts,
        },
        null,
        2,
      );
    }

    case "pfsense":
    case "plain": {
      const lines: string[] = [
        "# ==============================================================================",
        "# VextHub Zero Trust Quarantine Feed — pfSense / Plain Text URL Table Alias",
        `# Tenant: ${tenantId} | Generated: ${timestamp} | Total IPs: ${safeBlockedIps.length}`,
        "# Description: Live high-risk and quarantined endpoint IPs for automated firewall drop",
        "# ==============================================================================",
      ];

      if (safeBlockedIps.length === 0) {
        lines.push("# No active quarantined hosts");
      } else {
        for (const ip of safeBlockedIps) {
          const host = safeHosts.find((h) => h.ip === ip);
          if (host) {
            lines.push(`${ip} # ${host.hostname} (${host.reason})`);
          } else {
            lines.push(ip);
          }
        }
      }

      return lines.join("\n");
    }

    case "fortigate": {
      const lines: string[] = [
        "# ==============================================================================",
        "# VextHub Zero Trust Threat Feed — FortiGate External Threat Feed (IP Address)",
        `# Tenant: ${tenantId} | Generated: ${timestamp} | Total Entries: ${safeBlockedIps.length}`,
        "# Syntax: Single IP address or CIDR per line",
        "# ==============================================================================",
      ];

      if (safeBlockedIps.length === 0) {
        lines.push("# No active blocked IPs");
      } else {
        for (const ip of safeBlockedIps) {
          lines.push(ip.includes("/") ? ip : `${ip}/32`);
        }
      }

      return lines.join("\n");
    }

    case "mikrotik": {
      const lines: string[] = [
        "# ==============================================================================",
        "# VextHub Zero Trust Threat Feed — MikroTik RouterOS Address List Script",
        `# Tenant: ${tenantId} | Generated: ${timestamp} | Total IPs: ${safeBlockedIps.length}`,
        "# Usage: Import via RouterOS CLI: /import vext_quarantine.rsc",
        "# ==============================================================================",
        "/ip firewall address-list remove [find list=VEXTHUB_QUARANTINE]",
      ];

      if (safeBlockedIps.length === 0) {
        lines.push("# No quarantined hosts to add");
      } else {
        for (const ip of safeBlockedIps) {
          const host = safeHosts.find((h) => h.ip === ip);
          const rawComment = host ? `${host.hostname} - ${host.reason}` : "VextHub Zero Trust Quarantine";
          const safeComment = rawComment.replace(/"/g, "'").slice(0, 60);
          lines.push(
            `/ip firewall address-list add list=VEXTHUB_QUARANTINE address=${ip} comment="${safeComment}" timeout=1d`
          );
        }
      }

      return lines.join("\n");
    }

    case "iptables": {
      const lines: string[] = [
        "#!/bin/sh",
        "# ==============================================================================",
        "# VextHub Zero Trust Threat Feed — Linux ipset / iptables Enforcement Script",
        `# Tenant: ${tenantId} | Generated: ${timestamp} | Total IPs: ${safeBlockedIps.length}`,
        "# ==============================================================================",
        "set -e",
        "ipset create vext_quarantine hash:ip -exist",
        "ipset flush vext_quarantine",
      ];

      if (safeBlockedIps.length > 0) {
        for (const ip of safeBlockedIps) {
          lines.push(`ipset add vext_quarantine ${ip}`);
        }
      }

      lines.push(
        "iptables -C FORWARD -m set --match-set vext_quarantine src -j DROP 2>/dev/null || iptables -I FORWARD 1 -m set --match-set vext_quarantine src -j DROP",
        "iptables -C INPUT -m set --match-set vext_quarantine src -j DROP 2>/dev/null || iptables -I INPUT 1 -m set --match-set vext_quarantine src -j DROP",
      );

      return lines.join("\n");
    }

    default: {
      return JSON.stringify({ error: `Formato de feed não suportado: ${String(format)}` });
    }
  }
}
