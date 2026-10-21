import { analyzeTelemetryInventory } from "@/utils/security/telemetry-detection";

type DevEndpointSeed = {
  id: string;
  hostname: string;
  unit: string;
  os_name: string;
  cpu_info: string;
  ram_total: string;
  inventory_data: Record<string, unknown>;
};

const now = new Date();

function minutesAgo(minutes: number) {
  return new Date(now.getTime() - minutes * 60_000).toISOString();
}

const devEndpoints: DevEndpointSeed[] = [
  {
    id: "DEV-WKS-001",
    hostname: "DEV-WKS-001",
    unit: "Matriz TI",
    os_name: "Microsoft Windows 11 Pro",
    cpu_info: "Intel Core i7",
    ram_total: "16 GB",
    inventory_data: {
      software: [
        { name: "RustDesk", version: "1.2.7", publisher: "RustDesk" },
        { name: "AnyDesk", version: "8.0.8", publisher: "AnyDesk Software GmbH" },
        { name: "Microsoft 365 Apps", version: "16.0", publisher: "Microsoft Corporation" },
      ],
      processes: [
        {
          name: "rustdesk.exe",
          path: "C:\\Program Files\\RustDesk\\rustdesk.exe",
          command_line: "\"C:\\Program Files\\RustDesk\\rustdesk.exe\" --service",
        },
      ],
      services: [
        {
          name: "RustDesk",
          display_name: "RustDesk Service",
          state: "Running",
          start_mode: "Auto",
          path_name: "\"C:\\Program Files\\RustDesk\\rustdesk.exe\" --service",
        },
      ],
      startup_entries: [],
      network_connections: {
        listening_tcp_ports: [
          { protocol: "tcp", local_address: "0.0.0.0", local_port: 3389, exposure: "all_interfaces" },
          { protocol: "tcp", local_address: "127.0.0.1", local_port: 5900, exposure: "loopback" },
        ],
        established_external_tcp: [
          {
            protocol: "tcp",
            local_address: "192.168.10.22",
            local_port: 3389,
            remote_address: "198.51.100.42",
            remote_port: 54118,
            state: "Established",
          },
        ],
      },
    },
  },
  {
    id: "DEV-FIN-002",
    hostname: "DEV-FIN-002",
    unit: "Financeiro",
    os_name: "Microsoft Windows 10 Pro",
    cpu_info: "AMD Ryzen 5",
    ram_total: "8 GB",
    inventory_data: {
      software: [
        { name: "AnyDesk", version: "8.0.8", publisher: "AnyDesk Software GmbH" },
        { name: "Google Chrome", version: "124.0", publisher: "Google LLC" },
        { name: "LibreOffice", version: "24.2", publisher: "The Document Foundation" },
      ],
      processes: [],
      services: [],
      startup_entries: [],
      network_connections: {
        listening_tcp_ports: [{ protocol: "tcp", local_address: "127.0.0.1", local_port: 445, exposure: "loopback" }],
        established_external_tcp: [],
      },
    },
  },
  {
    id: "DEV-OPS-003",
    hostname: "DEV-OPS-003",
    unit: "Operacoes",
    os_name: "Microsoft Windows Server 2022",
    cpu_info: "Intel Xeon",
    ram_total: "32 GB",
    inventory_data: {
      software: [
        { name: "Microsoft Defender", version: "4.18", publisher: "Microsoft Corporation" },
        { name: "7-Zip", version: "24.01", publisher: "Igor Pavlov" },
      ],
      processes: [
        {
          name: "powershell.exe",
          path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          command_line: "powershell.exe -NoProfile -EncodedCommand <redacted>",
        },
      ],
      services: [],
      startup_entries: [],
      network_connections: {
        listening_tcp_ports: [{ protocol: "tcp", local_address: "10.20.0.15", local_port: 22, exposure: "private_interface" }],
        established_external_tcp: [],
      },
    },
  },
];

export function buildDevTelemetryData() {
  const endpoints = devEndpoints.map((endpoint, index) => {
    const securityAnalysis = analyzeTelemetryInventory(endpoint.inventory_data);
    return {
      ...endpoint,
      last_pulse: minutesAgo(index * 7 + 2),
      agent_version: "4.1.0",
      inventory_data: {
        ...endpoint.inventory_data,
        security_analysis: securityAnalysis,
      },
      risk_score: securityAnalysis.score,
      risk_level: securityAnalysis.risk_level,
      findings_count: securityAnalysis.findings.length,
    };
  });

  const alerts = endpoints.flatMap((endpoint) => {
    const analysis = endpoint.inventory_data.security_analysis;
    return analysis.findings.map((finding, index) => ({
      id: `${endpoint.id}-${finding.id}-${index}`,
      hostname: endpoint.hostname,
      unit: endpoint.unit,
      software_name: finding.software_name || finding.title,
      message: `[${finding.severity.toUpperCase()}] ${finding.title}. Evidence: ${finding.evidence}. Recommended: ${finding.recommended_action}`,
      severity: finding.severity,
      detection_category: finding.category,
      created_at: minutesAgo(index + 1),
      details: finding,
    }));
  });

  return {
    mode: "development",
    generated_at: new Date().toISOString(),
    telemetry_endpoint: "/api/telemetry",
    csharp_agent: {
      version: "4.1.0",
      source: "src/installer/VextHubAgent.cs",
      binary: "src/installer/VextHubAgent.exe",
      preferred_installer: "/api/installer/:unitName",
      bootstrap: "x-agent-key -> x-agent-token",
    },
    summary: {
      endpoints: endpoints.length,
      active_alerts: alerts.length,
      high_risk_endpoints: endpoints.filter((endpoint) => endpoint.risk_score >= 65).length,
      critical_endpoints: endpoints.filter((endpoint) => endpoint.risk_score >= 85).length,
      installed_software: endpoints.reduce((count, endpoint) => {
        const inventory = endpoint.inventory_data as Record<string, unknown>;
        const software = inventory.software;
        return count + (Array.isArray(software) ? software.length : 0);
      }, 0),
      external_sessions: endpoints.reduce((count, endpoint) => {
        const inventory = endpoint.inventory_data as Record<string, unknown>;
        const connections = inventory.network_connections as { established_external_tcp?: unknown[] } | undefined;
        return count + (Array.isArray(connections?.established_external_tcp) ? connections.established_external_tcp.length : 0);
      }, 0),
    },
    endpoints: endpoints.sort((left, right) => right.risk_score - left.risk_score),
    alerts: alerts.sort((left, right) => (right.severity === "critical" ? 1 : 0) - (left.severity === "critical" ? 1 : 0)),
    notes: [
      "AnyDesk appears in software inventory but is allowed by default and does not create a realtime alert.",
      "Network exposure detection is based on local listening TCP ports and established TCP sessions with public remote IPs.",
      "This dev portal does not use Supabase and does not persist telemetry.",
    ],
  };
}
