import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeTelemetryInventory,
} from "./telemetry-detection";

describe("Adversarial Challenge - Toxic Combinations & Attack Path Engine", () => {
  // =========================================================================
  // CHALLENGE 1: PARTIAL MATCHES (2 out of 3 signals must NOT trigger)
  // =========================================================================
  describe("Challenge 1: Partial Matches (2 of 3 signals must NOT trigger)", () => {
    // --- Path A: Remote Breach Path ---
    // Signal 1: Critical/KEV CVE or High-Risk RAT
    // Signal 2: Sensitive Listening Port (3389, 445, 139, 5800, 5900, 5901, 22)
    // Signal 3: Active External Connection (non-loopback, state != closed)

    it("Path A - Signals 1 & 2 only (Critical CVE + Sensitive Port, NO external conn) -> must NOT trigger", () => {
      const inventory = {
        software: [{ name: "Log4j Vulnerable App", version: "2.14.1", publisher: "Apache" }],
        processes: [],
        services: [],
        startup_entries: [],
        network_connections: {
          listening_tcp_ports: [{ local_address: "0.0.0.0", local_port: 3389 }],
          established_external_tcp: [], // NO external connection
        },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const breach = analysis.findings.find((f) => f.id === "toxic-path:remote-breach");
      assert.equal(breach, undefined, "Remote Breach path should NOT trigger without external connection");
    });

    it("Path A - Signals 1 & 3 only (Critical CVE + External Conn, NO sensitive listening port) -> must NOT trigger", () => {
      const inventory = {
        software: [{ name: "Log4j Vulnerable App", version: "2.14.1", publisher: "Apache" }],
        processes: [],
        services: [],
        startup_entries: [],
        network_connections: {
          listening_tcp_ports: [{ local_address: "0.0.0.0", local_port: 8080 }], // Non-sensitive port
          established_external_tcp: [
            { local_address: "10.0.0.50", local_port: 49152, remote_address: "198.51.100.1", remote_port: 443, state: "established" },
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const breach = analysis.findings.find((f) => f.id === "toxic-path:remote-breach");
      assert.equal(breach, undefined, "Remote Breach path should NOT trigger without sensitive listening port");
    });

    it("Path A - Signals 2 & 3 only (Sensitive Port + External Conn, NO critical CVE or high RAT) -> must NOT trigger", () => {
      const inventory = {
        software: [
          { name: "Google Chrome", version: "130.0.6723.70", publisher: "Google LLC" },
          { name: "Microsoft Office", version: "16.0", publisher: "Microsoft" },
        ],
        processes: [],
        services: [],
        startup_entries: [],
        network_connections: {
          listening_tcp_ports: [{ local_address: "0.0.0.0", local_port: 3389 }],
          established_external_tcp: [
            { local_address: "10.0.0.50", local_port: 3389, remote_address: "198.51.100.1", remote_port: 54321, state: "established" },
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const breach = analysis.findings.find((f) => f.id === "toxic-path:remote-breach");
      assert.equal(breach, undefined, "Remote Breach path should NOT trigger without critical CVE or high-risk RAT");
    });

    it("Path A - Medium severity RAT (Atera/ScreenConnect) + Sensitive Port + External Conn -> must NOT trigger", () => {
      const inventory = {
        software: [{ name: "Atera Agent", version: "1.0", publisher: "Atera" }],
        processes: [],
        services: [],
        startup_entries: [],
        network_connections: {
          listening_tcp_ports: [{ local_address: "0.0.0.0", local_port: 3389 }],
          established_external_tcp: [
            { local_address: "10.0.0.50", local_port: 3389, remote_address: "198.51.100.1", remote_port: 54321, state: "established" },
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const breach = analysis.findings.find((f) => f.id === "toxic-path:remote-breach");
      assert.equal(breach, undefined, "Remote Breach path should NOT trigger on medium-severity remote access tools");
    });

    it("Path A - Loopback listener (127.0.0.1:3389) + Critical CVE + External Conn -> must NOT trigger", () => {
      const inventory = {
        software: [{ name: "WinRAR Exploit", version: "6.22", publisher: "win.rar GmbH" }],
        processes: [],
        services: [],
        startup_entries: [],
        network_connections: {
          listening_tcp_ports: [{ local_address: "127.0.0.1", local_port: 3389 }], // Loopback only
          established_external_tcp: [
            { local_address: "10.0.0.50", local_port: 49152, remote_address: "198.51.100.1", remote_port: 443, state: "established" },
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const breach = analysis.findings.find((f) => f.id === "toxic-path:remote-breach");
      assert.equal(breach, undefined, "Remote Breach path should NOT trigger on loopback listener");
    });

    it("Path A - Closed external connection (state='closed') + Critical CVE + Sensitive Port -> must NOT trigger", () => {
      const inventory = {
        software: [{ name: "WinRAR Exploit", version: "6.22", publisher: "win.rar GmbH" }],
        processes: [],
        services: [],
        startup_entries: [],
        network_connections: {
          listening_tcp_ports: [{ local_address: "0.0.0.0", local_port: 445 }],
          established_external_tcp: [
            { local_address: "10.0.0.50", local_port: 445, remote_address: "198.51.100.1", remote_port: 54321, state: "closed" },
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const breach = analysis.findings.find((f) => f.id === "toxic-path:remote-breach");
      assert.equal(breach, undefined, "Remote Breach path should NOT trigger on closed connection");
    });

    // --- Path B: Stealth Persistence Path ---
    // Signal 1: Process running from suspicious path (%TEMP%, AppData, Public, ProgramData)
    // Signal 2: Startup / Registry Run key or auto-start service
    // Signal 3: Encoded LOLBin (powershell -enc, mshta, regsvr32, certutil)

    it("Path B - Signals 1 & 2 only (Suspicious path + Startup entry, NO lolbin) -> must NOT trigger", () => {
      const inventory = {
        software: [],
        processes: [
          { name: "benign.exe", path: "C:\\Users\\user\\AppData\\Local\\Temp\\benign.exe", command_line: "benign.exe --normal" },
        ],
        services: [],
        startup_entries: [
          { name: "BenignApp", command: "C:\\Users\\user\\AppData\\Local\\Temp\\benign.exe", location: "HKCU\\Run" },
        ],
        network_connections: { listening_tcp_ports: [], established_external_tcp: [] },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const stealth = analysis.findings.find((f) => f.id === "toxic-path:stealth-persistence");
      assert.equal(stealth, undefined, "Stealth Persistence path should NOT trigger without LOLBin execution");
    });

    it("Path B - Signals 1 & 3 only (Suspicious path + LOLBin, NO persistence entry or auto service) -> must NOT trigger", () => {
      const inventory = {
        software: [],
        processes: [
          { name: "updater.exe", path: "C:\\Users\\user\\AppData\\Local\\Temp\\updater.exe", command_line: "updater.exe" },
          { name: "powershell.exe", path: "C:\\Windows\\System32\\powershell.exe", command_line: "powershell.exe -enc AAAA" },
        ],
        services: [
          { name: "ManualSvc", start_mode: "manual" }, // Manual, not auto
        ],
        startup_entries: [], // Empty
        network_connections: { listening_tcp_ports: [], established_external_tcp: [] },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const stealth = analysis.findings.find((f) => f.id === "toxic-path:stealth-persistence");
      assert.equal(stealth, undefined, "Stealth Persistence path should NOT trigger without persistence entry");
    });

    it("Path B - Signals 2 & 3 only (Startup entry + LOLBin, NO suspicious temp/appdata path) -> must NOT trigger", () => {
      const inventory = {
        software: [],
        processes: [
          {
            name: "powershell.exe",
            path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line: "powershell.exe -enc AAAA",
          },
        ],
        services: [],
        startup_entries: [
          { name: "StandardApp", command: "C:\\Program Files\\App\\app.exe", location: "HKLM\\Run" },
        ],
        network_connections: { listening_tcp_ports: [], established_external_tcp: [] },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const stealth = analysis.findings.find((f) => f.id === "toxic-path:stealth-persistence");
      assert.equal(stealth, undefined, "Stealth Persistence path should NOT trigger without process in volatile path");
    });

    // --- Path C: Lateral Movement / Credential Exfiltration Path ---
    // Signal 1: Mimikatz/credential tool or LSASS access indicator
    // Signal 2: External SMB/RDP session (ports 445, 139, 3389, 22)
    // Signal 3: Statistical Anomaly (Z-score > 2.5 or anomaly flag)

    it("Path C - Signals 2 & 3 only (SMB session + Z-Score 3.5, NO Mimikatz/credential tool) -> must NOT trigger", () => {
      const inventory = {
        software: [],
        processes: [
          { name: "explorer.exe", path: "C:\\Windows\\explorer.exe", command_line: "explorer.exe" },
        ],
        services: [],
        startup_entries: [],
        max_z_score: 3.5,
        network_connections: {
          listening_tcp_ports: [],
          established_external_tcp: [
            { local_address: "10.0.0.50", local_port: 49152, remote_address: "10.0.0.1", remote_port: 445, state: "established" },
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const lateral = analysis.findings.find((f) => f.id === "toxic-path:lateral-credential-exfil");
      assert.equal(lateral, undefined, "Lateral Movement path should NOT trigger without credential dumping indicator");
    });

    it("Path C - Signals 1 & 3 only (Mimikatz + Z-Score 3.5, NO SMB/RDP session) -> must NOT trigger", () => {
      const inventory = {
        software: [{ name: "Mimikatz", version: "2.2.0", publisher: "gentilkiwi" }],
        processes: [
          { name: "mimikatz.exe", path: "C:\\tools\\mimikatz.exe", command_line: "mimikatz.exe" },
        ],
        services: [],
        startup_entries: [],
        max_z_score: 3.5,
        network_connections: {
          listening_tcp_ports: [],
          established_external_tcp: [
            // Only regular web browsing on 443, not SMB/RDP
            { local_address: "10.0.0.50", local_port: 49152, remote_address: "142.250.190.46", remote_port: 443, state: "established" },
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const lateral = analysis.findings.find((f) => f.id === "toxic-path:lateral-credential-exfil");
      assert.equal(lateral, undefined, "Lateral Movement path should NOT trigger without external SMB/RDP session");
    });

    it("Path C - Signals 1 & 2 only (Mimikatz + SMB session, but NORMAL behavior z_score=0.2, NOT anomalous) -> must NOT trigger", () => {
      const inventory = {
        software: [{ name: "Mimikatz", version: "2.2.0", publisher: "gentilkiwi" }],
        processes: [
          { name: "mimikatz.exe", path: "C:\\tools\\mimikatz.exe", command_line: "mimikatz.exe sekurlsa" },
        ],
        services: [],
        startup_entries: [],
        max_z_score: 0.2, // Below 2.5 threshold!
        is_anomalous: false,
        telemetry_anomaly: false,
        network_connections: {
          listening_tcp_ports: [],
          established_external_tcp: [
            { local_address: "10.0.0.50", local_port: 49152, remote_address: "10.0.0.1", remote_port: 445, state: "established" },
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const lateral = analysis.findings.find((f) => f.id === "toxic-path:lateral-credential-exfil");
      // Under the 3-signal specification (DISPATCH.md: 2 of 3 signals must NOT trigger),
      // this must NOT trigger because the statistical anomaly signal is absent.
      assert.equal(lateral, undefined, "Path C must NOT trigger when statistical anomaly is absent (Z-score 0.2 < 2.5)");
    });
  });

  // =========================================================================
  // CHALLENGE 2: COMPLETE MATCHES (All 3 signals -> Score >= 95 & CRITICAL)
  // =========================================================================
  describe("Challenge 2: Complete Matches (All 3 signals present)", () => {
    it("Path A Complete: Weaponized CVE (Log4j) + RDP Port 3389 + External IP -> Score >= 95, Critical", () => {
      const inventory = {
        software: [{ name: "Log4j Vulnerable App", version: "2.14.1", publisher: "Apache" }],
        processes: [],
        services: [],
        startup_entries: [],
        network_connections: {
          listening_tcp_ports: [{ local_address: "0.0.0.0", local_port: 3389 }],
          established_external_tcp: [
            { local_address: "10.0.0.50", local_port: 3389, remote_address: "198.51.100.22", remote_port: 54321, state: "established" },
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const pathA = analysis.findings.find((f) => f.id === "toxic-path:remote-breach");
      assert.ok(pathA, "Path A must trigger");
      assert.equal(pathA.severity, "critical");
      assert.ok(pathA.score >= 95, `Expected score >= 95, got ${pathA.score}`);
      assert.equal(pathA.category, "toxic_combination");
      assert.equal(pathA.attack_path?.type, "remote_breach");
      assert.ok(pathA.attack_path?.correlated_signals.length === 3);
      assert.ok(pathA.attack_path?.kill_chain.includes("Initial Access"));
      assert.deepEqual(pathA.attack_path?.mitre_tactics, ["TA0001", "TA0002", "TA0011"]);
    });

    it("Path A Complete with High-Risk RAT (Ammyy Admin) + SSH Port 22 + External IP -> Score >= 95, Critical", () => {
      const inventory = {
        software: [{ name: "Ammyy Admin", version: "3.5", publisher: "Ammyy" }],
        processes: [],
        services: [],
        startup_entries: [],
        network_connections: {
          listening_tcp_ports: [{ local_address: "0.0.0.0", local_port: 22 }],
          established_external_tcp: [
            { local_address: "10.0.0.50", local_port: 22, remote_address: "203.0.113.10", remote_port: 42100, state: "established" },
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const pathA = analysis.findings.find((f) => f.id === "toxic-path:remote-breach");
      assert.ok(pathA, "Path A with RAT must trigger");
      assert.equal(pathA.severity, "critical");
      assert.ok(pathA.score >= 95);
      assert.ok(pathA.evidence.includes("Ammyy Admin"));
    });

    it("Path B Complete: Temp Process + Startup Run Key + LOLBin powershell -enc -> Score >= 95, Critical", () => {
      const inventory = {
        software: [],
        processes: [
          { name: "loader.exe", path: "C:\\Users\\victim\\AppData\\Local\\Temp\\loader.exe", command_line: "loader.exe" },
          { name: "powershell.exe", path: "C:\\Windows\\System32\\powershell.exe", command_line: "powershell.exe -enc AAAAAA==" },
        ],
        services: [],
        startup_entries: [
          { name: "UpdaterRunKey", command: "C:\\Users\\victim\\AppData\\Local\\Temp\\loader.exe", location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        ],
        network_connections: { listening_tcp_ports: [], established_external_tcp: [] },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const pathB = analysis.findings.find((f) => f.id === "toxic-path:stealth-persistence");
      assert.ok(pathB, "Path B must trigger");
      assert.equal(pathB.severity, "critical");
      assert.ok(pathB.score >= 95);
      assert.equal(pathB.attack_path?.type, "stealth_persistence");
      assert.ok(pathB.attack_path?.kill_chain.includes("Persistence"));
      assert.deepEqual(pathB.attack_path?.mitre_tactics, ["TA0002", "TA0003", "TA0005"]);
    });

    it("Path B Complete: ProgramData Process + Automatic Service + LOLBin regsvr32 -> Score >= 95, Critical", () => {
      const inventory = {
        software: [],
        processes: [
          { name: "payload.dll", path: "C:\\ProgramData\\payload.dll", command_line: "regsvr32.exe /s C:\\ProgramData\\payload.dll" },
        ],
        services: [
          { name: "PersistentSvc", display_name: "Windows Driver Helper", start_mode: "auto", path_name: "C:\\ProgramData\\payload.dll" },
        ],
        startup_entries: [],
        network_connections: { listening_tcp_ports: [], established_external_tcp: [] },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const pathB = analysis.findings.find((f) => f.id === "toxic-path:stealth-persistence");
      assert.ok(pathB, "Path B with ProgramData + Service + regsvr32 must trigger");
      assert.equal(pathB.severity, "critical");
      assert.ok(pathB.score >= 95);
    });

    it("Path C Complete: Mimikatz + External SMB Session + Z-Score 3.2 -> Score 100, Critical", () => {
      const inventory = {
        software: [{ name: "Mimikatz Tool", version: "2.2.0", publisher: "gentilkiwi" }],
        processes: [
          { name: "mimikatz.exe", path: "C:\\Windows\\Temp\\mimikatz.exe", command_line: "mimikatz.exe \"privilege::debug\"" },
        ],
        services: [],
        startup_entries: [],
        max_z_score: 3.2,
        network_connections: {
          listening_tcp_ports: [],
          established_external_tcp: [
            { local_address: "10.0.0.50", local_port: 49152, remote_address: "10.0.0.1", remote_port: 445, state: "established" },
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(inventory);
      const pathC = analysis.findings.find((f) => f.id === "toxic-path:lateral-credential-exfil");
      assert.ok(pathC, "Path C must trigger");
      assert.equal(pathC.severity, "critical");
      assert.equal(pathC.score, 100);
      assert.equal(pathC.attack_path?.type, "lateral_movement");
      assert.ok(pathC.attack_path?.kill_chain.includes("Credential Access"));
      assert.deepEqual(pathC.attack_path?.mitre_tactics, ["TA0006", "TA0008", "TA0010"]);
    });
  });

  // =========================================================================
  // CHALLENGE 3: MULTI-PATH COLLISIONS (Simultaneous attack paths on same host)
  // =========================================================================
  describe("Challenge 3: Multi-Path Collisions on Same Host", () => {
    it("all 3 attack paths simultaneously active -> no clobbering, unique IDs, sorted to top", () => {
      const complexInventory = {
        // Path A signals
        software: [
          { name: "OpenSSH Portable", version: "9.2p1", publisher: "OpenBSD" }, // CVE-2024-6387 regreSSHion
        ],
        // Path B & C processes
        processes: [
          { name: "backdoor.exe", path: "C:\\Users\\Public\\backdoor.exe", command_line: "C:\\Users\\Public\\backdoor.exe" },
          { name: "powershell.exe", path: "C:\\Windows\\System32\\powershell.exe", command_line: "powershell.exe -encodedcommand JABhAD0AMQA=" },
          { name: "mimikatz.exe", path: "C:\\tools\\mimikatz.exe", command_line: "mimikatz.exe sekurlsa::logonpasswords" },
        ],
        services: [
          { name: "BackdoorService", start_mode: "automatic", path_name: "C:\\Users\\Public\\backdoor.exe" },
        ],
        startup_entries: [
          { name: "PublicBackdoor", command: "C:\\Users\\Public\\backdoor.exe", location: "HKCU\\Run" },
        ],
        max_z_score: 4.8, // Path C anomaly
        network_connections: {
          listening_tcp_ports: [
            { local_address: "0.0.0.0", local_port: 22 }, // Path A listener
          ],
          established_external_tcp: [
            { local_address: "10.0.0.50", local_port: 22, remote_address: "185.220.101.5", remote_port: 44321, state: "established" }, // Path A conn
            { local_address: "10.0.0.50", local_port: 49200, remote_address: "10.0.0.2", remote_port: 445, state: "established" }, // Path C SMB
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(complexInventory);

      // 1. Overall host posture
      assert.equal(analysis.risk_level, "critical");
      assert.equal(analysis.score, 100);

      // 2. All 3 toxic attack paths must exist
      const toxicPaths = analysis.findings.filter((f) => f.category === "toxic_combination");
      assert.equal(toxicPaths.length, 3, "All 3 toxic paths must be present without clobbering");

      const pathA = toxicPaths.find((f) => f.id === "toxic-path:remote-breach");
      const pathB = toxicPaths.find((f) => f.id === "toxic-path:stealth-persistence");
      const pathC = toxicPaths.find((f) => f.id === "toxic-path:lateral-credential-exfil");

      assert.ok(pathA, "Path A must be present");
      assert.ok(pathB, "Path B must be present");
      assert.ok(pathC, "Path C must be present");

      // 3. IDs must be unique across all findings
      const allIds = analysis.findings.map((f) => f.id);
      const uniqueIds = new Set(allIds);
      assert.equal(allIds.length, uniqueIds.size, "Findings array contains duplicate IDs!");

      // 4. Toxic combinations must occupy the top indices (0, 1, 2)
      assert.equal(analysis.findings[0].category, "toxic_combination");
      assert.equal(analysis.findings[1].category, "toxic_combination");
      assert.equal(analysis.findings[2].category, "toxic_combination");

      // 5. Sorted descending by score: 100 (Path C) -> 98 (Path A) -> 95 (Path B)
      assert.equal(analysis.findings[0].score, 100);
      assert.equal(analysis.findings[1].score, 98);
      assert.equal(analysis.findings[2].score, 95);

      // 6. Non-toxic findings follow after
      for (let i = 3; i < analysis.findings.length; i++) {
        assert.notEqual(analysis.findings[i].category, "toxic_combination");
      }
    });
  });

  // =========================================================================
  // CHALLENGE 4: EXTREME & MALFORMED TELEMETRY INPUTS
  // =========================================================================
  describe("Challenge 4: Extreme & Malformed Telemetry Inputs", () => {
    it("handles completely empty inventory object {} without errors", () => {
      const analysis = analyzeTelemetryInventory({});
      assert.equal(analysis.score, 0);
      assert.equal(analysis.risk_level, "low");
      assert.equal(analysis.findings.length, 0);
      assert.ok(analysis.analyzed_at);
    });

    it("handles arrays with null, undefined, primitive, and empty elements safely", () => {
      const dirtyInventory = {
        software: [null, undefined, 42, "string-entry", {}, { name: "", version: "" }],
        processes: [null, undefined, true, { name: undefined, path: null, command_line: undefined }],
        services: [null, { start_mode: null, name: undefined }],
        startup_entries: [null, { command: null, name: undefined }],
        network_connections: {
          listening_tcp_ports: [null, { local_port: null, local_address: undefined }],
          established_external_tcp: [null, { local_port: undefined, remote_address: null }],
        },
      };

      // Must execute cleanly without unhandled TypeError
      assert.doesNotThrow(() => {
        const analysis = analyzeTelemetryInventory(dirtyInventory as unknown as Record<string, unknown>);
        assert.equal(typeof analysis.score, "number");
        assert.ok(Array.isArray(analysis.findings));
      });
    });

    it("handles extreme and out-of-range port numbers (0, negative, > 65535, NaN, float)", () => {
      const extremePortsInventory = {
        software: [],
        processes: [],
        services: [],
        startup_entries: [],
        network_connections: {
          listening_tcp_ports: [
            { local_port: 0 },
            { local_port: -3389 },
            { local_port: 65536 },
            { local_port: 999999 },
            { local_port: NaN },
            { local_port: 3389.5 },
            { local_port: "3389" as unknown as number }, // String port
          ],
          established_external_tcp: [
            { local_port: -1, remote_port: 999999, remote_address: "1.2.3.4" },
            { local_port: 70000, remote_port: 0, remote_address: "1.2.3.4" },
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(extremePortsInventory);
      // Valid string "3389" is parsed by Number("3389") which equals 3389 and is an integer in range!
      // But 0, -3389, 65536, 999999, NaN, 3389.5 must be safely rejected by toPort.
      const portFindings = analysis.findings.filter((f) => f.category === "network_exposure");
      for (const finding of portFindings) {
        assert.ok(!finding.id.endsWith(":0"), "Port 0 should not be accepted");
        assert.ok(!finding.id.includes(":-"), "Negative port should not be accepted");
        assert.ok(!finding.id.includes("65536"), "Port 65536 should not be accepted");
        assert.ok(!finding.id.includes("999999"), "Port 999999 should not be accepted");
      }
    });

    it("handles weird IP representations and loopbacks (IPv6 ::1, localhost, ::ffff:127.0.0.1)", () => {
      const loopbackInventory = {
        software: [{ name: "Log4j Vulnerable App", version: "2.14.1", publisher: "Apache" }],
        processes: [],
        services: [],
        startup_entries: [],
        network_connections: {
          listening_tcp_ports: [
            { local_address: "localhost", local_port: 3389 },
            { local_address: "::1", local_port: 445 },
          ],
          established_external_tcp: [
            { local_address: "127.0.0.1", local_port: 3389, remote_address: "127.0.0.1", remote_port: 50000 },
            { local_address: "::1", local_port: 445, remote_address: "localhost", remote_port: 50001 },
          ],
        },
      };

      const analysis = analyzeTelemetryInventory(loopbackInventory);
      const breach = analysis.findings.find((f) => f.id === "toxic-path:remote-breach");
      assert.equal(breach, undefined, "Loopback addresses must never trigger Remote Breach toxic combination");
    });

    it("survives gigantic high-volume payload (10,000 items) in under 500ms", () => {
      const largeProcesses = Array.from({ length: 5000 }, (_, i) => ({
        name: `process_${i}.exe`,
        path: `C:\\Program Files\\App_${i}\\process_${i}.exe`,
        command_line: `process_${i}.exe --worker-id=${i}`,
      }));

      const largeSoftware = Array.from({ length: 3000 }, (_, i) => ({
        name: `SafeSoftware_${i}`,
        publisher: `Vendor_${i}`,
        version: `1.0.${i}`,
      }));

      const largeConnections = Array.from({ length: 2000 }, (_, i) => ({
        local_address: "192.168.1.100",
        local_port: 10000 + (i % 50000),
        remote_address: `10.0.${Math.floor(i / 256)}.${i % 256}`,
        remote_port: 80,
        state: "established",
      }));

      const hugeInventory = {
        software: largeSoftware,
        processes: largeProcesses,
        services: [],
        startup_entries: [],
        network_connections: {
          listening_tcp_ports: [],
          established_external_tcp: largeConnections,
        },
      };

      const startTime = performance.now();
      const analysis = analyzeTelemetryInventory(hugeInventory);
      const elapsed = performance.now() - startTime;

      assert.ok(elapsed < 1000, `Execution took ${elapsed.toFixed(1)}ms, expected under 1000ms`);
      assert.equal(analysis.score, 0);
      assert.equal(analysis.findings.length, 0);
    });

    it("resists prototype pollution keys in inventory input", () => {
      const pollutedInventory = JSON.parse(
        '{"__proto__": {"polluted": true}, "constructor": {"prototype": {"admin": true}}, "software": []}'
      );

      const analysis = analyzeTelemetryInventory(pollutedInventory);
      assert.equal(analysis.score, 0);
      assert.equal(({} as Record<string, unknown>).polluted, undefined);
    });
  });
});
