# VextHub Agent

The VextHub endpoint agent is a defensive inventory collector. The preferred runtime is the C# tray agent packaged as `VextHubAgent.exe`.

Current behavior:

- reads `config.json`
- collects hostname, serial, OS, CPU, RAM, unit, installed software, watched security telemetry, and sensitive TCP port/session telemetry
- sends telemetry to `POST /api/telemetry`
- bootstraps with `x-agent-key`, then stores a per-agent `agent_token` and uses `x-agent-token`
- runs from the user's local app data folder with a visible tray icon and a 10 minute timer

The agent does not execute arbitrary shell commands, PowerShell snippets, uninstall actions, or screenshot commands.

Installer ZIPs are generated per unit through:

```text
GET /api/installer/:unitName
```

That route requires an authenticated dashboard session and a strong `AGENT_SHARED_SECRET`.

ZIP contents:

- `VextHubAgent.exe`: preferred C# agent installer/runtime.
- `config.json`: per-unit server, tenant, enrollment, and interval config.
- `legacy-powershell/`: fallback scripts only; not the recommended path.
