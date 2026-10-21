# VextHub Security Model

VextHub is configured for defensive purple-team operations.

## Allowed Agent Actions

Only these action types are accepted by the app:

- `REFRESH_INVENTORY`
- `RUN_COMPLIANCE_SCAN`
- `UPDATE_AGENT`

The old arbitrary `POWERSHELL`, `CMD`, screenshot, and uninstall flows from the source projects were not promoted into VextHub.

## Endpoint Agent

The preferred endpoint runtime is the C# tray agent built from `src/installer/VextHubAgent.cs`. It reads the per-unit `config.json`, sends defensive telemetry to `POST /api/telemetry`, and stores a per-agent token after the first authorized bootstrap. The PowerShell agent remains packaged only under `legacy-powershell/` in the ZIP as a fallback path.

For lower false-positive rates in production, sign `VextHubAgent.exe` with an Authenticode code-signing certificate and distribute the per-unit ZIP from the authenticated dashboard route.

## Secrets

Do not commit `.env.local`, service-role keys, webhook secrets, or agent secrets.

Required:

- `AGENT_SHARED_SECRET`: at least 24 random characters.
- `WEBHOOK_SIGNING_SECRET`: strong random value for HMAC validation.

## Tenant Isolation

Use `infra/supabase/vexthub_schema.sql` for new deployments. It enables RLS on tenant-owned tables and scopes reads/writes by membership.

## Realtime Detection

The telemetry intake runs a local detector before returning the agent response. It flags:

- remote access tools often abused in scams or rogue support activity, including RustDesk, UltraViewer, Supremo, Ammyy Admin, DWService, ScreenConnect, Atera, Splashtop, Zoho Assist, and AeroAdmin
- suspicious execution indicators such as encoded PowerShell, MSHTA, and regsvr32 scriptlet patterns
- startup and service persistence for watched tools
- sensitive TCP exposure indicators for RDP, VNC, SMB, and SSH listening ports or established external sessions

AnyDesk is treated as an allowed tool by default. It still appears in software inventory, but it does not create a realtime security alert unless a separate policy marks it as forbidden.

AI enrichment is optional through `VEXTHUB_AI_ENABLED=true`. Supported providers are `gemini`, `groq`, and `opencloud-compatible`. The AI path is limited to defensive senior-analyst triage, sends a capped telemetry payload, requires structured JSON output, and rejects non-HTTPS provider URLs except localhost development. It can recommend investigation, containment, remediation, verification, prevention, and escalation steps, but it must not recommend exploit, evasion, credential theft, persistence, destructive actions, or arbitrary agent shell execution. The deterministic detector remains the source of truth for alert creation.

## Operational Notes

- Keep endpoint actions auditable.
- Run expensive scans through Redis workers.
- Execute plugins only in locked-down containers with pinned images.
- Store production secrets in a managed secret store instead of plaintext env files where possible.
