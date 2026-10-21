# VextHub Architecture

## What Was Reused

From Camilo:

- Next.js dashboard and Supabase integration.
- Units, device inventory, compliance, reports, and installer ZIP flow.
- Network vendor resolver and operational UI components.

From TheAPEX:

- API-first service separation.
- Security header model.
- Health check pattern.
- JSON observability.
- Webhook intake model.
- Sigma-style telemetry detection idea.
- Worker/queue separation for expensive jobs.

## Runtime Layout

```text
VEXT hub/
  src/                    Next.js SaaS dashboard and API routes
  src/installer/          preferred C# endpoint agent source and local build script
  public/installer/       installer scripts packaged with the rendered agent
  services/api/           FastAPI service for queues, webhooks, plugins
  infra/supabase/         PostgreSQL/Supabase RLS schema
  infra/k8s/              Kubernetes starting point
```

## Multi-Tenant Data Model

The canonical SaaS schema is `infra/supabase/vexthub_schema.sql`.

Every tenant-owned table has `tenant_id`. RLS policies call `public.is_tenant_member(tenant_id)` so authenticated users only see tenant data where they have membership.

## Worker Execution

Heavy work is queued through Redis. API requests enqueue jobs and return immediately. The worker consumes `vexthub:jobs`.

Plugin jobs are contracts for isolated container execution only. The API accepts pinned container images and records sandbox intent; it does not execute arbitrary user code inside the API process.

## Webhooks

Inbound webhook telemetry requires:

- `X-Tenant-Id`
- `X-VextHub-Signature`

The signature format is `sha256=<hex_hmac_sha256>`.
