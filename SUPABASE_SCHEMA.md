# VextHub Supabase Schema

Use the canonical SaaS schema at:

```text
infra/supabase/vexthub_schema.sql
```

That schema adds:

- `tenants`
- `tenant_memberships`
- tenant-scoped `units`, `machines`, `pulses`, `software_policies`, `compliance_alerts`, `agent_commands`
- `audit_log`
- `webhook_endpoints`
- RLS policies for tenant isolation

Legacy Camilo tables are still represented conceptually, but new deployments should use the tenant-aware schema instead of global tables.
