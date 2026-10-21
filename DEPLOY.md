# VextHub Deploy

## Web

Required environment variables:

```env
NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=
SUPABASE_SERVICE_ROLE_KEY=
AGENT_SHARED_SECRET=
```

`AGENT_SHARED_SECRET` must be at least 24 random characters.

## API

```env
DATABASE_URL=
REDIS_URL=
WEBHOOK_SIGNING_SECRET=
CORS_ORIGINS=
```

Local infrastructure:

```bash
docker compose -f infra/docker-compose.yml up --build
```

## Supabase

Apply `infra/supabase/vexthub_schema.sql` for tenant-aware deployments.
