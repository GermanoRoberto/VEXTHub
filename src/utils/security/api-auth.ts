import { NextResponse } from "next/server";
import { createClient } from "@/utils/supabase/server";

export type TenantRole = "owner" | "admin" | "analyst" | "viewer";

type TenantMembership = {
  tenant_id: string;
  role: TenantRole;
};

const ROLE_RANK: Record<TenantRole, number> = {
  viewer: 1,
  analyst: 2,
  admin: 3,
  owner: 4,
};

function jsonError(error: string, status: number) {
  return NextResponse.json({ error }, { status });
}

function getRequestedTenantId(request?: Request) {
  if (!request) return null;

  const headerTenant = request.headers.get("x-tenant-id")?.trim();
  if (headerTenant) return headerTenant;

  try {
    const url = new URL(request.url);
    return url.searchParams.get("tenant_id")?.trim() || null;
  } catch {
    return null;
  }
}

import { supabaseAdmin } from "@/utils/supabase/admin";

export function isLocalAuthFallbackAllowed(): boolean {
  if (
    process.env.VEXTHUB_LOCAL_MODE === "true" ||
    process.env.NEXT_PUBLIC_SIMULATION_MODE === "true" ||
    process.env.NODE_ENV !== "production"
  ) {
    return true;
  }
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL?.trim();
  const supabaseKey = (
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
  )?.trim();
  if (!supabaseUrl || !supabaseKey) return true;
  return false;
}

export async function requireDashboardUser() {
  if (isLocalAuthFallbackAllowed()) {
    return { 
      user: { id: "00000000-0000-0000-0000-000000000000", email: "guest@vexthub.local" }, 
      response: null 
    };
  }

  const supabase = await createClient();
  const {
    data: { user },
    error,
  } = await supabase.auth.getUser();

  if (error || !user) {
    return {
      user: null,
      response: NextResponse.json({ error: "Unauthorized" }, { status: 401 }),
    };
  }

  return { user, response: null };
}

export async function requireTenantAccess(
  request?: Request,
  minimumRole: TenantRole = "viewer",
) {
  const requestedTenantId = getRequestedTenantId(request);

  if (isLocalAuthFallbackAllowed()) {
    return {
      user: { id: "00000000-0000-0000-0000-000000000000", email: "guest@vexthub.local" },
      tenantId: requestedTenantId || "00000000-0000-0000-0000-000000000000",
      role: "owner" as TenantRole,
      response: null,
    };
  }

  const auth = await requireDashboardUser();
  if (auth.response) {
    return {
      user: null,
      tenantId: null,
      role: null,
      response: auth.response,
    };
  }

  const supabase = await createClient();

  let query = supabase
    .from("tenant_memberships")
    .select("tenant_id, role")
    .eq("user_id", auth.user!.id);

  if (requestedTenantId) {
    query = query.eq("tenant_id", requestedTenantId);
  }

  const { data, error } = await query
    .order("created_at", { ascending: true })
    .limit(1);

  if (error) {
    console.error("Tenant membership lookup failed:", error);
    return {
      user: auth.user,
      tenantId: null,
      role: null,
      response: jsonError("Tenant authorization failed.", 403),
    };
  }

  const membership = (data?.[0] || null) as TenantMembership | null;
  if (!membership) {
    return {
      user: auth.user,
      tenantId: null,
      role: null,
      response: jsonError("No tenant membership found.", 403),
    };
  }

  if (ROLE_RANK[membership.role] < ROLE_RANK[minimumRole]) {
    return {
      user: auth.user,
      tenantId: membership.tenant_id,
      role: membership.role,
      response: jsonError("Insufficient permissions.", 403),
    };
  }

  return {
    user: auth.user,
    tenantId: membership.tenant_id,
    role: membership.role,
    response: null,
  };
}

export async function logAuditEvent(params: {
  tenantId?: string | null;
  actorUserId?: string | null;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  details?: Record<string, unknown>;
}): Promise<void> {
  try {
    const { tenantId, actorUserId, action, targetType, targetId, details } = params;
    if (!tenantId || tenantId === "00000000-0000-0000-0000-000000000000") return;
    await supabaseAdmin.from("audit_log").insert({
      tenant_id: tenantId,
      actor_user_id: actorUserId && actorUserId !== "00000000-0000-0000-0000-000000000000" ? actorUserId : null,
      action,
      target_type: targetType || null,
      target_id: targetId || null,
      details: details || {},
    });
  } catch (err) {
    console.error("Falha ao registrar auditoria em audit_log:", err);
  }
}

export function clampString(value: unknown, maxLength: number) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}
