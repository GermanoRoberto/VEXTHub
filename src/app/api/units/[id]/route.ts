import { NextResponse } from "next/server";
import { supabaseAdmin } from "@/utils/supabase/admin";
import { requireTenantAccess } from "@/utils/security/api-auth";
import { allowOnlyFields, readLimitedJson, readStringField } from "@/utils/security/request-validation";

type RouteContext = {
  params: Promise<{ id: string }>;
};

export async function DELETE(_request: Request, context: RouteContext) {
  const auth = await requireTenantAccess(_request, "admin");
  if (auth.response) return auth.response;

  const { id } = await context.params;

  if (!id) {
    return NextResponse.json({ error: "ID da unidade e obrigatorio." }, { status: 400 });
  }

  const { error } = await supabaseAdmin
    .from("units")
    .delete()
    .eq("tenant_id", auth.tenantId)
    .eq("id", id);

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ ok: true });
}
export async function PATCH(request: Request, context: RouteContext) {
  const auth = await requireTenantAccess(request, "admin");
  if (auth.response) return auth.response;

  const { id } = await context.params;
  const parsed = await readLimitedJson(request, 32 * 1024);
  if (parsed.response) return parsed.response;

  const body = allowOnlyFields(parsed.value as Record<string, unknown>, [
    "name",
    "description",
    "auto_allow_compliance",
  ]);

  if (Object.prototype.hasOwnProperty.call(body, "name")) {
    body.name = readStringField(body, "name", 120);
    if (!body.name) {
      return NextResponse.json({ error: "Nome da unidade e obrigatorio." }, { status: 400 });
    }
  }

  if (Object.prototype.hasOwnProperty.call(body, "description")) {
    body.description = readStringField(body, "description", 500) || null;
  }

  if (Object.prototype.hasOwnProperty.call(body, "auto_allow_compliance")) {
    body.auto_allow_compliance = !!body.auto_allow_compliance;
  }

  const { error } = await supabaseAdmin
    .from("units")
    .update(body)
    .eq("tenant_id", auth.tenantId)
    .eq("id", id);

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ ok: true });
}
