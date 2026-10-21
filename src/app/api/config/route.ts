import { supabaseAdmin } from "@/utils/supabase/admin";
import { NextResponse } from "next/server";
import { requireTenantAccess } from "@/utils/security/api-auth";
import { readLimitedJson, readStringField } from "@/utils/security/request-validation";

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "viewer");
    if (auth.response) return auth.response;

    const { data, error } = await supabaseAdmin
      .from("app_config")
      .select("company_name")
      .eq("tenant_id", auth.tenantId)
      .maybeSingle();

    if (error || !data) {
      // Retorna vazio se a tabela não existir ou estiver vazia
      return NextResponse.json({ company_name: "" });
    }
    return NextResponse.json(data);
  } catch {
    return NextResponse.json({ company_name: "" });
  }
}

export async function PATCH(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "admin");
    if (auth.response) return auth.response;

    const parsed = await readLimitedJson(request, 16 * 1024);
    if (parsed.response) return parsed.response;

    const company_name = readStringField(parsed.value as Record<string, unknown>, "company_name", 120);

    if (!company_name) {
      return NextResponse.json({ error: "Nome da empresa e obrigatorio." }, { status: 400 });
    }

    const { data, error } = await supabaseAdmin
      .from("app_config")
      .upsert({ tenant_id: auth.tenantId, company_name, updated_at: new Date().toISOString() }, { onConflict: 'tenant_id' })
      .select()
      .single();

    if (error) {
      console.error("PATCH /api/config error:", error);
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    return NextResponse.json(data);
  } catch (err: any) {
    console.error("PATCH /api/config fatal error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
