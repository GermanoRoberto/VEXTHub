import { supabaseAdmin } from "@/utils/supabase/admin";
import { NextResponse } from "next/server";
import { requireTenantAccess } from "@/utils/security/api-auth";

export const dynamic = 'force-dynamic';

export async function POST(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "analyst");
    if (auth.response) return auth.response;

    // 1. Get all machines
    const { data: machines } = await supabaseAdmin
      .from("machines")
      .select("hostname, unit, inventory_data")
      .eq("tenant_id", auth.tenantId);
    
    // 2. Get forbidden policies
    const { data: forbiddenPolicies } = await supabaseAdmin
      .from("software_policies")
      .select("name")
      .eq("tenant_id", auth.tenantId)
      .eq("status", "forbidden");
    
    const forbiddenNames = new Set(forbiddenPolicies?.map((p: any) => p.name) || []);

    let createdCount = 0;

    for (const machine of (machines || [])) {
      const softwareList = machine.inventory_data?.software || [];
      const violations = softwareList.filter((s: any) => s.name && forbiddenNames.has(s.name));

      if (violations.length > 0) {
        for (const v of violations) {
          const { data: existing } = await supabaseAdmin
            .from("compliance_alerts")
            .select("id")
            .eq("tenant_id", auth.tenantId)
            .eq("hostname", machine.hostname)
            .eq("software_name", v.name)
            .eq("is_resolved", false)
            .maybeSingle();

          if (!existing) {
            await supabaseAdmin.from("compliance_alerts").insert({
              tenant_id: auth.tenantId,
              hostname: machine.hostname,
              unit: machine.unit,
              software_name: v.name,
              message: `Software proibido detectado: ${v.name}`,
              is_resolved: false
            });
            createdCount++;
          }
        }
      }
    }

    return NextResponse.json({ success: true, created: createdCount });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
