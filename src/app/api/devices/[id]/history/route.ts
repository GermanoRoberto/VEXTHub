import { supabaseAdmin } from "@/utils/supabase/admin";
import { NextResponse } from "next/server";
import { requireTenantAccess } from "@/utils/security/api-auth";

export async function GET(
  request: Request,
  context: { params: Promise<{ id: string }> }
) {
  try {
    const auth = await requireTenantAccess(request, "viewer");
    if (auth.response) return auth.response;

    const { id } = await context.params;

    if (!id) {
      return NextResponse.json({ error: "Machine ID is required" }, { status: 400 });
    }

    const { data, error } = await supabaseAdmin
      .from("pulses")
      .select("id, timestamp, unit")
      .eq("tenant_id", auth.tenantId)
      .eq("machine_id", id)
      .order("timestamp", { ascending: false })
      .limit(20);

    if (error) {
      console.error("Error fetching pulse history:", error);
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    return NextResponse.json({
      history: data || [],
    });
  } catch (err: any) {
    console.error("History API error:", err);
    return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
  }
}
