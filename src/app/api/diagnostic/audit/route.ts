import { supabaseAdmin } from "@/utils/supabase/admin";
import { NextResponse } from "next/server";
import { requireTenantAccess } from "@/utils/security/api-auth";

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "admin");
    if (auth.response) return auth.response;

    const { data: machines, error } = await supabaseAdmin
      .from("machines")
      .select("hostname, last_pulse, agent_version")
      .eq("tenant_id", auth.tenantId)
      .order("last_pulse", { ascending: false });

    if (error) throw error;

    const now = new Date();
    const audit: Array<{
      hostname?: string | null;
      version: string;
      last_pulse?: string | null;
      minutes_ago: number | "N/A";
      status: "ONLINE" | "OFFLINE";
    }> = machines.map((machine: { hostname?: string | null; last_pulse?: string | null; agent_version?: string | null }) => {
      const lastPulse = machine.last_pulse ? new Date(machine.last_pulse) : null;
      const diffMin = lastPulse ? Math.round((now.getTime() - lastPulse.getTime()) / 60000) : "N/A";
      
      return {
        hostname: machine.hostname,
        version: machine.agent_version || "Antiga",
        last_pulse: machine.last_pulse,
        minutes_ago: diffMin,
        status: diffMin !== "N/A" && (diffMin as number) <= 15 ? "ONLINE" : "OFFLINE"
      };
    });

    return NextResponse.json({
      total_fleet: machines.length,
      online_count: audit.filter((entry: { status: "ONLINE" | "OFFLINE" }) => entry.status === "ONLINE").length,
      audit_report: audit,
      server_time: now.toISOString(),
      env_status: {
        url: !!process.env.NEXT_PUBLIC_SUPABASE_URL,
        key: !!process.env.SUPABASE_SERVICE_ROLE_KEY,
        secret: !!process.env.AGENT_SHARED_SECRET
      }
    });
  } catch (err: any) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
