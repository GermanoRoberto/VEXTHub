import { NextResponse } from "next/server";
import { requireTenantAccess } from "@/utils/security/api-auth";
import { supabaseAdmin } from "@/utils/supabase/admin";
import { isSimulationFallbackEnabled, getSimulationState } from "@/utils/simulation/reader";
import {
  evaluateFleetZeroTrustPosture,
  formatFirewallFeed,
  type ZeroTrustFeedFormat,
} from "@/utils/security/zerotrust-posture";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    // 1. Strict Tenant Access Authorization (viewer role minimum)
    const auth = await requireTenantAccess(request, "viewer");
    if (auth.response) return auth.response;

    const url = new URL(request.url);
    const rawFormat = (url.searchParams.get("format") || "json").toLowerCase();
    const rawStatus = (url.searchParams.get("status") || "quarantined").toLowerCase();

    const validFormats: ZeroTrustFeedFormat[] = ["json", "pfsense", "plain", "fortigate", "mikrotik", "iptables"];
    const format: ZeroTrustFeedFormat = validFormats.includes(rawFormat as ZeroTrustFeedFormat)
      ? (rawFormat as ZeroTrustFeedFormat)
      : "json";

    const statusFilter = ["quarantined", "restricted", "all"].includes(rawStatus)
      ? rawStatus
      : "quarantined";

    // 2. Query Machine Inventory from Supabase (or fallback to Simulation State)
    let rawMachines: unknown[] = [];
    try {
      const { data, error } = await supabaseAdmin
        .from("machines")
        .select("id, hostname, unit, last_pulse, os_name, cpu_info, ram_total, agent_version, inventory_data")
        .eq("tenant_id", auth.tenantId)
        .order("last_pulse", { ascending: false })
        .limit(500);

      if (!error && Array.isArray(data) && data.length > 0) {
        rawMachines = data;
      }
    } catch {
      // Supabase unavailable; seamlessly fall back to simulation reader
    }

    if (rawMachines.length === 0 && isSimulationFallbackEnabled()) {
      const sim = getSimulationState();
      if (sim?.machines && Array.isArray(sim.machines)) {
        rawMachines = sim.machines;
      }
    }

    // 3. Batch Zero Trust Posture & Tunnel Radar Evaluation
    const evaluation = evaluateFleetZeroTrustPosture(rawMachines);

    // 4. Filter Reports by Status
    const targetReports =
      statusFilter === "all"
        ? evaluation.reports
        : statusFilter === "restricted"
        ? evaluation.reports.filter((r) => r.verdict === "RESTRICTED" || r.verdict === "QUARANTINED")
        : evaluation.reports.filter((r) => r.verdict === "QUARANTINED");

    // 5. Plain / Firewall Format Responses
    if (format === "pfsense" || format === "plain" || format === "fortigate" || format === "mikrotik" || format === "iptables") {
      const textOutput = formatFirewallFeed(
        evaluation.quarantinedHosts,
        evaluation.blockedIps,
        format,
        auth.tenantId,
        evaluation.summary,
      );

      return new NextResponse(textOutput, {
        status: 200,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store, max-age=0",
        },
      });
    }

    // 6. JSON Feed Response
    const origin = url.origin || "http://localhost:3000";

    return NextResponse.json(
      {
        version: "1.0.0",
        feed_type: "zerotrust_quarantine_feed",
        generated_at: new Date().toISOString(),
        tenant_id: auth.tenantId,
        status_filter: statusFilter,
        summary: evaluation.summary,
        blocked_ips: evaluation.blockedIps,
        quarantined_hosts: evaluation.quarantinedHosts,
        reports: targetReports,
        tunnel_radar_findings: targetReports.flatMap((r) => r.tunnel_radar.findings),
        firewall_integrations: {
          pfsense_url_table: `${origin}/api/security/zerotrust-feed?format=pfsense`,
          fortigate_threat_feed: `${origin}/api/security/zerotrust-feed?format=fortigate`,
          mikrotik_commands: `${origin}/api/security/zerotrust-feed?format=mikrotik`,
          iptables_commands: `${origin}/api/security/zerotrust-feed?format=iptables`,
        },
      },
      {
        headers: {
          "Cache-Control": "no-store, max-age=0",
        },
      },
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
