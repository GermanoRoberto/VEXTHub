import { NextResponse } from "next/server";
import { systemLogs } from "@/utils/server-logger";
import { requireTenantAccess } from "@/utils/security/api-auth";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const auth = await requireTenantAccess(request, "admin");
  if (auth.response) return auth.response;

  return NextResponse.json({
    timestamp: new Date().toISOString(),
    logs: systemLogs.slice(0, 50)
  });
}
