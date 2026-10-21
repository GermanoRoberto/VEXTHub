import { NextResponse } from "next/server";
import { isDevPortalEnabled } from "@/utils/dev/dev-portal";
import { buildDevTelemetryData } from "@/utils/dev/telemetry-fixtures";

export const dynamic = "force-dynamic";

export async function GET() {
  if (!isDevPortalEnabled()) {
    return NextResponse.json({ error: "Development portal disabled." }, { status: 404 });
  }

  return NextResponse.json(buildDevTelemetryData(), {
    headers: {
      "Cache-Control": "no-store, max-age=0",
    },
  });
}
