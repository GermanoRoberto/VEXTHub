import { POST as telemetryPOST } from "../telemetry/route";

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

// Alias direto para telemetria
export async function POST(request: Request) {
  return telemetryPOST(request);
}
