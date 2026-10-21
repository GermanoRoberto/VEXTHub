import { POST as telemetryPOST } from "../../telemetry/route";

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

// Alias para o endpoint legado que os agentes usam
export async function POST(request: Request) {
  return telemetryPOST(request);
}
