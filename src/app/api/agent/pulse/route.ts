import { POST as telemetryPOST } from "../../telemetry/route";

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

// Alias para garantir recepção total da frota
export async function POST(request: Request) {
  return telemetryPOST(request);
}
