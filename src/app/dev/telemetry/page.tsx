import { notFound } from "next/navigation";
import { isDevPortalEnabled } from "@/utils/dev/dev-portal";
import { DevTelemetryClient } from "./telemetry-client";

export const dynamic = "force-dynamic";

export default function DevTelemetryPage() {
  if (!isDevPortalEnabled()) {
    notFound();
  }

  return <DevTelemetryClient />;
}
