import fs from "fs";
import path from "path";
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const STATUS_FILE = path.join(process.cwd(), "scratch", "agent-install-simulation.json");
const PROFILE_FILE = path.join(process.cwd(), "scratch", "local-machine-profile.json");

function readJson(filePath: string) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error: any) {
    return { error: error.message };
  }
}

export async function GET() {
  const status = readJson(STATUS_FILE);
  const profile = readJson(PROFILE_FILE);

  return NextResponse.json({
    generated_at: new Date().toISOString(),
    status: status || {
      phase: "not_started",
      logs: [],
      steps: [],
      result: null,
    },
    profile_available: !!profile && !profile.error,
    profile_error: profile?.error || null,
  });
}
