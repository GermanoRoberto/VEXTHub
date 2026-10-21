import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json(
    {
      error: "Executable installer disabled.",
      detail: "Use the authenticated per-unit ZIP installer route. It contains the preferred C# agent plus config.json.",
    },
    { status: 410 },
  );
}
