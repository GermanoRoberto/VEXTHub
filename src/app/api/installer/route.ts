import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json(
    {
      error: "Generic installer endpoint disabled.",
      detail: "Use the authenticated per-unit ZIP installer route.",
    },
    { status: 410 },
  );
}
