import { NextResponse } from "next/server";
const AGENT_SOURCE_CODE = `
# VextHub Agent Code Mock
$AgentVersion = "4.0.0"
`;
import { getAgentSecret, verifyAgentRequest } from "@/utils/security/agent-auth";

function renderAgentSource() {
  const agentSecret = getAgentSecret();
  if (!agentSecret) throw new Error("AGENT_SHARED_SECRET is not configured securely.");

  return AGENT_SOURCE_CODE.replaceAll("__AGENT_SHARED_SECRET__", agentSecret);
}

export async function GET(request: Request) {
  const agentAuth = verifyAgentRequest(request);
  if (!agentAuth.ok) {
    return NextResponse.json({ error: agentAuth.error }, { status: agentAuth.status });
  }

  return new NextResponse(renderAgentSource(), {
    status: 200,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store, max-age=0",
    },
  });
}
