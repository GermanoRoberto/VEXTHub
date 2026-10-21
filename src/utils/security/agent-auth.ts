import { createHash, randomBytes, timingSafeEqual } from "crypto";

const MIN_AGENT_SECRET_LENGTH = 24;

export type AgentAuthResult =
  | { ok: true; secret: string }
  | { ok: false; status: number; error: string };

export function getAgentSecret(): string | null {
  const secret = process.env.AGENT_SHARED_SECRET?.trim();
  if (!secret || secret.length < MIN_AGENT_SECRET_LENGTH) {
    return null;
  }
  return secret;
}

/**
 * Constant-time string equality comparison using SHA-256 pre-hashing.
 * Guarantees fixed 32-byte buffers to avoid RangeError and length-leakage side channels.
 */
export function timingSafeEqualSha256(
  a: string | null | undefined,
  b: string | null | undefined
): boolean {
  if (typeof a !== "string" || typeof b !== "string" || a.length === 0 || b.length === 0) {
    const dummy = Buffer.alloc(32, 0);
    const h = createHash("sha256").update(typeof a === "string" ? a : "", "utf8").digest();
    timingSafeEqual(h, dummy);
    return false;
  }

  const hashA = createHash("sha256").update(a, "utf8").digest();
  const hashB = createHash("sha256").update(b, "utf8").digest();

  return timingSafeEqual(hashA, hashB);
}

export function constantTimeEqual(left: string, right: string): boolean {
  return timingSafeEqualSha256(left, right);
}

function headerValue(request: Request, name: string) {
  return request.headers.get(name)?.trim() || "";
}

export function getAgentBootstrapSecret(request: Request) {
  return (
    headerValue(request, "x-agent-secret") ||
    headerValue(request, "x-agent-key") ||
    headerValue(request, "x-vexthub-agent-key") ||
    request.headers.get("authorization")?.replace(/^Bearer\s+/i, "").trim() ||
    ""
  );
}

export function verifyAgentKey(
  presentedKey: string | null | undefined,
  expectedUnitKey?: string | null
): boolean {
  if (!presentedKey) return false;
  if (expectedUnitKey && timingSafeEqualSha256(presentedKey, expectedUnitKey)) {
    return true;
  }
  const sharedSecret = getAgentSecret();
  if (sharedSecret && timingSafeEqualSha256(presentedKey, sharedSecret)) {
    return true;
  }
  return false;
}

export function verifyAgentBootstrapSecret(
  request: Request,
  expectedUnitKey?: string | null
): AgentAuthResult {
  const headerSecret = getAgentBootstrapSecret(request);
  if (!headerSecret) {
    return { ok: false, status: 401, error: "Missing agent secret header." };
  }

  if (verifyAgentKey(headerSecret, expectedUnitKey)) {
    return { ok: true, secret: headerSecret };
  }

  const hasAnyExpected = Boolean(expectedUnitKey) || Boolean(getAgentSecret());
  if (!hasAnyExpected) {
    return {
      ok: false,
      status: 503,
      error: "Neither unit agent_key nor AGENT_SHARED_SECRET is configured.",
    };
  }

  return { ok: false, status: 401, error: "Unauthorized agent request." };
}

export function verifyAgentRequest(
  request: Request,
  expectedUnitKey?: string | null
): AgentAuthResult {
  return verifyAgentBootstrapSecret(request, expectedUnitKey);
}

export function createAgentToken() {
  return randomBytes(32).toString("base64url");
}

export function hashAgentToken(token: string) {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function getAgentToken(request: Request) {
  return headerValue(request, "x-agent-token");
}

export function verifyAgentToken(token: string, expectedHash: string) {
  if (!token || !expectedHash) return false;
  const tokenHash = hashAgentToken(token);
  return constantTimeEqual(tokenHash, expectedHash);
}
