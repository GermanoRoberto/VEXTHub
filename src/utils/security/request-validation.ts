import { NextResponse } from "next/server";

export const MAX_JSON_BODY_BYTES = 512 * 1024;

export function jsonError(error: string, status: number) {
  return NextResponse.json({ error }, { status });
}

export async function readLimitedJson(request: Request, maxBytes = MAX_JSON_BODY_BYTES) {
  const lengthHeader = request.headers.get("content-length");
  const declaredLength = lengthHeader ? Number(lengthHeader) : 0;
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    return { value: null, response: jsonError("Payload too large.", 413) };
  }

  const text = await request.text();
  if (Buffer.byteLength(text, "utf8") > maxBytes) {
    return { value: null, response: jsonError("Payload too large.", 413) };
  }

  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return { value: null, response: jsonError("Invalid JSON object.", 400) };
    }
    return { value, response: null };
  } catch {
    return { value: null, response: jsonError("Invalid JSON.", 400) };
  }
}

export function readStringField(source: Record<string, unknown>, field: string, maxLength: number) {
  const value = source[field];
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

export function readOptionalStringField(source: Record<string, unknown>, field: string, maxLength: number) {
  const value = readStringField(source, field, maxLength);
  return value || null;
}

export function allowOnlyFields(source: Record<string, unknown>, allowedFields: string[]) {
  return Object.fromEntries(
    allowedFields
      .filter((field) => Object.prototype.hasOwnProperty.call(source, field))
      .map((field) => [field, source[field]]),
  );
}
