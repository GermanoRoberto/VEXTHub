import { NextResponse } from "next/server";
import { requireTenantAccess, isLocalAuthFallbackAllowed } from "@/utils/security/api-auth";
import { supabaseAdmin } from "@/utils/supabase/admin";
import { redis } from "@/utils/redis";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "viewer");
    if (auth.response) return auth.response;

    const isLocal = isLocalAuthFallbackAllowed();
    const authMode = isLocal ? "local_mode" : "supabase_auth";
    const authDescription = isLocal
      ? "Modo Local (Standalone / Fallback Dev)"
      : "Autenticação Supabase em Produção";

    // 1. Probing Supabase PostgreSQL
    let dbStatus: "connected" | "simulation_mock" | "degraded" | "error" = "connected";
    let dbLatencyMs = 0;
    let dbDetails = "";
    const tDb = performance.now();
    try {
      if (
        process.env.NEXT_PUBLIC_SIMULATION_MODE === "true" ||
        !process.env.NEXT_PUBLIC_SUPABASE_URL ||
        !process.env.SUPABASE_SERVICE_ROLE_KEY
      ) {
        dbStatus = "simulation_mock";
        dbDetails = "Chaves do Supabase não configuradas (Operando em Modo Simulação Local)";
      } else {
        const { error, count } = await supabaseAdmin
          .from("machines")
          .select("id", { count: "exact", head: true });
        dbLatencyMs = Math.round(performance.now() - tDb);
        if (error) {
          dbStatus = "degraded";
          dbDetails = `Falha na consulta: ${error.message}`;
        } else {
          dbStatus = "connected";
          dbDetails = `Banco relacional ativo (${count ?? 0} endpoints monitorados)`;
        }
      }
    } catch (err: unknown) {
      dbLatencyMs = Math.round(performance.now() - tDb);
      dbStatus = "error";
      dbDetails = err instanceof Error ? err.message : String(err);
    }

    // 2. Probing FastAPI Tactical Engine
    const fastApiBase = process.env.FASTAPI_URL || process.env.TACTICAL_API_URL || "http://localhost:8000";
    let fastApiStatus: "online" | "offline" | "degraded" = "offline";
    let fastApiLatencyMs: number | null = null;
    let fastApiDetails = "";
    let fastApiChecks: Record<string, string> | null = null;
    const tFastApi = performance.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1500);
      const res = await fetch(`${fastApiBase}/health`, {
        signal: controller.signal,
        cache: "no-store",
      });
      clearTimeout(timeoutId);
      fastApiLatencyMs = Math.round(performance.now() - tFastApi);
      if (res.ok) {
        const body = (await res.json()) as { status: string; checks?: Record<string, string> };
        fastApiStatus = body.status === "ok" ? "online" : "degraded";
        fastApiChecks = body.checks || null;
        fastApiDetails = `Motor Tático ativo e responsivo (${fastApiBase})`;
      } else {
        fastApiStatus = "degraded";
        fastApiDetails = `HTTP ${res.status}: ${res.statusText}`;
      }
    } catch {
      fastApiStatus = "offline";
      fastApiDetails = `Motor Tático indisponível ou offline (${fastApiBase})`;
    }

    // 3. Probing Redis Queue
    let redisStatus: "connected" | "fallback_direct" = "connected";
    let redisLatencyMs: number | null = null;
    let redisDetails = "";
    const tRedis = performance.now();
    try {
      if (typeof redis.on === "function" && redis.listenerCount("error") === 0) {
        redis.on("error", () => {});
      }
      let timeoutId: NodeJS.Timeout | null = null;
      const timeoutPromise = new Promise<string>((_, reject) => {
        timeoutId = setTimeout(() => reject(new Error("Timeout")), 1000);
      });
      const pingPromise = redis.ping();
      const pong = await Promise.race([pingPromise, timeoutPromise]);
      if (timeoutId) clearTimeout(timeoutId);

      redisLatencyMs = Math.round(performance.now() - tRedis);
      if (pong === "PONG") {
        redisStatus = "connected";
        redisDetails = "Fila de jobs Redis ativa e responsiva";
      } else {
        redisStatus = "fallback_direct";
        redisDetails = "Modo direto ativo (resposta atípica do Redis)";
      }
    } catch {
      redisStatus = "fallback_direct";
      redisDetails = "Fila Redis inativa — Processamento direto ativado";
    }

    // 4. Probing AI Triage Engines
    const groqKey =
      process.env.VEXTHUB_GROQ_API_KEY?.trim() ||
      process.env.GROQ_API_KEY?.trim() ||
      process.env.VEXTHUB_AI_API_KEY?.trim();
    const geminiKey =
      process.env.VEXTHUB_GEMINI_API_KEY?.trim() ||
      process.env.GEMINI_API_KEY?.trim() ||
      process.env.VEXTHUB_AI_API_KEY?.trim();
    const aiEnabled = process.env.VEXTHUB_AI_ENABLED === "true";
    const activeProvider = process.env.VEXTHUB_AI_PROVIDER || "groq";

    let aiStatusState: "ready" | "partially_configured" | "disabled" | "missing_keys" = "ready";
    if (!aiEnabled) {
      aiStatusState = "disabled";
    } else if (groqKey && geminiKey) {
      aiStatusState = "ready";
    } else if (groqKey || geminiKey) {
      aiStatusState = "partially_configured";
    } else {
      aiStatusState = "missing_keys";
    }

    const aiStatus = {
      enabled: aiEnabled,
      active_provider: activeProvider,
      status: aiStatusState,
      providers: {
        groq: {
          configured: Boolean(groqKey),
          model: process.env.VEXTHUB_AI_MODEL || process.env.GROQ_MODEL || "llama-3.3-70b-versatile",
        },
        gemini: {
          configured: Boolean(geminiKey),
          model: process.env.GEMINI_MODEL || "gemini-2.0-flash",
        },
      },
    };

    const overallStatus: "healthy" | "degraded" | "critical" =
      dbStatus === "connected" && fastApiStatus === "online" && redisStatus === "connected"
        ? "healthy"
        : dbStatus === "error"
        ? "critical"
        : "degraded";

    return NextResponse.json(
      {
        timestamp: new Date().toISOString(),
        overall_status: overallStatus,
        auth: {
          mode: authMode,
          description: authDescription,
          tenant_id: auth.tenantId,
          user_email: auth.user?.email || "anonymous",
          role: auth.role,
        },
        services: {
          database: {
            name: "Supabase PostgreSQL",
            status: dbStatus,
            latency_ms: dbLatencyMs,
            details: dbDetails,
          },
          fastapi: {
            name: "Motor Tático FastAPI",
            status: fastApiStatus,
            latency_ms: fastApiLatencyMs,
            details: fastApiDetails,
            checks: fastApiChecks,
          },
          redis: {
            name: "Fila Assíncrona Redis",
            status: redisStatus,
            latency_ms: redisLatencyMs,
            details: redisDetails,
          },
          ai_triage: {
            name: "Motores de IA (Triagem Defensiva)",
            ...aiStatus,
          },
        },
      },
      {
        headers: { "Cache-Control": "no-store, max-age=0" },
      }
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
