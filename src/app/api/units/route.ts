import { supabaseAdmin } from "@/utils/supabase/admin";
import { NextResponse } from "next/server";
import { logAuditEvent, requireTenantAccess } from "@/utils/security/api-auth";
import { readLimitedJson, readStringField } from "@/utils/security/request-validation";
import { BRAZIL_STATES_COORDINATES } from "@/utils/network/geocoding";
import { getSimulationState, isSimulationFallbackEnabled, saveSimulationState } from "@/utils/simulation/reader";

export async function GET(request: Request) {
  const auth = await requireTenantAccess(request, "viewer");
  if (auth.response) return auth.response;

  // 1. Prioridade: Estado da Simulação Local
  if (isSimulationFallbackEnabled()) {
    try {
    const sim = getSimulationState();
    if (sim && sim.units) {
      return NextResponse.json(sim.units.map(u => ({
        id: u.id,
        name: u.name,
        city: u.city || u.location?.split(',')[0].trim(),
        state: u.state || u.location?.split(',')[1].trim(),
        latitude: u.lat,
        longitude: u.lon,
        agent_key: u.agent_key || `v_key_sim_${u.id}`,
        created_at: new Date().toISOString(),
        auto_allow_compliance: true,
        network_assets: u.network_assets || []
      })));
    }
    } catch (simError) {
      console.warn("Units API - Local simulation state failed, falling back to DB:", simError);
    }
  }

  // 2. Fallback: Supabase (Se não houver simulação ou falhar)
  try {
    const { data, error } = await supabaseAdmin
      .from("units")
      .select("*")
      .eq("tenant_id", auth.tenantId)
      .order("name");

    if (error) {
      console.warn("Units API - Supabase error:", error);
      return NextResponse.json([]);
    }
    return NextResponse.json(data || []);
  } catch {
    console.warn("Units API - Connection failed.");
    return NextResponse.json([]);
  }
}


export async function POST(request: Request) {
  const auth = await requireTenantAccess(request, "admin");
  if (auth.response) return auth.response;

  try {
    const parsed = await readLimitedJson(request, 32 * 1024);
    if (parsed.response) return parsed.response;

    const body = parsed.value as Record<string, unknown>;
    
    const name = readStringField(body, "name", 120);
    const description = readStringField(body, "description", 500) || null;
    const city = readStringField(body, "city", 100);
    const state = readStringField(body, "state", 2)?.toUpperCase();
    let latitude = typeof body.latitude === 'number' ? body.latitude : null;
    let longitude = typeof body.longitude === 'number' ? body.longitude : null;
    const auto_allow_compliance = !!body?.auto_allow_compliance;

    if (!name) {
      return NextResponse.json({ error: "Nome da unidade e obrigatorio." }, { status: 400 });
    }

    // Generate Agent Key
    const agent_key = `v_key_${crypto.randomUUID().replace(/-/g, '')}`;

    // Auto-geocode based on state if coordinates are missing
    if (state && BRAZIL_STATES_COORDINATES[state]) {
      if (latitude === null) latitude = BRAZIL_STATES_COORDINATES[state].lat;
      if (longitude === null) longitude = BRAZIL_STATES_COORDINATES[state].lon;
    }

    try {
      const { data: existing, error: existingError } = await supabaseAdmin
        .from("units")
        .select("*")
        .eq("tenant_id", auth.tenantId)
        .eq("name", name)
        .maybeSingle();

      if (existingError) throw existingError;

      if (existing) {
        return NextResponse.json(existing, { status: 200 });
      }

      const { data, error } = await supabaseAdmin
        .from("units")
        .insert([{ 
          tenant_id: auth.tenantId, 
          name, 
          description, 
          city, 
          state, 
          latitude, 
          longitude, 
          agent_key,
          auto_allow_compliance 
        }])
        .select()
        .single();

      if (error) throw error;

      await logAuditEvent({
        tenantId: auth.tenantId,
        actorUserId: auth.user?.id,
        action: "UNIT_CREATE",
        targetType: "units",
        targetId: data?.id,
        details: { name, city, state },
      });

      return NextResponse.json(data, { status: 201 });
    } catch (dbError) {
      if (!isSimulationFallbackEnabled()) throw dbError;

      console.warn("POST /api/units - Supabase error, falling back to local simulation:", dbError);
      
      const sim = getSimulationState();
      if (!sim) {
        return NextResponse.json({ error: "Simulacao nao carregada e Supabase indisponivel." }, { status: 500 });
      }

      const newUnit = {
        id: `UN-LOCAL-${Date.now()}`,
        name,
        city,
        state,
        location: `${city}, ${state}`,
        lat: latitude || 0,
        lon: longitude || 0,
        agent_key,
        auto_allow_compliance,
        x: 50,
        y: 50
      };

      sim.units.push(newUnit as any);
      if (saveSimulationState(sim)) {
        return NextResponse.json({
          ...newUnit,
          latitude: newUnit.lat,
          longitude: newUnit.lon,
          created_at: new Date().toISOString()
        }, { status: 201 });
      }

      return NextResponse.json({ error: "Falha ao salvar no estado local." }, { status: 500 });
    }
  } catch (err) {
    console.error("POST /api/units - Crash in handler:", err);
    return NextResponse.json({ 
      error: "Erro inesperado no servidor (Crash).", 
      details: err instanceof Error ? err.message : String(err) 
    }, { status: 500 });
  }
}
