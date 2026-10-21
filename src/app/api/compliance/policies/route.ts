import { supabaseAdmin } from "@/utils/supabase/admin";
import { NextResponse } from "next/server";
import { requireTenantAccess } from "@/utils/security/api-auth";
import { readLimitedJson, readOptionalStringField, readStringField } from "@/utils/security/request-validation";
import { isSimulationFallbackEnabled, getSimulationState, saveSimulationState } from "@/utils/simulation/reader";

export async function GET(request: Request) {
  const softwareData: Record<string, { name: string, status: string, units: string[], overrides: any[] }> = {};
  
  try {
    const auth = await requireTenantAccess(request, "viewer");
    if (auth.response) return auth.response;

    // 1. Coleta agressiva de dados com Timeout
    let machines: any[] = [];
    let globalPolicies: any[] = [];
    let unitOverrides: any[] = [];

    try {
      const fetchPromise = Promise.all([
        supabaseAdmin.from("machines").select("unit, inventory_data").eq("tenant_id", auth.tenantId),
        supabaseAdmin.from("software_policies").select("*").eq("tenant_id", auth.tenantId),
        supabaseAdmin.from("unit_software_policies").select("*").eq("tenant_id", auth.tenantId)
      ]);

      const timeoutPromise = new Promise<null>((resolve) => 
        setTimeout(() => resolve(null), isSimulationFallbackEnabled() ? 2000 : 30000)
      );

      const result = await Promise.race([fetchPromise, timeoutPromise]);

      if (result) {
        const [mRes, pRes, oRes] = result;
        machines = mRes.data || [];
        globalPolicies = pRes.data || [];
        unitOverrides = oRes.data || [];
      } else {
        console.warn("[POLICIES] Supabase timeout, falling back to simulation.");
      }
    } catch {
      console.warn("[POLICIES] Supabase connection failed.");
    }

    if (isSimulationFallbackEnabled()) {
      try {
        const sim = getSimulationState();
        if (sim) {
          if (!globalPolicies || globalPolicies.length === 0) {
            globalPolicies = sim.software_policies || [];
          }
          if (!unitOverrides || unitOverrides.length === 0) {
            unitOverrides = sim.unit_software_policies || [];
          }
        }
      } catch (simErr) {
        console.warn("[POLICIES] Failed to load simulation state policies:", simErr);
      }
    }

    // 2. Mapa de Políticas Existentes (para garantir que nada que foi configurado suma)
    globalPolicies?.forEach((p: any) => {
      softwareData[p.name] = { 
        name: p.name, 
        status: p.status || 'pending', 
        units: [], 
        overrides: unitOverrides?.filter((o: any) => o.software_name === p.name) || []
      };
    });

    // 3. Mineração de Inventário Vivo (Máquinas Online)
    type MachineRow = { unit?: string | null; inventory_data?: unknown };
    type InventoryPayload = {
      software?: unknown[];
      inventory?: unknown[];
    };

    if (machines && Array.isArray(machines)) {
      machines.forEach((m: MachineRow) => {
        let inventory: InventoryPayload | string | null | undefined = m.inventory_data as InventoryPayload | string | null | undefined;
        
        // Tratamento de JSON flexível
        if (typeof inventory === 'string') {
          try { inventory = JSON.parse(inventory) as InventoryPayload; } catch { inventory = {}; }
        }

        // Procura por 'software' ou 'inventory' (compatibilidade de versões)
        const softwareList = inventory?.software || inventory?.inventory || [];
        
        if (Array.isArray(softwareList)) {
          const normalizedSoftwareList = softwareList as Array<{
            name?: string;
            DisplayName?: string;
            software_name?: string;
            Title?: string;
          }>;

          normalizedSoftwareList.forEach((s) => {
            // Fallback universal de nomes
            const sName = s.name || s.DisplayName || s.software_name || s.Title;
            if (!sName || typeof sName !== 'string') return;

            if (!softwareData[sName]) {
              softwareData[sName] = { 
                name: sName, 
                status: 'pending', 
                units: [], 
                overrides: unitOverrides?.filter(o => o.software_name === sName) || []
              };
            }

            // Adiciona unidade à lista se não existir
            if (m.unit && !softwareData[sName].units.includes(m.unit)) {
              softwareData[sName].units.push(m.unit);
            }
          });
        }
      });
    }

    if ((!machines || machines.length === 0) && isSimulationFallbackEnabled()) {
      const sim = getSimulationState();
      if (sim) {
        sim.machines.forEach((m: any) => {
          const softwareList = m.inventory_data?.software || [];
          if (Array.isArray(softwareList)) {
            softwareList.forEach((s: any) => {
              const sName = s.name || s.DisplayName || s.software_name || s.Title;
              if (!sName || typeof sName !== 'string') return;
              if (!softwareData[sName]) {
                softwareData[sName] = { 
                  name: sName, 
                  status: 'pending', 
                  units: [], 
                  overrides: []
                };
              }
              if (m.unit && !softwareData[sName].units.includes(m.unit)) {
                softwareData[sName].units.push(m.unit);
              }
            });
          }
        });
      }
    }

    const finalResult = Object.values(softwareData).sort((a, b) => a.name.localeCompare(b.name));

    console.log(`[POLICIES API] Retornando ${finalResult.length} softwares processados.`);
    return NextResponse.json(finalResult);

  } catch (err: any) {
    if (isSimulationFallbackEnabled()) {
       console.warn("Policies API error (likely Supabase offline), returning what we have.");
       return NextResponse.json(Object.values(softwareData || {}).sort((a, b) => a.name.localeCompare(b.name)));
    }
    console.error("CRITICAL API ERROR (Policies):", err);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const auth = await requireTenantAccess(request, "admin");
    if (auth.response) return auth.response;

    const parsed = await readLimitedJson(request, 32 * 1024);
    if (parsed.response) return parsed.response;

    const body = parsed.value as Record<string, unknown>;
    const name = readStringField(body, "name", 160);
    const status = readStringField(body, "status", 24);
    const unit_name = readOptionalStringField(body, "unit_name", 160);

    if (!name || !status) {
      return NextResponse.json({ error: "Dados incompletos" }, { status: 400 });
    }

    if (!["allowed", "forbidden", "pending"].includes(status)) {
      return NextResponse.json({ error: "Status de politica nao suportado" }, { status: 400 });
    }

    if (unit_name) {
      try {
        const { data, error } = await supabaseAdmin
          .from("unit_software_policies")
          .upsert({ 
            tenant_id: auth.tenantId,
            software_name: name, 
            unit_name: unit_name, 
            status 
          }, { onConflict: 'tenant_id,software_name,unit_name' })
          .select()
          .single();
        if (error) throw error;
        return NextResponse.json(data);
      } catch (err) {
        if (isSimulationFallbackEnabled()) {
          console.warn("[POLICIES POST] Supabase offline, saving unit policy override to simulation.");
          const sim = getSimulationState();
          if (sim) {
            if (!sim.unit_software_policies) sim.unit_software_policies = [];
            const idx = sim.unit_software_policies.findIndex((o: any) => o.software_name === name && o.unit_name === unit_name);
            const record = { tenant_id: auth.tenantId, software_name: name, unit_name, status };
            if (idx >= 0) {
              sim.unit_software_policies[idx] = record;
            } else {
              sim.unit_software_policies.push(record);
            }
            saveSimulationState(sim);
            return NextResponse.json(record);
          }
        }
        throw err;
      }
    } else {
      try {
        const { data, error } = await supabaseAdmin
          .from("software_policies")
          .upsert({ tenant_id: auth.tenantId, name, status }, { onConflict: 'tenant_id,name' })
          .select()
          .single();
        if (error) throw error;
        return NextResponse.json(data);
      } catch (err) {
        if (isSimulationFallbackEnabled()) {
          console.warn("[POLICIES POST] Supabase offline, saving global policy to simulation.");
          const sim = getSimulationState();
          if (sim) {
            if (!sim.software_policies) sim.software_policies = [];
            const idx = sim.software_policies.findIndex((p: any) => p.name === name);
            const record = { tenant_id: auth.tenantId, name, status };
            if (idx >= 0) {
              sim.software_policies[idx] = record;
            } else {
              sim.software_policies.push(record);
            }
            saveSimulationState(sim);
            return NextResponse.json(record);
          }
        }
        throw err;
      }
    }
  } catch (err: any) {
    console.error("POST ERROR (Policies):", err);
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
