import { NextResponse } from "next/server";
import { requireTenantAccess } from "@/utils/security/api-auth";
import { supabaseAdmin } from "@/utils/supabase/admin";
import { getSimulationState, isSimulationFallbackEnabled } from "@/utils/simulation/reader";

export const dynamic = "force-dynamic";

function enrichSimulationMachine(machine: any, units: any[] = []) {
  const seq = Number(String(machine.id || "").split("-").at(-1)) || 1;
  const unitId = machine.unit || "UN-00";
  
  // Encontrar o nome amigável da unidade
  const unitData = units.find(u => u.id === unitId);
  const unitName = unitData ? unitData.name : unitId;

  const telemetry = machine.telemetry || {};
  const diskUsedPct = Number(telemetry.disk || 50);
  const diskTotal = seq % 3 === 0 ? 256 : 512;
  const diskFree = Math.max(12, Math.round((diskTotal * (100 - diskUsedPct)) / 100));
  const inventory = { ...(machine.inventory_data || {}) };
  const systemDetails = { ...(inventory.system_details || {}) };

  inventory.system_details = {
    active_user: systemDetails.active_user || `${String(unitId).toLowerCase()}\\operador${String(seq).padStart(3, "0")}`,
    local_ip: systemDetails.local_ip || machine.ip || "0.0.0.0",
    disk_total_gb: systemDetails.disk_total_gb || diskTotal,
    disk_free_gb: systemDetails.disk_free_gb || diskFree,
    domain: systemDetails.domain || `VEXT-${unitId}`,
  };

  return {
    ...machine,
    unit: unitName, // Sobrescrevemos ou adicionamos para o frontend
    unit_id: unitId,
    serial_number: machine.serial_number || `VEXT-${String(unitId).replace("-", "")}-${String(seq).padStart(5, "0")}`,
    inventory_data: inventory,
  };
}

export async function GET(request: Request) {
  const auth = await requireTenantAccess(request, "viewer");
  if (auth.response) return auth.response;

  const { searchParams } = new URL(request.url);
  const unit = searchParams.get("unit");

  try {
    let query = supabaseAdmin
      .from("machines")
      .select("*")
      .eq("tenant_id", auth.tenantId)
      .order("last_pulse", { ascending: false })
      .limit(500);

    if (unit) {
      query = query.eq("unit", unit);
    }

    const fetchPromise = query;
    const timeoutPromise = new Promise<null>((resolve) => 
      setTimeout(() => resolve(null), isSimulationFallbackEnabled() ? 2000 : 30000)
    );

    const result = await Promise.race([fetchPromise as any, timeoutPromise]);

    if (!result) {
       throw new Error("Supabase timeout");
    }

    const { data, error } = result as any;
    if (error) throw error;

    return NextResponse.json(data || []);
  } catch (error: any) {
    if (!isSimulationFallbackEnabled()) {
      console.error("GET /api/inventory/machines error:", error.message);
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    console.warn("Inventory machines - Supabase unavailable, using local simulation:", error.message);
    const sim = getSimulationState();
    if (!sim) return NextResponse.json([]);

    const units = sim.units || [];
    const targetUnit = units.find(u => u.name === unit || u.id === unit);
    const targetId = targetUnit ? targetUnit.id : unit;

    const machines = unit
      ? sim.machines.filter((machine) => machine.unit === targetId || machine.unit === unit)
      : sim.machines;

    return NextResponse.json(machines.slice(0, 500).map(m => enrichSimulationMachine(m, units)));
  }
}
