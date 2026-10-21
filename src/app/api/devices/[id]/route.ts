import { supabaseAdmin } from "@/utils/supabase/admin";
import { NextResponse } from "next/server";
import { logAuditEvent, requireTenantAccess } from "@/utils/security/api-auth";

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  // Em Next.js 15/16, params deve ser aguardado (await)
  const resolvedParams = await params;
  const { id } = resolvedParams;

  if (!id) {
    return NextResponse.json({ error: "ID do dispositivo e obrigatorio." }, { status: 400 });
  }

  const auth = await requireTenantAccess(request, "admin");
  if (auth.response) return auth.response;

  try {
    console.log(`DELETE /api/devices/${id} - Attempting to remove device for tenant ${auth.tenantId}`);

    // EXCLUSIVO SUPABASE (SQLite removido conforme solicitado)
    // Deletamos os pulsos primeiro para evitar erros de FK (se não houver cascade)
    const { error: pulseError } = await supabaseAdmin
      .from("pulses")
      .delete()
      .eq("tenant_id", auth.tenantId)
      .eq("machine_id", id);
      
    if (pulseError) {
      console.warn("Could not delete pulses from Supabase:", pulseError);
    }

    const { error } = await supabaseAdmin
      .from("machines")
      .delete()
      .eq("tenant_id", auth.tenantId)
      .eq("id", id);

    if (error) {
      console.error("Supabase device deletion error:", error);
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    await logAuditEvent({
      tenantId: auth.tenantId,
      actorUserId: auth.user?.id,
      action: "DEVICE_DELETE",
      targetType: "machines",
      targetId: id,
      details: { machine_id: id },
    });

    return NextResponse.json({ success: true, message: "Dispositivo excluido com sucesso." });
  } catch (err) {
    console.error("Device deletion unexpected error:", err);
    return NextResponse.json({ error: "Erro interno no servidor." }, { status: 500 });
  }
}
