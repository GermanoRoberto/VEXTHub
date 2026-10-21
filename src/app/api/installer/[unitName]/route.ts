import { NextRequest, NextResponse } from "next/server";
import JSZip from "jszip";
import { readFile } from "fs/promises";
import path from "path";
const AGENT_SOURCE_CODE = `
# VextHub Agent Code Mock
$AgentVersion = "4.0.0"
`;
import { getAgentSecret } from "@/utils/security/agent-auth";
import { requireTenantAccess } from "@/utils/security/api-auth";
import { supabaseAdmin } from "@/utils/supabase/admin";

function renderAgentSource(agentSecret: string) {
  return AGENT_SOURCE_CODE.replaceAll("__AGENT_SHARED_SECRET__", agentSecret);
}

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ unitName: string }> }
) {
  try {
    const auth = await requireTenantAccess(request, "admin");
    if (auth.response) return auth.response;

    const { unitName: rawUnitName } = await context.params;
    const unitName = decodeURIComponent(rawUnitName).trim() || "Sem Unidade";

    const configuredServerUrl = process.env.APP_BASE_URL?.trim();
    if (!configuredServerUrl) {
      return NextResponse.json(
        { error: "APP_BASE_URL must be configured before generating installers." },
        { status: 503 },
      );
    }
    const serverUrl = configuredServerUrl.replace(/\/+$/, "");

    let effectiveAgentKey: string | null = null;
    if (auth.tenantId && auth.tenantId !== "00000000-0000-0000-0000-000000000000") {
      try {
        const { data: unitRecord } = await supabaseAdmin
          .from("units")
          .select("id, agent_key")
          .eq("tenant_id", auth.tenantId)
          .eq("name", unitName)
          .maybeSingle();

        if (unitRecord?.agent_key?.trim()) {
          effectiveAgentKey = unitRecord.agent_key.trim();
        }
      } catch (unitErr) {
        console.warn("Could not query unit agent_key from database:", unitErr);
      }
    }

    if (!effectiveAgentKey) {
      effectiveAgentKey = getAgentSecret();
    }

    if (!effectiveAgentKey) {
      return NextResponse.json(
        { error: "Nenhuma chave de agente configurada para a unidade ou ambiente (configure units.agent_key ou AGENT_SHARED_SECRET)." },
        { status: 503 },
      );
    }

    const installerDir = path.join(process.cwd(), "public", "installer");
    const agentExePath = path.join(process.cwd(), "src", "installer", "VextHubAgent.exe");
    const agentExeAltPath = path.join(process.cwd(), "src", "installer", "VextHub_Agent.exe");
    const [installScript, launcherBat, uninstallScript, agentExe] = await Promise.all([
      readFile(path.join(installerDir, "install.ps1"), "utf8"),
      readFile(path.join(installerDir, "instalar.bat"), "utf8"),
      readFile(path.join(installerDir, "uninstall.ps1"), "utf8"),
      readFile(agentExePath).catch(() => readFile(agentExeAltPath)).catch(() => null),
    ]);

    const zip = new JSZip();

    const configData = {
      unit: unitName,
      tenant_id: auth.tenantId,
      server_url: serverUrl,
      agent_key: effectiveAgentKey,
      interval_minutes: 10,
    };

    if (agentExe) {
      zip.file("VextHubAgent.exe", agentExe);
      zip.file(
        "LEIA-ME.txt",
        [
          "VextHub Endpoint Agent",
          "",
          "Caminho recomendado: execute VextHubAgent.exe.",
          "O agente C# le este config.json, instala no perfil local do usuario e salva token proprio apos o primeiro envio.",
          "",
          "Fallback legado: os scripts PowerShell ficam em legacy-powershell/.",
        ].join("\r\n"),
      );
    }

    zip.file("config.json", JSON.stringify(configData, null, 2));
    zip.file("legacy-powershell/agent.ps1", renderAgentSource(effectiveAgentKey));
    zip.file("legacy-powershell/install.ps1", installScript);
    zip.file("legacy-powershell/instalar.bat", launcherBat);
    zip.file("legacy-powershell/uninstall.ps1", uninstallScript);

    const zipBuffer = await zip.generateAsync({ type: "uint8array" });
    const zipArrayBuffer = zipBuffer.buffer.slice(
      zipBuffer.byteOffset,
      zipBuffer.byteOffset + zipBuffer.byteLength
    ) as ArrayBuffer;
    const zipBlob = new Blob([zipArrayBuffer], { type: "application/zip" });
    const safeUnitName = unitName.replace(/[^a-z0-9_-]+/gi, "_").slice(0, 80) || "unit";
    const fileName = `Agent_${safeUnitName}.zip`;

    return new NextResponse(zipBlob, {
      status: 200,
      headers: {
        "Content-Type": "application/zip",
        "Content-Disposition": `attachment; filename="${fileName}"`,
        "Cache-Control": "no-store, max-age=0",
      },
    });
  } catch (err: any) {
    console.error("Installer generation error:", err);
    return NextResponse.json({ error: "Erro interno ao gerar instalador" }, { status: 500 });
  }
}
