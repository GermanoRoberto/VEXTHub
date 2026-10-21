import { scanHostVulnerabilities, vulnerabilityToFinding } from "./cve-scanner";

export type TelemetrySoftware = {
  name?: string;
  version?: string;
  publisher?: string;
  install_date?: string;
};

export type TelemetryProcess = {
  name?: string;
  path?: string;
  company?: string;
  command_line?: string;
};

export type TelemetryService = {
  name?: string;
  display_name?: string;
  state?: string;
  start_mode?: string;
  path_name?: string;
};

export type TelemetryStartupEntry = {
  name?: string;
  command?: string;
  location?: string;
};

export type TelemetryListeningPort = {
  protocol?: string;
  local_address?: string;
  local_port?: number;
  exposure?: string;
};

export type TelemetryExternalConnection = {
  protocol?: string;
  local_address?: string;
  local_port?: number;
  remote_address?: string;
  remote_port?: number;
  state?: string;
};

export type DetectionSeverity = "low" | "medium" | "high" | "critical";

export type ToxicAttackPath = {
  type: "remote_breach" | "stealth_persistence" | "lateral_movement";
  title: string;
  kill_chain: string;
  stage: string;
  correlated_signals: string[];
  mitre_tactics: string[];
};

export type TelemetryFinding = {
  id: string;
  title: string;
  severity: DetectionSeverity;
  score: number;
  category:
    | "remote_access"
    | "persistence"
    | "execution"
    | "policy"
    | "malware_indicator"
    | "network_exposure"
    | "vulnerability"
    | "toxic_combination";
  confidence: number;
  evidence: string;
  software_name?: string;
  mitre?: string;
  recommended_action: string;
  cve?: string;
  cvss?: number;
  cisa_kev?: boolean;
  fixed_version?: string;
  attack_path?: ToxicAttackPath;
};

type Rule = {
  id: string;
  title: string;
  aliases: string[];
  category: TelemetryFinding["category"];
  severity: DetectionSeverity;
  score: number;
  confidence: number;
  mitre?: string;
  recommended_action: string;
};

const remoteAccessRules: Rule[] = [
  {
    id: "rat-rustdesk",
    title: "Ferramenta de Acesso Remoto RustDesk Detectada",
    aliases: ["rustdesk"],
    category: "remote_access",
    severity: "high",
    score: 70,
    confidence: 0.9,
    mitre: "T1219",
    recommended_action: "Confirmar autorização imediatamente; utilitário frequentemente abusado para controle não autorizado e golpes.",
  },
  {
    id: "rat-ultraviewer",
    title: "Ferramenta de Acesso Remoto UltraViewer Detectada",
    aliases: ["ultraviewer", "ultra viewer"],
    category: "remote_access",
    severity: "high",
    score: 75,
    confidence: 0.92,
    mitre: "T1219",
    recommended_action: "Inspecionar o endpoint e desinstalar se a instalação não tiver sido homologada pela equipe de TI.",
  },
  {
    id: "rat-supremo",
    title: "Ferramenta de Acesso Remoto Supremo Detectada",
    aliases: ["supremo"],
    category: "remote_access",
    severity: "high",
    score: 75,
    confidence: 0.92,
    mitre: "T1219",
    recommended_action: "Validar com o usuário responsável e remover através do processo padrão de TI se não autorizado.",
  },
  {
    id: "rat-ammyy",
    title: "Ferramenta de Acesso Remoto Ammyy Admin Detectada",
    aliases: ["ammyy"],
    category: "remote_access",
    severity: "critical",
    score: 90,
    confidence: 0.94,
    mitre: "T1219",
    recommended_action: "Tratar com alta urgência e isolar a máquina caso não tenha sido expressamente autorizada pela TI.",
  },
  {
    id: "rat-dwservice",
    title: "Agente de Acesso Remoto DWService Detectado",
    aliases: ["dwservice", "dwagent"],
    category: "remote_access",
    severity: "high",
    score: 78,
    confidence: 0.9,
    mitre: "T1219",
    recommended_action: "Verificar a persistência e o proprietário do processo; remover caso não seja gerenciado pela TI corporativa.",
  },
  {
    id: "rat-screenconnect",
    title: "Agente ConnectWise ScreenConnect Detectado",
    aliases: ["screenconnect", "connectwise control"],
    category: "remote_access",
    severity: "medium",
    score: 55,
    confidence: 0.84,
    mitre: "T1219",
    recommended_action: "Confirmar se o software pertence à esteira homologada de suporte remoto corporativo.",
  },
  {
    id: "rat-atera",
    title: "Agente de Gerenciamento RMM Atera Detectado",
    aliases: ["atera"],
    category: "remote_access",
    severity: "medium",
    score: 50,
    confidence: 0.82,
    mitre: "T1219",
    recommended_action: "Confirmar a titularidade do MSP/RMM; instalações não homologadas de RMM são portas comuns de intrusão.",
  },
  {
    id: "rat-splashtop",
    title: "Ferramenta de Acesso Remoto Splashtop Detectada",
    aliases: ["splashtop"],
    category: "remote_access",
    severity: "medium",
    score: 48,
    confidence: 0.82,
    mitre: "T1219",
    recommended_action: "Confirmar se o endpoint está atribuído a um grupo corporativo de suporte autorizado.",
  },
  {
    id: "rat-zoho-assist",
    title: "Ferramenta de Suporte Remoto Zoho Assist Detectada",
    aliases: ["zoho assist"],
    category: "remote_access",
    severity: "medium",
    score: 48,
    confidence: 0.8,
    mitre: "T1219",
    recommended_action: "Validar contra o inventário de softwares homologados para acesso remoto.",
  },
  {
    id: "rat-anydesk",
    title: "Ferramenta de Acesso Remoto AnyDesk Detectada",
    aliases: ["anydesk"],
    category: "remote_access",
    severity: "high",
    score: 72,
    confidence: 0.9,
    mitre: "T1219",
    recommended_action: "Validar autorização de uso; o AnyDesk é amplamente explorado para suporte não autorizado e invasões.",
  },
  {
    id: "rat-teamviewer",
    title: "Ferramenta de Acesso Remoto TeamViewer Detectada",
    aliases: ["teamviewer"],
    category: "remote_access",
    severity: "medium",
    score: 60,
    confidence: 0.85,
    mitre: "T1219",
    recommended_action: "Verificar se esta instância é gerenciada pela conta corporativa da empresa ou por uso pessoal.",
  },
  {
    id: "rat-aeroadmin",
    title: "Ferramenta de Acesso Remoto AeroAdmin Detectada",
    aliases: ["aeroadmin", "aero admin"],
    category: "remote_access",
    severity: "high",
    score: 72,
    confidence: 0.9,
    mitre: "T1219",
    recommended_action: "Investigar com urgência; ferramenta comumente associada a acessos externos não corporativos.",
  },
];

const suspiciousExecutionRules: Rule[] = [
  {
    id: "lolbin-powershell-encoded",
    title: "Execução de Comando PowerShell Codificado (Base64)",
    aliases: ["powershell -enc", "powershell.exe -enc", "encodedcommand"],
    category: "execution",
    severity: "high",
    score: 75,
    confidence: 0.86,
    mitre: "T1059.001",
    recommended_action: "Revisar a árvore de processos e o script executado; argumentos codificados são comumente usados para evasão.",
  },
  {
    id: "lolbin-mshta",
    title: "Execução de Utilitário MSHTA Detectada",
    aliases: ["mshta.exe", "mshta "],
    category: "execution",
    severity: "high",
    score: 70,
    confidence: 0.82,
    mitre: "T1218.005",
    recommended_action: "Revisar a origem do script e bloquear caso não faça parte de automações legítimas de TI.",
  },
  {
    id: "hacktool-mimikatz",
    title: "Ferramenta de Extração de Credenciais Mimikatz Detectada",
    aliases: ["mimikatz"],
    category: "execution",
    severity: "critical",
    score: 100,
    confidence: 0.98,
    mitre: "T1003.001",
    recommended_action: "ISOLAR O HOST IMEDIATAMENTE. O Mimikatz é um indicador crítico de roubo de credenciais e movimentação lateral.",
  },
  {
    id: "lolbin-regsvr32-scriptlet",
    title: "Execução de Scriptlet Regsvr32 Detectada",
    aliases: ["regsvr32", "scrobj.dll", "/i:http"],
    category: "execution",
    severity: "critical",
    score: 90,
    confidence: 0.88,
    mitre: "T1218.010",
    recommended_action: "Escalar imediatamente; padrão fortemente associado a técnicas de proxy execution para bypass de segurança.",
  },
];

type NetworkPortRule = {
  id: string;
  title: string;
  ports: number[];
  severity: DetectionSeverity;
  score: number;
  confidence: number;
  recommended_action: string;
};

const sensitiveListeningPortRules: NetworkPortRule[] = [
  {
    id: "net-rdp-listening",
    title: "Porta RDP (3389) em Escuta Detectada",
    ports: [3389],
    severity: "medium",
    score: 55,
    confidence: 0.78,
    recommended_action: "Validar se o acesso RDP é estritamente necessário; confirmar firewall do Windows, VPN e ausência de exposição direta à internet.",
  },
  {
    id: "net-vnc-listening",
    title: "Porta VNC em Escuta Detectada",
    ports: [5800, 5900, 5901],
    severity: "high",
    score: 72,
    confidence: 0.82,
    recommended_action: "Confirmar o responsável e restringir o tráfego apenas a redes internas de gerenciamento autorizadas.",
  },
  {
    id: "net-smb-listening",
    title: "Porta de Compartilhamento SMB (445/139) em Escuta",
    ports: [139, 445],
    severity: "medium",
    score: 50,
    confidence: 0.76,
    recommended_action: "Garantir que o SMB esteja limitado a redes internas confiáveis e nunca exposto via VPN sem controle ou regras de NAT.",
  },
  {
    id: "net-ssh-listening",
    title: "Servidor SSH (Porta 22) em Escuta Detectado",
    ports: [22],
    severity: "medium",
    score: 45,
    confidence: 0.74,
    recommended_action: "Validar se o serviço de SSH é esperado neste host e restrito apenas aos administradores homologados.",
  },
];

const sensitiveEstablishedPortRules: NetworkPortRule[] = [
  {
    id: "net-rdp-external-session",
    title: "Sessão RDP Externa Ativa Estabelecida",
    ports: [3389],
    severity: "high",
    score: 82,
    confidence: 0.84,
    recommended_action: "Validar imediatamente o IP remoto, usuário conectado, chamado de suporte e rota de VPN/Firewall.",
  },
  {
    id: "net-vnc-external-session",
    title: "Sessão VNC Externa Ativa Estabelecida",
    ports: [5800, 5900, 5901],
    severity: "high",
    score: 82,
    confidence: 0.84,
    recommended_action: "Validar o IP de origem remoto e encerrar a sessão imediatamente caso não haja autorização explícita.",
  },
  {
    id: "net-smb-external-session",
    title: "Sessão SMB Externa Ativa Estabelecida",
    ports: [139, 445],
    severity: "critical",
    score: 90,
    confidence: 0.86,
    recommended_action: "Tratar conexão SMB externa com máxima urgência; validar IP de origem, logs de firewall e histórico de arquivos acessados.",
  },
  {
    id: "net-ssh-external-session",
    title: "Sessão SSH Externa Ativa Estabelecida",
    ports: [22],
    severity: "high",
    score: 78,
    confidence: 0.82,
    recommended_action: "Validar atividade do administrador, IP de origem, logs de autenticação e regras de firewall aplicáveis.",
  },
];

function normalize(value: unknown) {
  return String(value || "").trim().toLowerCase();
}

function includesAlias(text: string, aliases: string[]) {
  return aliases.some((alias) => text.includes(alias));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toPort(value: unknown) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : null;
}

function isLoopbackAddress(address: unknown) {
  const text = normalize(address);
  return text === "127.0.0.1" || text === "::1" || text === "localhost";
}

function severityRank(severity: DetectionSeverity) {
  return { low: 1, medium: 2, high: 3, critical: 4 }[severity];
}

export function getTelemetryRiskLevel(score: number): DetectionSeverity {
  if (score >= 85) return "critical";
  if (score >= 65) return "high";
  if (score >= 35) return "medium";
  return "low";
}

function addFinding(findings: Map<string, TelemetryFinding>, finding: TelemetryFinding) {
  const existing = findings.get(finding.id);
  if (!existing || severityRank(finding.severity) > severityRank(existing.severity) || finding.score > existing.score) {
    findings.set(finding.id, finding);
  }
}

function softwareText(software: TelemetrySoftware) {
  if (!isRecord(software)) return "";
  return [software.name, software.publisher, software.version].map(normalize).join(" ");
}

export function analyzeTelemetryInventory(inventory: Record<string, unknown>) {
  const findings = new Map<string, TelemetryFinding>();
  const software = Array.isArray(inventory?.software)
    ? inventory.software.filter((s): s is TelemetrySoftware => isRecord(s))
    : [];
  const processes = Array.isArray(inventory?.processes)
    ? inventory.processes.filter((p): p is TelemetryProcess => isRecord(p))
    : [];
  const services = Array.isArray(inventory?.services)
    ? inventory.services.filter((s): s is TelemetryService => isRecord(s))
    : [];
  const startupEntries = Array.isArray(inventory?.startup_entries)
    ? inventory.startup_entries.filter((e): e is TelemetryStartupEntry => isRecord(e))
    : [];
  const networkConnections = isRecord(inventory?.network_connections) ? inventory.network_connections : {};
  const listeningPorts = Array.isArray(networkConnections.listening_tcp_ports)
    ? networkConnections.listening_tcp_ports.filter((l): l is TelemetryListeningPort => isRecord(l))
    : [];
  const externalConnections = Array.isArray(networkConnections.established_external_tcp)
    ? networkConnections.established_external_tcp.filter((c): c is TelemetryExternalConnection => isRecord(c))
    : [];

  // Precompile fast-path regexes for O(1) skipping
  const buildRegex = (rules: Rule[]) => {
    const aliases = rules.flatMap((r) => r.aliases);
    // Escape regex special chars
    const escaped = aliases.map((a) => a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    return new RegExp(escaped.join('|')); // Text is already lowercase via normalize()
  };

  const remoteAccessRegex = buildRegex(remoteAccessRules);
  const allExecRules = [...remoteAccessRules, ...suspiciousExecutionRules];
  const allExecRegex = buildRegex(allExecRules);

  for (const item of software) {
    const text = softwareText(item);
    
    // Fast path: skip if no aliases match
    if (!remoteAccessRegex.test(text)) continue;

    for (const rule of remoteAccessRules) {
      if (!includesAlias(text, rule.aliases)) continue;

      addFinding(findings, {
        id: `${rule.id}:${normalize(item.name)}`,
        title: rule.title,
        severity: rule.severity,
        score: rule.score,
        category: rule.category,
        confidence: rule.confidence,
        evidence: `${item.name || "Unknown software"} ${item.version || ""} ${item.publisher || ""}`.trim(),
        software_name: item.name,
        mitre: rule.mitre,
        recommended_action: rule.recommended_action,
      });
    }
  }

  // 1. Scan installed software against Curated CVE Database & CISA KEV
  const vulnReport = scanHostVulnerabilities(software);
  for (const vuln of vulnReport.vulnerabilities) {
    addFinding(findings, vulnerabilityToFinding(vuln));
  }

  const processAndStartupText = [
    ...processes.map((process) => [process.name, process.path, process.company, process.command_line].map(normalize).join(" ")),
    ...services.map((service) => [service.name, service.display_name, service.path_name, service.start_mode].map(normalize).join(" ")),
    ...startupEntries.map((entry) => [entry.name, entry.command, entry.location].map(normalize).join(" ")),
  ];

  for (const text of processAndStartupText) {
    // Fast path: skip if no aliases match
    if (!allExecRegex.test(text)) continue;

    for (const rule of allExecRules) {
      if (!includesAlias(text, rule.aliases)) continue;

      addFinding(findings, {
        id: `${rule.id}:runtime`,
        title: rule.title,
        severity: rule.severity,
        score: Math.min(100, rule.score + 8),
        category: rule.category,
        confidence: Math.min(0.98, rule.confidence + 0.04),
        evidence: text.slice(0, 240),
        mitre: rule.mitre,
        recommended_action: rule.recommended_action,
      });
    }
  }

  for (const listener of listeningPorts) {
    const port = toPort(listener.local_port);
    if (!port || isLoopbackAddress(listener.local_address)) continue;

    for (const rule of sensitiveListeningPortRules) {
      if (!rule.ports.includes(port)) continue;

      addFinding(findings, {
        id: `${rule.id}:${port}`,
        title: rule.title,
        severity: rule.severity,
        score: rule.score,
        category: "network_exposure",
        confidence: rule.confidence,
        evidence: `tcp ${listener.local_address || "0.0.0.0"}:${port} listening (${listener.exposure || "unknown exposure"})`,
        recommended_action: rule.recommended_action,
      });
    }
  }

  for (const connection of externalConnections) {
    const localPort = toPort(connection.local_port);
    if (!localPort) continue;

    for (const rule of sensitiveEstablishedPortRules) {
      if (!rule.ports.includes(localPort)) continue;

      addFinding(findings, {
        id: `${rule.id}:${localPort}:${normalize(connection.remote_address)}`,
        title: rule.title,
        severity: rule.severity,
        score: rule.score,
        category: "network_exposure",
        confidence: rule.confidence,
        evidence: `tcp ${connection.local_address || "local"}:${localPort} <- ${connection.remote_address || "external"}:${connection.remote_port || "unknown"} (${connection.state || "established"})`,
        recommended_action: rule.recommended_action,
      });
    }
  }

  // 2. Toxic Combinations & Attack Path Engine (Correlated Multi-Signal Chains)
  // Path A: Remote Breach Path
  // (Critical/KEV CVE or High-Risk RAT) + Sensitive Listening Port + Active External Connection
  const criticalOrKevVuln = Array.from(findings.values()).find(
    (f) => f.category === "vulnerability" && (f.severity === "critical" || f.cisa_kev === true)
  );
  const highRiskRat = Array.from(findings.values()).find(
    (f) => f.category === "remote_access" && (f.severity === "high" || f.severity === "critical")
  );
  const sensitiveListener = listeningPorts.find((l) => {
    const port = toPort(l.local_port);
    return port !== null && [3389, 445, 139, 5800, 5900, 5901, 22].includes(port) && !isLoopbackAddress(l.local_address);
  });
  const activeExternalConn = externalConnections.find((c) => {
    return Boolean(c.remote_address && !isLoopbackAddress(c.remote_address) && normalize(c.state) !== "closed");
  });

  if ((criticalOrKevVuln || highRiskRat) && sensitiveListener && activeExternalConn) {
    const breachVector = criticalOrKevVuln
      ? `Vulnerabilidade armada ${criticalOrKevVuln.cve || criticalOrKevVuln.title} (CVSS ${criticalOrKevVuln.cvss?.toFixed(1) || "N/A"}${criticalOrKevVuln.cisa_kev ? ", CISA KEV Ativo" : ""})`
      : `Ferramenta de controle remoto não autorizada (${highRiskRat?.title || "RAT"})`;
    const portEvidence = `Porta sensível aberta: tcp/${toPort(sensitiveListener.local_port)} (${sensitiveListener.local_address || "0.0.0.0"})`;
    const connEvidence = `Conexão externa ativa estabelecida com IP ${activeExternalConn.remote_address}:${activeExternalConn.remote_port || "N/A"}`;

    addFinding(findings, {
      id: "toxic-path:remote-breach",
      title: "Cadeia Crítica de Invasão Remota (Remote Breach Path)",
      severity: "critical",
      score: 98,
      category: "toxic_combination",
      confidence: 0.98,
      evidence: `${breachVector} combinada com ${portEvidence} e ${connEvidence}. Alto risco de comprometimento perimetral e execução remota não autorizada.`,
      mitre: "T1190 / T1219 / T1071",
      recommended_action: "Isolar o endpoint imediatamente da rede local. Encerrar a sessão externa suspeita, bloquear o IP de origem no firewall de borda e fechar a porta de escuta.",
      attack_path: {
        type: "remote_breach",
        title: "Cadeia de Invasão Remota",
        kill_chain: "Initial Access (TA0001) -> Execution (TA0002) -> Command and Control (TA0011)",
        stage: "Acesso Inicial & Canal Remoto Ativo",
        correlated_signals: [breachVector, portEvidence, connEvidence],
        mitre_tactics: ["TA0001", "TA0002", "TA0011"],
      },
    });
  }

  // Path B: Stealth Persistence Path
  // Process running from suspicious path (%TEMP%, AppData\Local\Temp, AppData\Roaming, C:\Users\Public, ProgramData)
  // + Startup/Registry Run key or auto-start service
  // + Encoded LOLBin (powershell -enc, mshta, regsvr32)
  const suspiciousPathProcess = processes.find((p) => {
    const path = normalize(p.path);
    const cmd = normalize(p.command_line);
    const target = `${path} ${cmd}`;
    return (
      target.includes("\\temp\\") ||
      target.includes("/temp/") ||
      target.includes("appdata\\local\\temp") ||
      target.includes("appdata/local/temp") ||
      target.includes("appdata\\roaming") ||
      target.includes("appdata/roaming") ||
      target.includes("users\\public") ||
      target.includes("users/public") ||
      target.includes("c:\\programdata\\") ||
      target.includes("/programdata/")
    );
  });

  const persistenceEntry =
    startupEntries.length > 0 ||
    services.some((s) => {
      const mode = normalize(s.start_mode);
      if (mode !== "auto" && mode !== "automatic") return false;
      const svcPath = normalize(s.path_name);
      const svcCachedName = normalize(s.name);
      const isSuspiciousServicePath =
        svcPath.includes("\\temp\\") ||
        svcPath.includes("/temp/") ||
        svcPath.includes("appdata") ||
        svcPath.includes("users\\public") ||
        svcPath.includes("users/public") ||
        svcPath.includes("programdata");

      if (isSuspiciousServicePath) return true;

      if (suspiciousPathProcess) {
        const procName = normalize(suspiciousPathProcess.name);
        const procPath = normalize(suspiciousPathProcess.path);
        if (procPath && svcPath && (svcPath.includes(procPath) || procPath.includes(svcPath))) {
          return true;
        }
        if (procName && (svcPath.includes(procName) || svcCachedName.includes(procName))) {
          return true;
        }
      }
      return false;
    });

  const lolbinFinding = Array.from(findings.values()).find(
    (f) => f.id.startsWith("lolbin-") || f.id.includes("encoded")
  );
  const lolbinProcess = processes.find((p) => {
    const text = `${normalize(p.name)} ${normalize(p.command_line)}`;
    return (
      text.includes("-enc") ||
      text.includes("-encodedcommand") ||
      text.includes("mshta") ||
      text.includes("regsvr32") ||
      text.includes("certutil")
    );
  });

  if (suspiciousPathProcess && persistenceEntry && (lolbinFinding || lolbinProcess)) {
    const procSignal = `Processo em diretório volátil/incomum: ${suspiciousPathProcess.name || "desconhecido"} (${suspiciousPathProcess.path || suspiciousPathProcess.command_line || "TEMP/AppData"})`;
    const persistSignal = startupEntries.length > 0
      ? `Entrada de inicialização automática persistida: ${startupEntries[0].name || startupEntries[0].location || "Startup"}`
      : `Serviço persistente em modo automático configurado`;
    const lolbinSignal = lolbinFinding
      ? `Execução de LOLBin detectada: ${lolbinFinding.title}`
      : `Comando LOLBin codificado observado: ${lolbinProcess?.command_line?.slice(0, 80) || "powershell/mshta"}`;

    addFinding(findings, {
      id: "toxic-path:stealth-persistence",
      title: "Cadeia de Persistência Furtiva & Evasão (Stealth Persistence Path)",
      severity: "critical",
      score: 95,
      category: "toxic_combination",
      confidence: 0.95,
      evidence: `${procSignal}; ${persistSignal}; ${lolbinSignal}. Assinatura clássica de implante furtivo e evasão de defesas.`,
      mitre: "T1059 / T1547 / T1036",
      recommended_action: "Terminar o processo em execução a partir de diretório volátil, remover chaves de registro ou atalhos em Inicializar e coletar o binário para análise no Malware Lab.",
      attack_path: {
        type: "stealth_persistence",
        title: "Persistência Furtiva & Evasão",
        kill_chain: "Execution (TA0002) -> Persistence (TA0003) -> Defense Evasion (TA0005)",
        stage: "Persistência no Endpoint & Execução Oculta",
        correlated_signals: [procSignal, persistSignal, lolbinSignal],
        mitre_tactics: ["TA0002", "TA0003", "TA0005"],
      },
    });
  }

  // Path C: Lateral Movement / Credential Exfiltration Path
  // Mimikatz/credential tool or LSASS memory access indicator
  // + External SMB/RDP session
  // + Statistical Anomaly (Z-score > 2.5)
  const credentialIndicator =
    findings.has("hacktool-mimikatz:runtime") ||
    processes.some((p) => {
      const text = `${normalize(p.name)} ${normalize(p.command_line)}`;
      return text.includes("mimikatz") || text.includes("sekurlsa") || text.includes("procdump") || text.includes("lsass");
    }) ||
    software.some((s) => normalize(s.name).includes("mimikatz"));

  const smbOrRdpSession = externalConnections.find((c) => {
    const lPort = toPort(c.local_port) || 0;
    const rPort = toPort(c.remote_port) || 0;
    const isSensitive = [445, 139, 3389, 22].includes(lPort) || [445, 139, 3389, 22].includes(rPort);
    return isSensitive && Boolean(c.remote_address && !isLoopbackAddress(c.remote_address));
  });

  const maxZScore =
    typeof inventory?.max_z_score === "number"
      ? inventory.max_z_score
      : typeof inventory?.z_score === "number"
      ? inventory.z_score
      : typeof inventory?.anomaly_score === "number"
      ? inventory.anomaly_score
      : 0;

  const isAnomalous =
    maxZScore >= 2.5 ||
    Boolean(inventory?.is_anomalous) ||
    Boolean(inventory?.telemetry_anomaly);

  if (credentialIndicator && smbOrRdpSession && isAnomalous) {
    const credSignal = "Indicador de ferramenta de extração de credenciais (LSASS / Mimikatz)";
    const sessionSignal = `Sessão SMB/RDP ativa conectada a endereço externo/pivô: ${smbOrRdpSession.remote_address}:${smbOrRdpSession.remote_port || "445/3389"}`;
    const anomalySignal = maxZScore >= 2.5
      ? `Anomalia estatística de comportamento confirmada (Z-Score ${maxZScore.toFixed(2)} > 2.5)`
      : `Desvio de tráfego de credenciais associado à movimentação lateral não usual`;

    addFinding(findings, {
      id: "toxic-path:lateral-credential-exfil",
      title: "Movimentação Lateral & Extração de Credenciais (Lateral Movement Path)",
      severity: "critical",
      score: 100,
      category: "toxic_combination",
      confidence: 0.99,
      evidence: `${credSignal} acompanhado de ${sessionSignal} e ${anomalySignal}. Risco iminente de comprometimento em domínio e espalhamento na rede interna.`,
      mitre: "T1003 / T1021 / T1048",
      recommended_action: "Revogar credenciais de administrador de domínio imediatamente, suspender a sessão de rede lateral e redefinir hashes Kerberos/NTLM.",
      attack_path: {
        type: "lateral_movement",
        title: "Movimentação Lateral & Credenciais",
        kill_chain: "Credential Access (TA0006) -> Lateral Movement (TA0008) -> Exfiltration (TA0010)",
        stage: "Acesso a Credenciais & Pivot Lateral",
        correlated_signals: [credSignal, sessionSignal, anomalySignal],
        mitre_tactics: ["TA0006", "TA0008", "TA0010"],
      },
    });
  }

  // Priority placement: toxic combinations at the top, then descending by score
  const result = Array.from(findings.values()).sort((left, right) => {
    const leftIsToxic = left.category === "toxic_combination";
    const rightIsToxic = right.category === "toxic_combination";
    if (leftIsToxic && !rightIsToxic) return -1;
    if (!leftIsToxic && rightIsToxic) return 1;
    return right.score - left.score;
  });

  const score = result.reduce((max, finding) => Math.max(max, finding.score), 0);

  return {
    score,
    risk_level: getTelemetryRiskLevel(score),
    findings: result,
    analyzed_at: new Date().toISOString(),
  };
}
