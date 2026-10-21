import governanceFrameworksData from "@/data/governance-frameworks.json";
import type { TelemetryFinding } from "@/utils/security/telemetry-detection";

type GovernanceSource = {
  label: string;
  url: string;
  usage: string;
};

type GovernanceFramework = {
  id: string;
  name: string;
  category: string;
  primary_focus: string[];
  finding_categories: TelemetryFinding["category"][];
  evidence_signals: string[];
  audit_evidence: string[];
  prompt_guidance: string;
};

type GovernanceDataset = {
  source: GovernanceSource;
  frameworks: GovernanceFramework[];
};

export type GovernanceContextFramework = {
  id: string;
  name: string;
  category: string;
  primary_focus: string[];
  audit_evidence: string[];
  prompt_guidance: string;
};

export type GovernanceContext = {
  source: GovernanceSource;
  selected_frameworks: GovernanceContextFramework[];
  evidence_questions: string[];
  usage_note: string;
};

const dataset = governanceFrameworksData as GovernanceDataset;

const DEFAULT_FRAMEWORK_IDS = new Set(["nist-csf", "iso-27001", "cis-controls", "cobit-2019", "itil-4", "itam"]);

const QUESTION_BY_EVIDENCE: Record<string, string> = {
  access_review: "O acesso ou ferramenta remota tem dono, aprovacao e justificativa atual?",
  asset_inventory: "O ativo afetado esta inventariado, com unidade e responsavel identificados?",
  change_record: "Existe mudanca aprovada relacionada a instalacao, remocao ou configuracao observada?",
  closure_validation: "Ha evidencia de reteste ou validacao de encerramento depois da acao corretiva?",
  incident_record: "O evento ja foi registrado como incidente, com impacto, horario e responsavel?",
  incident_timeline: "A linha do tempo do evento cobre deteccao, triagem, acao e verificacao?",
  log_review: "Os logs confirmam a origem, usuario, processo e persistencia do comportamento?",
  personal_data_exposure: "Ha evidencia de dados pessoais expostos ou acessados indevidamente?",
  policy_exception: "A excecao de politica esta documentada, aprovada e com prazo de revisao?",
  response_actions: "As acoes defensivas tomadas estao registradas e sao reversiveis/auditaveis?",
  risk_register: "O risco foi aceito, tratado, transferido ou mitigado por responsavel formal?",
  secure_configuration: "A configuracao do endpoint ou servico esta alinhada ao baseline aprovado?",
  security_alerts: "Os alertas foram correlacionados com inventario, processo, rede e usuario?",
  software_inventory: "O software detectado consta no inventario aprovado e no controle de licencas?",
  vulnerability_scan: "Existe varredura ou evidencia tecnica que confirme a exposicao observada?"
};

function unique<T>(values: T[]) {
  return Array.from(new Set(values));
}

function normalizeText(value: string) {
  return value.toLowerCase().normalize("NFD").replace(/\p{Diacritic}/gu, "");
}

function scoreFramework(framework: GovernanceFramework, findings: TelemetryFinding[], queryText?: string) {
  let score = DEFAULT_FRAMEWORK_IDS.has(framework.id) ? 2 : 0;
  const normalizedQuery = normalizeText(queryText || "");

  for (const finding of findings) {
    if (framework.finding_categories.includes(finding.category)) score += 4;

    const findingText = normalizeText([
      finding.title,
      finding.category,
      finding.evidence,
      finding.recommended_action,
      finding.mitre || "",
      finding.software_name || "",
    ].join(" "));

    for (const signal of framework.evidence_signals) {
      if (findingText.includes(normalizeText(signal.replaceAll("_", " ")))) score += 1;
    }
  }

  if (normalizedQuery) {
    const frameworkText = normalizeText([
      framework.id,
      framework.name,
      framework.category,
      framework.primary_focus.join(" "),
      framework.prompt_guidance,
    ].join(" "));
    for (const token of normalizedQuery.split(/\s+/).filter((item) => item.length > 2)) {
      if (frameworkText.includes(token)) score += 2;
    }
  }

  return score;
}

export function buildGovernanceContext(options: { findings?: TelemetryFinding[]; queryText?: string; limit?: number } = {}): GovernanceContext {
  const findings = options.findings || [];
  const limit = Math.max(1, Math.min(options.limit || 6, 10));
  const selected = dataset.frameworks
    .map((framework) => ({ framework, score: scoreFramework(framework, findings, options.queryText) }))
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score || a.framework.name.localeCompare(b.framework.name))
    .slice(0, limit)
    .map(({ framework }) => ({
      id: framework.id,
      name: framework.name,
      category: framework.category,
      primary_focus: framework.primary_focus.slice(0, 5),
      audit_evidence: framework.audit_evidence.slice(0, 5),
      prompt_guidance: framework.prompt_guidance,
    }));

  const evidenceSignals = unique(
    selected.flatMap((framework) => {
      const source = dataset.frameworks.find((item) => item.id === framework.id);
      return source?.evidence_signals || [];
    }),
  );

  return {
    source: dataset.source,
    selected_frameworks: selected,
    evidence_questions: evidenceSignals.map((signal) => QUESTION_BY_EVIDENCE[signal]).filter(Boolean).slice(0, 8),
    usage_note:
      "Use this governance context to map telemetry to controls, audit evidence, and management actions. Do not claim certification or compliance unless supplied evidence proves it.",
  };
}

export function formatGovernanceContextForPrompt(context: GovernanceContext) {
  return [
    `Fonte de referencia: ${context.source.label} (${context.source.url}).`,
    context.usage_note,
    "Frameworks relevantes:",
    ...context.selected_frameworks.map((framework) => {
      return `- ${framework.name}: foco=${framework.primary_focus.join(", ")}; evidencias=${framework.audit_evidence.join(", ")}; uso=${framework.prompt_guidance}`;
    }),
    "Perguntas de evidencia:",
    ...context.evidence_questions.map((question) => `- ${question}`),
  ].join("\n");
}
