import type { jsPDF as JsPdfType } from 'jspdf';

// ============================================================================
// STRICT TYPES & INTERFACES (ZERO `any`)
// ============================================================================

export interface DeviceExportItem {
  id: string;
  hostname: string;
  unit: string;
  status: 'online' | 'away' | 'offline';
  ip: string;
  user: string;
  os: string;
  cpu: string;
  ram: string;
  agentVersion: string;
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical' | string;
  lastPulse: string;
}

export interface SoftwarePolicyExportItem {
  name: string;
  status: 'allowed' | 'forbidden' | 'pending';
  units: string[];
  overrides?: Array<{ unit_name: string; status: 'allowed' | 'forbidden' }>;
}

export interface ComplianceAlertExportItem {
  id: string;
  hostname: string;
  unit: string;
  software_name: string;
  message: string;
  created_at: string;
  is_resolved?: boolean;
}

export interface CveExportItem {
  cveId: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | string;
  cvssScore: number;
  cisaKev: boolean;
  softwareName: string;
  affectedHosts: number;
  remediation: string;
}

export interface ZeroTrustExportItem {
  postureScore: number;
  trustedCount: number;
  restrictedCount: number;
  quarantinedCount: number;
  tunnelsDetected: number;
}

export interface GrcComplianceExportItem {
  framework: string;
  controlCode: string;
  controlName: string;
  status: 'Conforme' | 'Alerta' | 'Não Conforme';
  coveragePercent: number;
  notes: string;
}

export interface ComplianceExportOptions {
  cveList?: CveExportItem[];
  zeroTrust?: ZeroTrustExportItem;
  grcControls?: GrcComplianceExportItem[];
}

interface MetricCardData {
  title: string;
  value: string | number;
  accent: [number, number, number];
}

// ============================================================================
// RFC-4180 DETERMINISTIC CSV EXPORT ENGINE
// ============================================================================

/**
 * Escapes a single cell value according to RFC-4180:
 * Encloses the value in double quotes if it contains commas, double quotes,
 * or newline characters, and escapes internal double quotes with double-quotes ("").
 */
export function escapeCsvCell(value: unknown): string {
  if (value === null || value === undefined) {
    return '';
  }
  const str = String(value);
  if (/[",\r\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Builds a valid RFC-4180 CSV string with CRLF row delimiters.
 */
export function generateCsv(
  headers: string[],
  rows: (string | number | boolean | null | undefined)[][]
): string {
  const headerLine = headers.map(escapeCsvCell).join(',');
  const rowLines = rows.map((row) => row.map(escapeCsvCell).join(','));
  return [headerLine, ...rowLines].join('\r\n');
}

/**
 * Triggers a browser download of a client-side Blob with automatic URL revocation.
 * Prepends the UTF-8 Byte Order Mark (\uFEFF) for Excel compatibility.
 */
export function downloadBlob(
  content: string,
  filename: string,
  mimeType = 'text/csv;charset=utf-8;'
): void {
  if (typeof window === 'undefined') return;
  const bom = '\uFEFF';
  const blob = new Blob([bom + content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', filename);
  link.style.visibility = 'hidden';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function getTimestampSlug(): string {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}`;
}

export function exportDevicesCsv(devices: DeviceExportItem[]): void {
  const headers = [
    'ID',
    'Hostname',
    'Unidade',
    'Status',
    'IP Local',
    'Usuário Ativo',
    'Sistema Operacional',
    'CPU',
    'RAM',
    'Versão Agente',
    'Score de Risco',
    'Nível de Risco',
    'Último Heartbeat',
  ];

  const rows = devices.map((d) => [
    d.id,
    d.hostname,
    d.unit,
    d.status.toUpperCase(),
    d.ip,
    d.user,
    d.os,
    d.cpu,
    d.ram,
    d.agentVersion,
    d.riskScore,
    d.riskLevel.toUpperCase(),
    d.lastPulse,
  ]);

  const csv = generateCsv(headers, rows);
  const filename = `VextHub_Inventario_Dispositivos_${getTimestampSlug()}.csv`;
  downloadBlob(csv, filename);
}

export function exportComplianceCsv(
  policies: SoftwarePolicyExportItem[],
  alerts?: ComplianceAlertExportItem[],
  options?: ComplianceExportOptions
): void {
  const emissionDate = new Date().toLocaleString('pt-BR');
  const sections: string[] = [];

  // Header comment block
  sections.push(
    `# RELATÓRIO EXECUTIVO DE COMPLIANCE & POLÍTICAS DE SOFTWARE - VEXTHUB\r\n# Data de Emissão: ${escapeCsvCell(emissionDate)}\r\n# Status do Tenant: Ativo (Produção)`
  );

  // Section 1: Policies
  sections.push('# POLÍTICAS DE HOMOLOGAÇÃO DE SOFTWARES');
  const policyHeaders = [
    'Nome do Software',
    'Status Global',
    'Unidades Aplicadas',
    'Exceções por Unidade',
  ];
  const policyRows = policies.map((p) => {
    const statusLabel =
      p.status === 'allowed'
        ? 'Homologado'
        : p.status === 'forbidden'
        ? 'Proibido'
        : 'Pendente';
    const unitsStr =
      p.units && p.units.length > 0 ? p.units.join('; ') : 'Todas as Unidades';
    const overridesStr =
      p.overrides && p.overrides.length > 0
        ? p.overrides
            .map((o) => `${o.unit_name}: ${o.status === 'allowed' ? 'Homologado' : 'Proibido'}`)
            .join(' | ')
        : 'Nenhuma exceção configurada';
    return [p.name, statusLabel, unitsStr, overridesStr];
  });
  sections.push(generateCsv(policyHeaders, policyRows));

  // Section 2: Active Alerts (if provided)
  if (alerts && alerts.length > 0) {
    sections.push('\r\n# ALERTAS E VIOLAÇÕES DE CONFORMIDADE ATIVOS');
    const alertHeaders = [
      'ID do Alerta',
      'Hostname',
      'Unidade',
      'Software Detectado',
      'Detalhes da Infração',
      'Data/Hora da Detecção',
      'Situação',
    ];
    const alertRows = alerts.map((a) => [
      a.id,
      a.hostname,
      a.unit,
      a.software_name,
      a.message,
      a.created_at,
      a.is_resolved ? 'Resolvido' : 'Pendente / Ativo',
    ]);
    sections.push(generateCsv(alertHeaders, alertRows));
  }

  // Section 3: Zero Trust Posture & Tunnel Radar (if provided)
  if (options?.zeroTrust) {
    sections.push('\r\n# POSTURA ZERO TRUST & RESILIÊNCIA DA FROTA');
    const ztHeaders = [
      'Score de Postura (0-100)',
      'Hosts Confiáveis (Trusted)',
      'Hosts Restritos (Restricted)',
      'Hosts em Quarentena (Quarantined)',
      'Túneis / Evasões Detectados',
    ];
    const ztRows = [
      [
        options.zeroTrust.postureScore,
        options.zeroTrust.trustedCount,
        options.zeroTrust.restrictedCount,
        options.zeroTrust.quarantinedCount,
        options.zeroTrust.tunnelsDetected,
      ],
    ];
    sections.push(generateCsv(ztHeaders, ztRows));
  }

  // Section 4: Vulnerabilities & CISA KEV Summary (if provided)
  if (options?.cveList && options.cveList.length > 0) {
    sections.push('\r\n# RESUMO DE VULNERABILIDADES & CISA KEV (TVM / ISO 27001 A.8.8)');
    const cveHeaders = [
      'CVE ID',
      'Software Afetado',
      'Severidade',
      'Score CVSS',
      'CISA KEV (Explorado Ativamente)',
      'Hosts Afetados',
      'Recomendação de Remediação',
    ];
    const cveRows = options.cveList.map((c) => [
      c.cveId,
      c.softwareName,
      String(c.severity).toUpperCase(),
      c.cvssScore,
      c.cisaKev ? 'SIM (CISA KEV)' : 'NÃO',
      c.affectedHosts,
      c.remediation,
    ]);
    sections.push(generateCsv(cveHeaders, cveRows));
  }

  // Section 5: GRC Compliance Controls Coverage (if provided)
  if (options?.grcControls && options.grcControls.length > 0) {
    sections.push('\r\n# MATRIZ DE CONFORMIDADE REGULATÓRIA GRC (ISO 27001, LGPD, CIS CONTROLS V8)');
    const grcHeaders = [
      'Framework',
      'Código do Controle',
      'Nome do Controle',
      'Status de Conformidade',
      'Cobertura (%)',
      'Observações Forenses',
    ];
    const grcRows = options.grcControls.map((g) => [
      g.framework,
      g.controlCode,
      g.controlName,
      g.status,
      `${g.coveragePercent}%`,
      g.notes,
    ]);
    sections.push(generateCsv(grcHeaders, grcRows));
  }

  const fullCsv = sections.join('\r\n\r\n');
  const filename = `VextHub_Relatorio_Compliance_${getTimestampSlug()}.csv`;
  downloadBlob(fullCsv, filename);
}

// ============================================================================
// EXECUTIVE VECTOR PDF EXPORT ENGINE (jsPDF A4)
// ============================================================================

function fitText(doc: JsPdfType, text: string, maxWidth: number): string {
  if (!text) return '';
  if (doc.getTextWidth(text) <= maxWidth) return text;
  let truncated = text;
  while (truncated.length > 0 && doc.getTextWidth(truncated + '…') > maxWidth) {
    truncated = truncated.slice(0, -1);
  }
  return truncated.length > 0 ? truncated + '…' : '';
}

function drawBrandHeader(
  doc: JsPdfType,
  documentTitle: string,
  emissionDate: string
): void {
  // Top purple accent stripe
  doc.setFillColor(124, 58, 237); // #7C3AED
  doc.rect(0, 0, 210, 4, 'F');

  // Brand Name
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(20);
  doc.setTextColor(124, 58, 237);
  doc.text('VEXTHUB', 14, 16);

  // Brand Subtitle
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(6.5);
  doc.setTextColor(100, 116, 139); // #64748B
  doc.text('PLATAFORMA AUTÔNOMA DE DEFESA CIBERNÉTICA & TELEMETRIA', 14, 21);

  // Document Title (Right)
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(15, 23, 42); // #0F172A
  doc.text(documentTitle, 196, 14, { align: 'right' });

  // Emission Timestamp (Right)
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(100, 116, 139);
  doc.text(`Emissão: ${emissionDate}`, 196, 19, { align: 'right' });

  // Confidential badge
  const pillText = 'CONFIDENCIAL // AUDITORIA TÁTICA';
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(6);
  const pillW = doc.getTextWidth(pillText) + 5;
  const pillX = 196 - pillW;
  const pillY = 22;
  doc.setFillColor(254, 242, 242);
  doc.setDrawColor(254, 202, 202);
  doc.setLineWidth(0.2);
  doc.roundedRect(pillX, pillY, pillW, 4, 1, 1, 'FD');
  doc.setTextColor(220, 38, 38);
  doc.text(pillText, pillX + 2.5, pillY + 2.9);

  // Divider rule
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.3);
  doc.line(14, 28, 196, 28);
}

function drawMetricCards(doc: JsPdfType, cards: MetricCardData[], y: number): void {
  const cardWidth = 42.5;
  const cardHeight = 18;
  const gap = 4;

  cards.forEach((card, i) => {
    const x = 14 + i * (cardWidth + gap);

    // Card background
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.2);
    doc.roundedRect(x, y, cardWidth, cardHeight, 1.5, 1.5, 'FD');

    // Colored top status stripe
    doc.setFillColor(card.accent[0], card.accent[1], card.accent[2]);
    doc.rect(x + 1, y, cardWidth - 2, 2, 'F');

    // Figure value
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(15, 23, 42);
    doc.text(String(card.value), x + 3.5, y + 10);

    // Label
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6);
    doc.setTextColor(100, 116, 139);
    doc.text(card.title.toUpperCase(), x + 3.5, y + 15);
  });
}

function drawContinuationHeader(
  doc: JsPdfType,
  documentTitle: string,
  emissionDate: string
): void {
  // Top purple stripe
  doc.setFillColor(124, 58, 237);
  doc.rect(0, 0, 210, 4, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(15, 23, 42);
  doc.text(`VEXTHUB — CONTINUAÇÃO: ${documentTitle.toUpperCase()}`, 14, 12);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(100, 116, 139);
  doc.text(`Emissão: ${emissionDate}`, 196, 12, { align: 'right' });

  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.2);
  doc.line(14, 15, 196, 15);
}

function finalizeFooters(doc: JsPdfType): void {
  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);

    // Divider
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.2);
    doc.line(14, 286, 196, 286);

    // Left confidential notice
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(148, 163, 184);
    doc.text(
      'VextHub Security Intelligence — Relatório Executivo Auditável // Confidencial',
      14,
      291
    );

    // Right page number
    doc.text(`Página ${p} de ${totalPages}`, 196, 291, { align: 'right' });
  }
}

export async function exportDevicesPdf(devices: DeviceExportItem[]): Promise<void> {
  const { jsPDF } = await import('jspdf');
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
    compress: true,
  });

  const emissionDate = new Date().toLocaleString('pt-BR');
  const docTitle = 'LAUDO EXECUTIVO DE INVENTÁRIO DO PARQUE';

  // 1. Brand Header
  drawBrandHeader(doc, docTitle, emissionDate);

  // 2. 4 Executive KPI Cards
  const totalCount = devices.length;
  const onlineCount = devices.filter((d) => d.status === 'online').length;
  const alertCount = devices.filter((d) => d.status !== 'online').length;
  const avgRisk =
    totalCount > 0
      ? Math.round(devices.reduce((acc, d) => acc + d.riskScore, 0) / totalCount)
      : 0;

  const kpis: MetricCardData[] = [
    { title: 'Total de Endpoints', value: totalCount, accent: [99, 102, 241] }, // Indigo
    { title: 'Endpoints Online', value: onlineCount, accent: [16, 185, 129] }, // Emerald
    { title: 'Offline / Alerta', value: alertCount, accent: [245, 158, 11] }, // Amber
    { title: 'Score Médio de Risco', value: `${avgRisk}/100`, accent: [124, 58, 237] }, // Purple
  ];

  drawMetricCards(doc, kpis, 31);

  // 3. Devices Table
  let currentY = 53;

  const drawTableHeader = (y: number) => {
    doc.setFillColor(15, 23, 42); // #0F172A
    doc.rect(14, y, 182, 6.5, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(255, 255, 255);

    doc.text('HOSTNAME', 16, y + 4.3);
    doc.text('UNIDADE', 48, y + 4.3);
    doc.text('STATUS', 74, y + 4.3);
    doc.text('IP LOCAL', 94, y + 4.3);
    doc.text('USUÁRIO ATIVO', 120, y + 4.3);
    doc.text('SISTEMA OPERACIONAL', 146, y + 4.3);
    doc.text('RISCO', 174, y + 4.3);
  };

  drawTableHeader(currentY);
  currentY += 6.5;

  const rowHeight = 6.0;

  devices.forEach((d, index) => {
    // Check pagination
    if (currentY + rowHeight > 278) {
      doc.addPage();
      drawContinuationHeader(doc, docTitle, emissionDate);
      currentY = 19;
      drawTableHeader(currentY);
      currentY += 6.5;
    }

    // Zebra striping
    if (index % 2 === 1) {
      doc.setFillColor(248, 250, 252);
      doc.rect(14, currentY, 182, rowHeight, 'F');
    }

    // Bottom border
    doc.setDrawColor(241, 245, 249);
    doc.setLineWidth(0.15);
    doc.line(14, currentY + rowHeight, 196, currentY + rowHeight);

    // Hostname
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(15, 23, 42);
    doc.text(fitText(doc, d.hostname, 30), 16, currentY + 4.0);

    // Unit
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.2);
    doc.setTextColor(71, 85, 105);
    doc.text(fitText(doc, d.unit, 24), 48, currentY + 4.0);

    // Status dot & text
    const statusColor: [number, number, number] =
      d.status === 'online'
        ? [16, 185, 129] // Emerald
        : d.status === 'away'
        ? [245, 158, 11] // Amber
        : [148, 163, 184]; // Slate
    doc.setFillColor(statusColor[0], statusColor[1], statusColor[2]);
    doc.circle(76, currentY + 3.6, 1.0, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(5.8);
    doc.setTextColor(statusColor[0], statusColor[1], statusColor[2]);
    doc.text(d.status.toUpperCase(), 79, currentY + 4.0);

    // IP
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.2);
    doc.setTextColor(71, 85, 105);
    doc.text(fitText(doc, d.ip, 24), 94, currentY + 4.0);

    // User
    doc.text(fitText(doc, d.user, 24), 120, currentY + 4.0);

    // OS
    doc.text(fitText(doc, d.os, 26), 146, currentY + 4.0);

    // Risk
    const isHigh = d.riskScore >= 70 || d.riskLevel === 'high' || d.riskLevel === 'critical';
    const isMed = d.riskScore >= 40 || d.riskLevel === 'medium';
    const riskColor: [number, number, number] = isHigh
      ? [220, 38, 38]
      : isMed
      ? [217, 119, 6]
      : [16, 185, 129];

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.2);
    doc.setTextColor(riskColor[0], riskColor[1], riskColor[2]);
    doc.text(fitText(doc, `${d.riskScore} (${d.riskLevel})`, 20), 174, currentY + 4.0);

    currentY += rowHeight;
  });

  // Finalize Footers on all pages
  finalizeFooters(doc);

  // Save PDF
  const filename = `VextHub_Laudo_Dispositivos_${getTimestampSlug()}.pdf`;
  doc.save(filename);
}

export async function exportCompliancePdf(
  policies: SoftwarePolicyExportItem[],
  alerts?: ComplianceAlertExportItem[],
  options?: ComplianceExportOptions
): Promise<void> {
  const { jsPDF } = await import('jspdf');
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
    compress: true,
  });

  const emissionDate = new Date().toLocaleString('pt-BR');
  const docTitle = 'AUDITORIA DE COMPLIANCE & POLÍTICAS DE SOFTWARE';

  // 1. Brand Header
  drawBrandHeader(doc, docTitle, emissionDate);

  // 2. 4 Executive KPI Cards
  const totalPolicies = policies.length;
  const allowedCount = policies.filter((p) => p.status === 'allowed').length;
  const forbiddenCount = policies.filter((p) => p.status === 'forbidden').length;
  const alertCount = alerts ? alerts.length : 0;

  const kpis: MetricCardData[] = [
    { title: 'Softwares Catalogados', value: totalPolicies, accent: [99, 102, 241] }, // Indigo
    { title: 'Homologados / OK', value: allowedCount, accent: [16, 185, 129] }, // Emerald
    { title: 'Proibidos / Bloqueados', value: forbiddenCount, accent: [239, 68, 68] }, // Rose
    { title: 'Violações Ativas', value: alertCount, accent: [249, 115, 22] }, // Orange
  ];

  drawMetricCards(doc, kpis, 31);

  let currentY = 53;

  // Zero Trust Posture & Shadow IT Radar Summary Banner
  if (options?.zeroTrust) {
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.2);
    doc.roundedRect(14, currentY, 182, 10, 1.5, 1.5, 'FD');

    // Left color indicator for posture score
    const score = options.zeroTrust.postureScore;
    const scoreColor: [number, number, number] =
      score >= 80 ? [16, 185, 129] : score >= 60 ? [245, 158, 11] : [220, 38, 38];
    doc.setFillColor(scoreColor[0], scoreColor[1], scoreColor[2]);
    doc.rect(14, currentY, 2.5, 10, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(15, 23, 42);
    doc.text('POSTURA ZERO TRUST (ZTNA / CIS CONTROLS):', 19, currentY + 4.0);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(scoreColor[0], scoreColor[1], scoreColor[2]);
    doc.text(`SCORE: ${score}/100`, 78, currentY + 4.0);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.2);
    doc.setTextColor(71, 85, 105);
    doc.text(
      `Trusted: ${options.zeroTrust.trustedCount}  |  Restricted: ${options.zeroTrust.restrictedCount}  |  Quarantined: ${options.zeroTrust.quarantinedCount}`,
      19,
      currentY + 8.0
    );

    const tunnels = options.zeroTrust.tunnelsDetected;
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(tunnels > 0 ? 220 : 71, tunnels > 0 ? 38 : 85, tunnels > 0 ? 38 : 105);
    doc.text(`Túneis Clandestinos: ${tunnels} detectados`, 130, currentY + 8.0);

    currentY += 13.5;
  }

  // 3. Section: Active Violations (if present)
  if (alerts && alerts.length > 0) {
    // Section Title
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(220, 38, 38);
    doc.text(`ALERTAS E VIOLAÇÕES DE CONFORMIDADE ATIVAS (${alerts.length})`, 14, currentY);
    currentY += 2.5;

    const drawAlertHeader = (y: number) => {
      doc.setFillColor(15, 23, 42);
      doc.rect(14, y, 182, 6.5, 'F');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.5);
      doc.setTextColor(255, 255, 255);

      doc.text('HOSTNAME', 16, y + 4.3);
      doc.text('UNIDADE', 48, y + 4.3);
      doc.text('SOFTWARE NÃO AUTORIZADO', 74, y + 4.3);
      doc.text('DETALHES DA INFRAÇÃO', 114, y + 4.3);
      doc.text('DATA/HORA', 170, y + 4.3);
    };

    drawAlertHeader(currentY);
    currentY += 6.5;

    const rowHeight = 6.0;

    alerts.forEach((alert, index) => {
      if (currentY + rowHeight > 278) {
        doc.addPage();
        drawContinuationHeader(doc, docTitle, emissionDate);
        currentY = 19;
        drawAlertHeader(currentY);
        currentY += 6.5;
      }

      if (index % 2 === 1) {
        doc.setFillColor(254, 242, 242); // Subtle red tint for violations
        doc.rect(14, currentY, 182, rowHeight, 'F');
      }

      doc.setDrawColor(241, 245, 249);
      doc.setLineWidth(0.15);
      doc.line(14, currentY + rowHeight, 196, currentY + rowHeight);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.5);
      doc.setTextColor(15, 23, 42);
      doc.text(fitText(doc, alert.hostname, 30), 16, currentY + 4.0);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.2);
      doc.setTextColor(71, 85, 105);
      doc.text(fitText(doc, alert.unit, 24), 48, currentY + 4.0);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.2);
      doc.setTextColor(220, 38, 38);
      doc.text(fitText(doc, alert.software_name, 38), 74, currentY + 4.0);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.0);
      doc.setTextColor(71, 85, 105);
      doc.text(fitText(doc, alert.message, 54), 114, currentY + 4.0);

      doc.text(fitText(doc, alert.created_at, 24), 170, currentY + 4.0);

      currentY += rowHeight;
    });

    currentY += 6.0; // Space between sections
  }

  // 4. Section: Software Governance Matrix
  if (currentY + 20 > 278) {
    doc.addPage();
    drawContinuationHeader(doc, docTitle, emissionDate);
    currentY = 19;
  }

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(15, 23, 42);
  doc.text(`MATRIZ DE GOVERNANÇA DE SOFTWARES (${policies.length})`, 14, currentY);
  currentY += 2.5;

  const drawPolicyHeader = (y: number) => {
    doc.setFillColor(15, 23, 42);
    doc.rect(14, y, 182, 6.5, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(255, 255, 255);

    doc.text('SOFTWARE', 16, y + 4.3);
    doc.text('STATUS GLOBAL', 68, y + 4.3);
    doc.text('UNIDADES APLICADAS', 104, y + 4.3);
    doc.text('EXCEÇÕES ESPECÍFICAS', 150, y + 4.3);
  };

  drawPolicyHeader(currentY);
  currentY += 6.5;

  const policyRowHeight = 6.0;

  policies.forEach((policy, index) => {
    if (currentY + policyRowHeight > 278) {
      doc.addPage();
      drawContinuationHeader(doc, docTitle, emissionDate);
      currentY = 19;
      drawPolicyHeader(currentY);
      currentY += 6.5;
    }

    if (index % 2 === 1) {
      doc.setFillColor(248, 250, 252);
      doc.rect(14, currentY, 182, policyRowHeight, 'F');
    }

    doc.setDrawColor(241, 245, 249);
    doc.setLineWidth(0.15);
    doc.line(14, currentY + policyRowHeight, 196, currentY + policyRowHeight);

    // Software Name
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(15, 23, 42);
    doc.text(fitText(doc, policy.name, 48), 16, currentY + 4.0);

    // Status Dot & Label
    const status = policy.status;
    const isAllowed = status === 'allowed';
    const isForbidden = status === 'forbidden';
    const statusColor: [number, number, number] = isAllowed
      ? [16, 185, 129] // Emerald
      : isForbidden
      ? [239, 68, 68] // Red
      : [245, 158, 11]; // Amber

    doc.setFillColor(statusColor[0], statusColor[1], statusColor[2]);
    doc.circle(70, currentY + 3.6, 1.0, 'F');

    const statusLabel = isAllowed
      ? 'HOMOLOGADO'
      : isForbidden
      ? 'PROIBIDO'
      : 'PENDENTE';
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(5.8);
    doc.setTextColor(statusColor[0], statusColor[1], statusColor[2]);
    doc.text(statusLabel, 73, currentY + 4.0);

    // Units
    const unitsText =
      policy.units && policy.units.length > 0
        ? policy.units.join(', ')
        : 'Todas as Unidades';
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.2);
    doc.setTextColor(71, 85, 105);
    doc.text(fitText(doc, unitsText, 44), 104, currentY + 4.0);

    // Overrides
    const overridesText =
      policy.overrides && policy.overrides.length > 0
        ? policy.overrides
            .map((o) => `${o.unit_name}: ${o.status === 'allowed' ? 'OK' : 'Bloq'}`)
            .join('; ')
        : 'Padrão global';
    doc.text(fitText(doc, overridesText, 44), 150, currentY + 4.0);

    currentY += policyRowHeight;
  });

  // 5. Section: Prioritized CVEs & CISA KEV Summary (if provided)
  if (options?.cveList && options.cveList.length > 0) {
    currentY += 4.0;
    if (currentY + 25 > 278) {
      doc.addPage();
      drawContinuationHeader(doc, docTitle, emissionDate);
      currentY = 19;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(15, 23, 42);
    doc.text(`VULNERABILIDADES PRIORITÁRIAS & CISA KEV (TVM / ISO 27001 A.8.8) (${options.cveList.length})`, 14, currentY);
    currentY += 2.5;

    const drawCveHeader = (y: number) => {
      doc.setFillColor(15, 23, 42);
      doc.rect(14, y, 182, 6.5, 'F');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.5);
      doc.setTextColor(255, 255, 255);

      doc.text('CVE ID', 16, y + 4.3);
      doc.text('SOFTWARE AFETADO', 46, y + 4.3);
      doc.text('SEVERIDADE', 94, y + 4.3);
      doc.text('CVSS', 118, y + 4.3);
      doc.text('CISA KEV', 132, y + 4.3);
      doc.text('RECOMENDAÇÃO DE REMEDIAÇÃO', 152, y + 4.3);
    };

    drawCveHeader(currentY);
    currentY += 6.5;

    const cveRowHeight = 6.0;

    options.cveList.forEach((cve, index) => {
      if (currentY + cveRowHeight > 278) {
        doc.addPage();
        drawContinuationHeader(doc, docTitle, emissionDate);
        currentY = 19;
        drawCveHeader(currentY);
        currentY += 6.5;
      }

      if (index % 2 === 1) {
        doc.setFillColor(248, 250, 252);
        doc.rect(14, currentY, 182, cveRowHeight, 'F');
      }

      doc.setDrawColor(241, 245, 249);
      doc.setLineWidth(0.15);
      doc.line(14, currentY + cveRowHeight, 196, currentY + cveRowHeight);

      // CVE ID
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.2);
      doc.setTextColor(15, 23, 42);
      doc.text(fitText(doc, cve.cveId, 28), 16, currentY + 4.0);

      // Software
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.0);
      doc.setTextColor(71, 85, 105);
      doc.text(fitText(doc, cve.softwareName, 44), 46, currentY + 4.0);

      // Severity
      const isCrit = cve.severity.toLowerCase() === 'critical';
      const isHigh = cve.severity.toLowerCase() === 'high';
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(5.8);
      doc.setTextColor(
        isCrit ? 220 : isHigh ? 217 : 71,
        isCrit ? 38 : isHigh ? 119 : 85,
        isCrit ? 38 : isHigh ? 6 : 105
      );
      doc.text(cve.severity.toUpperCase(), 94, currentY + 4.0);

      // CVSS
      doc.setTextColor(15, 23, 42);
      doc.text(cve.cvssScore.toFixed(1), 118, currentY + 4.0);

      // CISA KEV
      if (cve.cisaKev) {
        doc.setFillColor(254, 242, 242);
        doc.rect(131, currentY + 1.2, 17, 3.8, 'F');
        doc.setTextColor(220, 38, 38);
        doc.text('SIM (KEV)', 132, currentY + 4.0);
      } else {
        doc.setTextColor(148, 163, 184);
        doc.text('Não', 132, currentY + 4.0);
      }

      // Remediation
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(5.8);
      doc.setTextColor(71, 85, 105);
      doc.text(fitText(doc, cve.remediation, 42), 152, currentY + 4.0);

      currentY += cveRowHeight;
    });
  }

  // 6. Section: GRC Regulatory Compliance Coverage (if provided)
  if (options?.grcControls && options.grcControls.length > 0) {
    currentY += 4.0;
    if (currentY + 25 > 278) {
      doc.addPage();
      drawContinuationHeader(doc, docTitle, emissionDate);
      currentY = 19;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(15, 23, 42);
    doc.text(`MATRIZ DE CONFORMIDADE REGULATÓRIA GRC (ISO 27001 / LGPD / CIS CONTROLS) (${options.grcControls.length})`, 14, currentY);
    currentY += 2.5;

    const drawGrcHeader = (y: number) => {
      doc.setFillColor(15, 23, 42);
      doc.rect(14, y, 182, 6.5, 'F');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.5);
      doc.setTextColor(255, 255, 255);

      doc.text('FRAMEWORK', 16, y + 4.3);
      doc.text('CONTROLE', 52, y + 4.3);
      doc.text('NOME DO CONTROLE', 76, y + 4.3);
      doc.text('STATUS', 140, y + 4.3);
      doc.text('COBERTURA', 168, y + 4.3);
    };

    drawGrcHeader(currentY);
    currentY += 6.5;

    const grcRowHeight = 6.0;

    options.grcControls.forEach((grc, index) => {
      if (currentY + grcRowHeight > 278) {
        doc.addPage();
        drawContinuationHeader(doc, docTitle, emissionDate);
        currentY = 19;
        drawGrcHeader(currentY);
        currentY += 6.5;
      }

      if (index % 2 === 1) {
        doc.setFillColor(248, 250, 252);
        doc.rect(14, currentY, 182, grcRowHeight, 'F');
      }

      doc.setDrawColor(241, 245, 249);
      doc.setLineWidth(0.15);
      doc.line(14, currentY + grcRowHeight, 196, currentY + grcRowHeight);

      // Framework
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.0);
      doc.setTextColor(15, 23, 42);
      doc.text(fitText(doc, grc.framework, 34), 16, currentY + 4.0);

      // Code
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.2);
      doc.setTextColor(124, 58, 237);
      doc.text(fitText(doc, grc.controlCode, 22), 52, currentY + 4.0);

      // Name
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.0);
      doc.setTextColor(71, 85, 105);
      doc.text(fitText(doc, grc.controlName, 60), 76, currentY + 4.0);

      // Status
      const isOk = grc.status === 'Conforme';
      const isWarn = grc.status === 'Alerta';
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(5.8);
      doc.setTextColor(
        isOk ? 16 : isWarn ? 217 : 220,
        isOk ? 185 : isWarn ? 119 : 38,
        isOk ? 129 : isWarn ? 6 : 38
      );
      doc.text(grc.status.toUpperCase(), 140, currentY + 4.0);

      // Coverage
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(15, 23, 42);
      doc.text(`${grc.coveragePercent}%`, 168, currentY + 4.0);

      currentY += grcRowHeight;
    });
  }

  // Finalize Footers on all pages
  finalizeFooters(doc);

  // Save PDF
  const filename = `VextHub_Laudo_Compliance_${getTimestampSlug()}.pdf`;
  doc.save(filename);
}
