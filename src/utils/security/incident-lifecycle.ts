/**
 * VextHub Incident Response Fast-Track, Blast Radius & GRC Compliance Engine
 * Alinhado a: TIVIT Defense/Sensr, Clavis GRC, ISO/IEC 27001:2022, LGPD e CIS Controls v8.
 */

// ============================================================================
// TYPES & CONSTANTS (ZERO `any`)
// ============================================================================

export type IncidentStatus = 'TRIAGE' | 'CONTAINMENT' | 'ERADICATION' | 'RECOVERED';
export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low';
export type SlaStatus = 'within_sla' | 'warning' | 'breached';
export type BlastRadiusVectorType = 'software' | 'port' | 'process' | 'cve';

export interface BlastRadiusVector {
  type: BlastRadiusVectorType;
  identifier: string;
}

export const SLA_TARGETS_HOURS: Record<IncidentSeverity, number> = {
  critical: 1,  // 1 hora para contenção crítica
  high: 4,      // 4 horas para alta severidade
  medium: 24,   // 24 horas para média severidade
  low: 72,      // 72 horas para baixa severidade
};

export interface GRCControl {
  framework: 'ISO 27001:2022' | 'LGPD' | 'CIS Controls v8';
  code: string;
  title: string;
  description: string;
}

export const GRC_STANDARDS: Record<string, GRCControl> = {
  ISO_A_8_8: {
    framework: 'ISO 27001:2022',
    code: 'A.8.8',
    title: 'Gestão de Vulnerabilidades Técnicas',
    description: 'Obtenção oportuna de informações sobre vulnerabilidades de software e aplicação de medidas de tratamento apropriadas.',
  },
  ISO_A_8_16: {
    framework: 'ISO 27001:2022',
    code: 'A.8.16',
    title: 'Atividades de Monitoramento',
    description: 'Monitoramento contínuo de redes, sistemas e aplicações contra comportamentos anômalos e ameaças.',
  },
  ISO_A_8_15: {
    framework: 'ISO 27001:2022',
    code: 'A.8.15',
    title: 'Registro em Log',
    description: 'Geração, retenção e proteção de registros de eventos para evidência forense e auditoria.',
  },
  ISO_A_5_24: {
    framework: 'ISO 27001:2022',
    code: 'A.5.24',
    title: 'Gestão de Incidentes de Segurança da Informação',
    description: 'Capacidade operacional estruturada para detecção, análise, contenção e recuperação de incidentes cibernéticos.',
  },
  LGPD_ART_46: {
    framework: 'LGPD',
    code: 'Art. 46',
    title: 'Medidas de Segurança e Confidencialidade',
    description: 'Adoção de medidas de segurança, técnicas e administrativas aptas a proteger dados pessoais contra acessos não autorizados.',
  },
  LGPD_ART_48: {
    framework: 'LGPD',
    code: 'Art. 48',
    title: 'Comunicação de Incidentes Relevantes',
    description: 'Comunicação formal à autoridade nacional e aos titulares sobre incidentes que possam acarretar risco ou dano relevante.',
  },
  CIS_CONTROL_7: {
    framework: 'CIS Controls v8',
    code: 'Control 7',
    title: 'Vulnerability Management',
    description: 'Desenvolver e manter um processo contínuo de avaliação e remediação de vulnerabilidades de software.',
  },
  CIS_CONTROL_8: {
    framework: 'CIS Controls v8',
    code: 'Control 8',
    title: 'Audit Log Management',
    description: 'Coletar, gerenciar e auditar registros de eventos de segurança para suporte à resposta a incidentes.',
  },
  CIS_CONTROL_17: {
    framework: 'CIS Controls v8',
    code: 'Control 17',
    title: 'Incident Response Management',
    description: 'Estabelecer e manter planos de resposta a incidentes para conter e mitigar violações em tempo hábil.',
  },
};

export interface BlastRadiusPeer {
  id: string;
  hostname: string;
  unit: string;
  ip?: string;
  last_pulse?: string;
}

export interface BlastRadiusResult {
  vector_type: BlastRadiusVectorType;
  vector_identifier: string;
  same_unit_count: number;
  total_fleet_count: number;
  affected_peers: BlastRadiusPeer[];
  risk_multiplier: number;
  recommendation: string;
}

export interface SecurityIncident {
  id: string;
  alert_id?: string;
  machine_id: string;
  hostname: string;
  unit: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  created_at: string;
  updated_at: string;
  sla_target_hours: number;
  sla_deadline: string;
  sla_status: SlaStatus;
  remaining_minutes: number;
  blast_radius: BlastRadiusResult;
  grc_controls: GRCControl[];
  mitre_technique?: string;
  remediation_playbook?: string;
  contained_at?: string;
  eradicated_at?: string;
  recovered_at?: string;
}

export interface IncidentMetrics {
  total_incidents: number;
  active_triage: number;
  in_containment: number;
  in_eradication: number;
  recovered: number;
  mttd_minutes: number;
  mttr_minutes: number;
  sla_compliance_rate: number;
  avg_blast_radius: number;
}

// ============================================================================
// SLA & WORKFLOW CALCULATION
// ============================================================================

export const INCIDENT_WORKFLOW_STAGES: readonly IncidentStatus[] = [
  'TRIAGE',
  'CONTAINMENT',
  'ERADICATION',
  'RECOVERED',
] as const;

/**
 * Returns the next status in the incident response lifecycle.
 */
export function getNextStatus(current: IncidentStatus): IncidentStatus | null {
  const currentIndex = INCIDENT_WORKFLOW_STAGES.indexOf(current);
  if (currentIndex >= 0 && currentIndex < INCIDENT_WORKFLOW_STAGES.length - 1) {
    return INCIDENT_WORKFLOW_STAGES[currentIndex + 1];
  }
  return null;
}

/**
 * Validates whether a state transition is permitted.
 * Supports standard progressive workflow as well as returning to containment if needed.
 */
export function canTransition(from: IncidentStatus, to: IncidentStatus): boolean {
  if (from === to) return false;
  const fromIndex = INCIDENT_WORKFLOW_STAGES.indexOf(from);
  const toIndex = INCIDENT_WORKFLOW_STAGES.indexOf(to);
  if (fromIndex === -1 || toIndex === -1) return false;

  // Progressive advance
  if (toIndex === fromIndex + 1) return true;
  // Jump from triage to containment, eradication or recovered when resolved
  if (fromIndex < toIndex) return true;
  // Re-open into containment from recovered if re-infected
  if (from === 'RECOVERED' && to === 'CONTAINMENT') return true;

  return false;
}

/**
 * Calculates deadline, remaining minutes, and SLA compliance status.
 */
export function calculateSlaStatus(
  createdAt: string,
  severity: IncidentSeverity,
  resolvedAt?: string,
  referenceNow?: Date
): {
  slaTargetHours: number;
  deadline: string;
  remainingMinutes: number;
  slaStatus: SlaStatus;
} {
  const slaTargetHours = SLA_TARGETS_HOURS[severity] || 24;
  const createdDate = new Date(createdAt);
  const now = referenceNow || new Date();

  // If invalid date, fallback gracefully
  const validCreated = Number.isNaN(createdDate.getTime()) ? now : createdDate;
  const deadlineDate = new Date(validCreated.getTime() + slaTargetHours * 60 * 60 * 1000);
  const deadlineIso = deadlineDate.toISOString();

  // If incident was resolved (recovered), evaluate based on resolution time
  if (resolvedAt) {
    const resolvedDate = new Date(resolvedAt);
    if (!Number.isNaN(resolvedDate.getTime())) {
      const isBreached = resolvedDate.getTime() > deadlineDate.getTime();
      const remainingMinutesAtResolution = Math.round(
        (deadlineDate.getTime() - resolvedDate.getTime()) / (60 * 1000)
      );
      return {
        slaTargetHours,
        deadline: deadlineIso,
        remainingMinutes: remainingMinutesAtResolution,
        slaStatus: isBreached ? 'breached' : 'within_sla',
      };
    }
  }

  const remainingMs = deadlineDate.getTime() - now.getTime();
  const remainingMinutes = Math.round(remainingMs / (60 * 1000));

  let slaStatus: SlaStatus = 'within_sla';
  if (remainingMinutes <= 0) {
    slaStatus = 'breached';
  } else {
    const totalMinutes = slaTargetHours * 60;
    // Warning if less than 20% SLA remains or <= 30 minutes
    if (remainingMinutes <= Math.max(30, totalMinutes * 0.2)) {
      slaStatus = 'warning';
    }
  }

  return {
    slaTargetHours,
    deadline: deadlineIso,
    remainingMinutes,
    slaStatus,
  };
}

/**
 * Advances an incident to its next lifecycle stage, updating timestamps and SLA.
 */
export function advanceIncidentStatus(
  incident: SecurityIncident,
  targetStatus?: IncidentStatus,
  actionTimestamp?: string
): SecurityIncident {
  const next = targetStatus || getNextStatus(incident.status);
  if (!next) return incident;

  const timestamp = actionTimestamp || new Date().toISOString();
  const updated: SecurityIncident = {
    ...incident,
    status: next,
    updated_at: timestamp,
  };

  if (next === 'CONTAINMENT' && !updated.contained_at) {
    updated.contained_at = timestamp;
  } else if (next === 'ERADICATION' && !updated.eradicated_at) {
    updated.eradicated_at = timestamp;
  } else if (next === 'RECOVERED' && !updated.recovered_at) {
    updated.recovered_at = timestamp;
  }

  // Recalculate SLA based on current state
  const sla = calculateSlaStatus(
    updated.created_at,
    updated.severity,
    updated.recovered_at
  );

  updated.sla_status = sla.slaStatus;
  updated.remaining_minutes = sla.remainingMinutes;

  return updated;
}

// ============================================================================
// BLAST RADIUS CALCULATION ENGINE
// ============================================================================

export interface MachineForBlastRadius {
  id: string;
  hostname?: string;
  unit?: string;
  ip?: string;
  last_pulse?: string;
  inventory_data?: Record<string, unknown> | null;
}

/**
 * Deterministically calculates the Blast Radius of a given security vector
 * across the target host, its unit peers, and the broader fleet.
 */
export function calculateBlastRadius(
  targetMachineId: string,
  vector: BlastRadiusVector,
  fleetMachines: MachineForBlastRadius[]
): BlastRadiusResult {
  const safeFleet = Array.isArray(fleetMachines) ? fleetMachines : [];
  const targetHost = safeFleet.find((m) => m && m.id === targetMachineId);
  const targetUnit = (targetHost?.unit || '').trim();
  const searchId = (vector?.identifier || '').toLowerCase().trim();

  const affectedPeers: BlastRadiusPeer[] = [];

  if (searchId) {
    for (const machine of safeFleet) {
      if (!machine || machine.id === targetMachineId) continue;

      let matched = false;
      const inv = machine.inventory_data;

      switch (vector.type) {
        case 'software': {
          const programs = Array.isArray(inv?.installed_programs) ? inv.installed_programs : [];
          matched = programs.some((p: unknown) => {
            if (p && typeof p === 'object' && 'name' in p) {
              const name = String((p as { name?: unknown }).name || '').toLowerCase();
              return name.includes(searchId);
            }
            return false;
          });
          break;
        }

        case 'port': {
          const ports = Array.isArray(inv?.listening_ports) ? inv.listening_ports : [];
          matched = ports.some((lp: unknown) => {
            if (lp && typeof lp === 'object' && 'local_port' in lp) {
              const port = String((lp as { local_port?: unknown }).local_port || '');
              return port === searchId;
            }
            return false;
          });
          break;
        }

        case 'process': {
          const procs = Array.isArray(inv?.running_processes)
            ? inv.running_processes
            : Array.isArray(inv?.monitored_processes)
            ? inv.monitored_processes
            : [];
          matched = procs.some((pr: unknown) => {
            if (pr && typeof pr === 'object') {
              const item = pr as { name?: unknown; path?: unknown; command_line?: unknown };
              const name = String(item.name || '').toLowerCase();
              const path = String(item.path || '').toLowerCase();
              const cmd = String(item.command_line || '').toLowerCase();
              return name.includes(searchId) || path.includes(searchId) || cmd.includes(searchId);
            }
            return false;
          });
          break;
        }

        case 'cve': {
          // Check security_analysis findings
          const secAnalysis = inv?.security_analysis as Record<string, unknown> | undefined;
          const findings = Array.isArray(secAnalysis?.findings) ? secAnalysis.findings : [];
          matched = findings.some((f: unknown) => {
            if (f && typeof f === 'object') {
              const finding = f as { title?: unknown; description?: unknown; id?: unknown };
              const title = String(finding.title || '').toLowerCase();
              const desc = String(finding.description || '').toLowerCase();
              const fid = String(finding.id || '').toLowerCase();
              return title.includes(searchId) || desc.includes(searchId) || fid.includes(searchId);
            }
            return false;
          });

          // Also check installed software if CVE search ID resembles a software name
          if (!matched) {
            const programs = Array.isArray(inv?.installed_programs) ? inv.installed_programs : [];
            matched = programs.some((p: unknown) => {
              if (p && typeof p === 'object' && 'name' in p) {
                const name = String((p as { name?: unknown }).name || '').toLowerCase();
                return name.includes(searchId);
              }
              return false;
            });
          }
          break;
        }

        default:
          matched = false;
      }

      if (matched) {
        affectedPeers.push({
          id: machine.id,
          hostname: machine.hostname || machine.id,
          unit: (machine.unit || 'Geral').trim(),
          ip: machine.ip,
          last_pulse: machine.last_pulse,
        });
      }
    }
  }

  const sameUnitCount = targetUnit
    ? affectedPeers.filter((p) => p.unit.toLowerCase() === targetUnit.toLowerCase()).length
    : 0;
  const totalFleetCount = affectedPeers.length;
  // Risk multiplier scales gracefully from 1.0 to 3.0 based on fleet propagation
  const riskMultiplier = Math.min(3.0, Number((1.0 + totalFleetCount * 0.15).toFixed(2)));

  let recommendation = `Vetor '${vector.identifier}' isolado no host alvo. Nenhuma propagação na frota.`;
  if (totalFleetCount > 0) {
    recommendation = `ALERTA DE PROPAGAÇÃO: ${totalFleetCount} hosts na frota (${sameUnitCount} na filial '${targetUnit || 'Geral'}') compartilham o vetor '${vector.identifier}'.`;
  }

  return {
    vector_type: vector.type,
    vector_identifier: vector.identifier,
    same_unit_count: sameUnitCount,
    total_fleet_count: totalFleetCount,
    affected_peers: affectedPeers,
    risk_multiplier: riskMultiplier,
    recommendation,
  };
}

// ============================================================================
// GRC REGULATORY COMPLIANCE MAPPING
// ============================================================================

export interface GrcMappingContext {
  severity?: IncidentSeverity | string;
  vectorType?: BlastRadiusVectorType | string;
  findingTitle?: string;
  isIncident?: boolean;
}

/**
 * Maps a security event, finding, or incident to appropriate GRC controls
 * across ISO/IEC 27001:2022, LGPD, and CIS Controls v8.
 */
export function mapToGrcControls(context: GrcMappingContext): GRCControl[] {
  const controls: GRCControl[] = [];
  const addedCodes = new Set<string>();

  const add = (control: GRCControl) => {
    if (!addedCodes.has(control.code)) {
      addedCodes.add(control.code);
      controls.push(control);
    }
  };

  const title = (context.findingTitle || '').toLowerCase();
  const vectorType = (context.vectorType || '').toLowerCase();
  const severity = (context.severity || '').toLowerCase();

  // 1. Vulnerability Management: ISO A.8.8 & CIS Control 7
  if (
    vectorType === 'cve' ||
    vectorType === 'software' ||
    title.includes('cve') ||
    title.includes('vulnerab') ||
    title.includes('outdated') ||
    title.includes('desatualizad')
  ) {
    add(GRC_STANDARDS.ISO_A_8_8);
    add(GRC_STANDARDS.CIS_CONTROL_7);
  }

  // 2. Monitoring & Logging: ISO A.8.16, ISO A.8.15 & CIS Control 8
  add(GRC_STANDARDS.ISO_A_8_16);
  add(GRC_STANDARDS.ISO_A_8_15);
  add(GRC_STANDARDS.CIS_CONTROL_8);

  // 3. Incident Response: ISO A.5.24 & CIS Control 17
  if (context.isIncident || severity === 'critical' || severity === 'high') {
    add(GRC_STANDARDS.ISO_A_5_24);
    add(GRC_STANDARDS.CIS_CONTROL_17);
  }

  // 4. LGPD Art. 46 (Security measures) for all security events
  add(GRC_STANDARDS.LGPD_ART_46);

  // 5. LGPD Art. 48 (Mandatory incident notification) for Critical/High breach paths
  if (
    severity === 'critical' ||
    title.includes('breach') ||
    title.includes('exfiltration') ||
    title.includes('credential') ||
    title.includes('mimikatz') ||
    title.includes('vazamento')
  ) {
    add(GRC_STANDARDS.LGPD_ART_48);
  }

  return controls;
}

// ============================================================================
// SOC EFFICIENCY METRICS (MTTD, MTTR, SLA COMPLIANCE)
// ============================================================================

/**
 * Calculates aggregated SOC efficiency metrics from a collection of incidents.
 */
export function calculateIncidentMetrics(incidents: SecurityIncident[]): IncidentMetrics {
  const safeIncidents = Array.isArray(incidents) ? incidents : [];

  if (safeIncidents.length === 0) {
    return {
      total_incidents: 0,
      active_triage: 0,
      in_containment: 0,
      in_eradication: 0,
      recovered: 0,
      mttd_minutes: 0,
      mttr_minutes: 0,
      sla_compliance_rate: 100,
      avg_blast_radius: 0,
    };
  }

  let activeTriage = 0;
  let inContainment = 0;
  let inEradication = 0;
  let recovered = 0;

  let totalMttdMinutes = 0;
  let mttdSamples = 0;

  let totalMttrMinutes = 0;
  let mttrSamples = 0;

  let compliantIncidents = 0;
  let totalBlastRadius = 0;

  for (const incident of safeIncidents) {
    switch (incident.status) {
      case 'TRIAGE':
        activeTriage++;
        break;
      case 'CONTAINMENT':
        inContainment++;
        break;
      case 'ERADICATION':
        inEradication++;
        break;
      case 'RECOVERED':
        recovered++;
        break;
    }

    // Blast Radius tally
    totalBlastRadius += incident.blast_radius?.total_fleet_count || 0;

    // SLA compliance
    if (incident.sla_status !== 'breached') {
      compliantIncidents++;
    }

    // MTTD: Detection/Triage to Containment (or creation to containment)
    const createdTime = new Date(incident.created_at).getTime();
    if (incident.contained_at && !Number.isNaN(createdTime)) {
      const containedTime = new Date(incident.contained_at).getTime();
      if (!Number.isNaN(containedTime) && containedTime >= createdTime) {
        totalMttdMinutes += Math.round((containedTime - createdTime) / (60 * 1000));
        mttdSamples++;
      }
    } else if (incident.status !== 'TRIAGE' && !Number.isNaN(createdTime)) {
      // If beyond triage, use updated_at as proxy if contained_at wasn't recorded
      const updatedTime = new Date(incident.updated_at).getTime();
      if (!Number.isNaN(updatedTime) && updatedTime >= createdTime) {
        totalMttdMinutes += Math.round((updatedTime - createdTime) / (60 * 1000));
        mttdSamples++;
      }
    }

    // MTTR: Creation to Recovered
    if (incident.recovered_at && !Number.isNaN(createdTime)) {
      const recoveredTime = new Date(incident.recovered_at).getTime();
      if (!Number.isNaN(recoveredTime) && recoveredTime >= createdTime) {
        totalMttrMinutes += Math.round((recoveredTime - createdTime) / (60 * 1000));
        mttrSamples++;
      }
    }
  }

  const mttdMinutes = mttdSamples > 0 ? Math.round(totalMttdMinutes / mttdSamples) : 0;
  const mttrMinutes = mttrSamples > 0 ? Math.round(totalMttrMinutes / mttrSamples) : 0;
  const slaComplianceRate = Math.round((compliantIncidents / safeIncidents.length) * 1000) / 10;
  const avgBlastRadius = Math.round((totalBlastRadius / safeIncidents.length) * 10) / 10;

  return {
    total_incidents: safeIncidents.length,
    active_triage: activeTriage,
    in_containment: inContainment,
    in_eradication: inEradication,
    recovered,
    mttd_minutes: mttdMinutes,
    mttr_minutes: mttrMinutes,
    sla_compliance_rate: slaComplianceRate,
    avg_blast_radius: avgBlastRadius,
  };
}

// ============================================================================
// INCIDENT FACTORY / SYNCHRONIZATION HELPERS
// ============================================================================

export interface RawAlertInput {
  id: string;
  hostname?: string;
  unit?: string;
  software_name?: string;
  message?: string;
  severity?: string;
  created_at?: string;
  machine_id?: string;
}

/**
 * Creates a fully populated SecurityIncident from a raw telemetry alert and fleet data.
 */
export function createIncidentFromAlert(
  alert: RawAlertInput,
  fleetMachines: MachineForBlastRadius[],
  referenceNow?: Date
): SecurityIncident {
  const machineId = alert.machine_id || alert.id || 'unknown';
  const hostname = alert.hostname || 'endpoint';
  const unit = alert.unit || 'Matriz';
  const rawSev = (alert.severity || 'medium').toLowerCase();
  const severity: IncidentSeverity =
    rawSev === 'critical' ? 'critical' : rawSev === 'high' ? 'high' : rawSev === 'low' ? 'low' : 'medium';

  const createdAt = alert.created_at || new Date().toISOString();

  // Determine vector from software_name or message
  let vectorType: BlastRadiusVectorType = 'software';
  let vectorId = alert.software_name || '';

  if (vectorId.toUpperCase().startsWith('CVE-')) {
    vectorType = 'cve';
  } else if (/port\s*(\d+)/i.test(alert.message || '')) {
    const portMatch = (alert.message || '').match(/port\s*(\d+)/i);
    if (portMatch) {
      vectorType = 'port';
      vectorId = portMatch[1];
    }
  } else if (/\.exe/i.test(vectorId) || /process/i.test(alert.message || '')) {
    vectorType = 'process';
  }

  const blastRadius = calculateBlastRadius(
    machineId,
    { type: vectorType, identifier: vectorId || hostname },
    fleetMachines
  );

  const sla = calculateSlaStatus(createdAt, severity, undefined, referenceNow);
  const grcControls = mapToGrcControls({
    severity,
    vectorType,
    findingTitle: alert.message || alert.software_name,
    isIncident: true,
  });

  return {
    id: `inc-${alert.id}`,
    alert_id: alert.id,
    machine_id: machineId,
    hostname,
    unit,
    title: alert.software_name || 'Incidente de Segurança',
    description: alert.message || `Detecção de anomalia crítica no host ${hostname}.`,
    severity,
    status: 'TRIAGE',
    created_at: createdAt,
    updated_at: createdAt,
    sla_target_hours: sla.slaTargetHours,
    sla_deadline: sla.deadline,
    sla_status: sla.slaStatus,
    remaining_minutes: sla.remainingMinutes,
    blast_radius: blastRadius,
    grc_controls: grcControls,
    remediation_playbook: severity === 'critical' ? 'PB-01: Contenção de Rede Imediata' : 'PB-03: Remediação de Software',
  };
}
